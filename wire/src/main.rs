#![allow(unused_imports)]

#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate tokio;
extern crate wire;

use wire::Kind;
use wire::Class;
use wire::OpCode;
use wire::Request;
use wire::Response;
use wire::Question;
use wire::ReprFlags;
use wire::HeaderFlags;
use wire::record::Record;
use wire::ser::Serialize;
use wire::ser::Serializer;
use wire::de::Deserialize;
use wire::de::Deserializer;


use std::io;
use std::env;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;

use tokio::net::UdpSocket;
use tokio::net::TcpListener;
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;


pub fn handle_res(pkt: &[u8]) {
    let mut deserializer = Deserializer::new(&pkt);
    let res = Response::deserialize(&mut deserializer);
    debug!("Res: {:?}", res);
}


pub fn handle_req(pkt: &[u8]) {
    let mut deserializer = Deserializer::new(&pkt);
    let req = Request::deserialize(&mut deserializer);
    debug!("Req: {:?}", req);
}

pub async fn run_udp_server() -> Result<(), tokio::io::Error> {
    let mut buf = [0u8; 1500];
    let mut listener = UdpSocket::bind("127.0.0.1:53").await?;
    info!("[UDP] udp service running at 127.0.0.1:53 ...");

    loop {
        match listener.recv_from(&mut buf).await {
            Ok((0, _)) => continue,
            Ok((amt, peer_addr)) => {
                let data = &buf[..amt];
                info!("[UDP] received {:?} bytes from {:?}", data.len(), peer_addr);
                debug!("{:?}", data);

                handle_req(data);
            },
            Err(e) => error!("{:?}", e),
        }
    }
}

pub async fn run_tcp_server() -> Result<(), tokio::io::Error> {
    let mut listener = TcpListener::bind("127.0.0.1:53").await?;
    info!("[TCP] tcp service running at 127.0.0.1:53 ...");
    loop {
        match listener.accept().await {
            Ok((mut tcp_stream, peer_addr)) => {

                tokio::spawn(async move {
                    let mut buf = [0u8; 1500];

                    let amt = tcp_stream.read(&mut buf[..2]).await?;
                    if amt != 2 {
                        return Err(io::Error::from(io::ErrorKind::Other));
                    }

                    let pkt_len = u16::from_be_bytes([ buf[0], buf[1] ]);
                    if pkt_len == 0 {
                        return Err(io::Error::from(io::ErrorKind::Other));
                    }

                    if pkt_len > 1000 {
                        error!("pkt size limit.");
                        return Err(io::Error::from(io::ErrorKind::Other));
                    }

                    let mut amt = 0usize;
                    while amt < pkt_len as usize {
                        let len = tcp_stream.read(&mut buf[amt..]).await?;
                        if len == 0 {
                            break;
                        }
                        amt += len;
                    }
                    
                    let data = &buf[..amt];

                    info!("[TCP] received {:?} bytes from client {:?}", data.len(), peer_addr);
                    debug!("req pkt : {:?}", data);
                    handle_req(data);

                    Ok(())
                });

            },
            Err(e) => error!("{:?}", e),
        }
    }
}

async fn run_server() -> Result<(), tokio::io::Error> {
    try_join!(
        run_tcp_server(),
        run_udp_server()
    ).map(|(_ret1, _ret2)| ())
}

async fn query(req: &Request, server_addr: &SocketAddr, buf: &mut [u8]) -> Result<Response, wire::Error> {
    let mut serializer = Serializer::new(&mut buf[2..]);
    req.serialize(&mut serializer)?;

    let pos = serializer.position() + 2;
    let _ = serializer.into_inner();

    let pkt = &buf[2..pos];
    if pkt.len() > std::u16::MAX as usize {
        return Err(wire::Error::from(wire::ErrorKind::FormatError));
    }

    let len = pkt.len() as u16;
    &mut buf[..2].copy_from_slice(&len.to_be_bytes());

    let mut stream = tokio::net::TcpStream::connect(&server_addr).await
            .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;

    stream.write_all(&buf[..pos]).await.map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;

    stream.read_exact(&mut buf[..2]).await.map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;
    let amt = u16::from_be_bytes([buf[0], buf[1]]) as usize;

    stream.read_exact(&mut buf[..amt]).await.map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;
    let pkt = &buf[..amt];

    let mut deserializer = Deserializer::new(&pkt);
    let res = Response::deserialize(&mut deserializer)?;

    Ok(res)
}

async fn lookup(name: &str) -> Result<Response, Box<dyn std::error::Error>> {
    let mut res = lookup_inner(name).await?;
    'LOOP1: loop {
        if res.answers.len() == 0 {
            return Ok(res);
        }

        for rr in res.answers.iter() {
            match rr {
                Record::A(_) | Record::AAAA(_) => {
                    return Ok(res);
                },
                _ => { },
            }
        }

        for rr in res.answers.iter() {
            match rr {
                Record::CNAME(inner) => {
                    res = lookup_inner(&inner.value).await?;
                    continue 'LOOP1;
                },
                _ => { },
            }
        }

        break;
    }

    Ok(res)
}

async fn lookup_inner(name: &str) -> Result<Response, Box<dyn std::error::Error>> {
    let req = Request {
        id: 100,
        flags: ReprFlags::default(),
        opcode: OpCode::QUERY,
        client_subnet: None,
        questions: vec![
            Question {
                name: String::from(name),
                kind: Kind::A,
                class: Class::IN,
            }
        ],
    };

    dbg!(&req);

    // ROOT SERVER L
    let root_server_l: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 41, 162, 30), 53));

    let mut buf = vec![0u8; 1024*4];

    let mut res = query(&req, &root_server_l, &mut buf).await?;
    loop {
        dbg!(&res);

        if res.id != req.id {
            return Err(wire::Error::from(wire::ErrorKind::ServerFailure).into());
        }

        if res.answers.len() > 0 {
            return Ok(res);
        }

        'LOOP2: for rr in res.authorities.iter() {
            match rr {
                Record::NS(ns_inner) => {
                    for rr2 in res.additionals.iter() {
                        match rr2 {
                            Record::A(inner) => {
                                if &ns_inner.value == rr2.name() {
                                    let addr = SocketAddr::V4(SocketAddrV4::new(inner.value, 53));
                                    res = query(&req, &addr, &mut buf).await?;
                                    break 'LOOP2;
                                }
                            },
                            Record::AAAA(inner) => {
                                if &ns_inner.value == rr2.name() {
                                    let addr = SocketAddr::V6(SocketAddrV6::new(inner.value, 53, 0, 0));
                                    res = query(&req, &addr, &mut buf).await?;
                                    break 'LOOP2;
                                }
                            },
                            _ => { },
                        }
                    }
                },
                Record::CNAME(_) => { },
                _ => { },
            }
        }
    }
}

pub fn parse_root_zone() {
    println!("Record Size: {:?}", std::mem::size_of::<wire::record::Record>() );

    let data = include_str!("../../data/root.zone");
    for line in data.lines() {
        println!("{:?}", line.parse::<wire::record::Record>());
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("RUST_LOG", "debug");

    env_logger::init();

    

    
    let mut args = env::args();
    args.next();
    let name = args.next().expect("./lookup www.qq.com");

    let mut rt = tokio::runtime::Runtime::new()?;
    rt.block_on(lookup(&name))?;
    rt.block_on(run_server())?;

    Ok(())
}
