#![allow(unused_imports)]

#[macro_use]
extern crate log;
extern crate env_logger;
#[macro_use]
extern crate tokio;
extern crate wire;

use tokio::net::UdpSocket;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;

use wire::kind::Kind;
use wire::class::Class;
use wire::opcode::OpCode;
use wire::header::Request;
use wire::header::Response;
use wire::header::Question;
use wire::header::ReprFlags;
use wire::header::HeaderFlags;
use wire::ser::Serialize;
use wire::ser::Serializer;
use wire::de::Deserialize;
use wire::de::Deserializer;


use std::io;

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

async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    let req = Request {
        id: 100,
        flags: ReprFlags::default(),
        opcode: OpCode::QUERY,
        client_subnet: None,
        questions: vec![
            Question {
                name: String::from("www.baidu.com"),
                kind: Kind::A,
                class: Class::IN,
            }
        ],
    };

    println!("{:?}", req);

    let mut buf = vec![0u8; 1024*4];
    let mut serializer = Serializer::new(&mut buf);
    req.serialize(&mut serializer)?;
    
    let pos = serializer.position();
    let buf = serializer.get_ref();
    let pkt = &buf[..pos];
    let len = pkt.len() as u16;

    use std::io::Write;
    use std::io::Read;
    use crate::tokio::io::AsyncWriteExt;
    use crate::tokio::io::AsyncReadExt;

    // println!("{:?}", pkt);
    handle_req(&pkt);


    let mut stream = tokio::net::TcpStream::connect("8.8.8.8:53").await?;
    stream.write_all( &len.to_be_bytes() ).await?;
    stream.write_all( &pkt ).await?;

    let mut buf = vec![0u8; 1024*4];
    stream.read_exact(&mut buf[..2]).await?;
    let amt = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    
    info!("response pkt size: {}", amt);

    stream.read_exact(&mut buf[..amt]).await?;
    let pkt = &buf[..amt];

    // println!("{:?}", pkt);
    handle_res(&pkt);
    
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("RUST_LOG", "debug");

    env_logger::init();

    println!("Record Size: {:?}", std::mem::size_of::<wire::record::Record>() );

    let data = include_str!("../../data/root.zone");
    for line in data.lines() {
        // println!("{:?}", line.parse::<wire::record::Record>());
    }

    let mut rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_client())?;
    rt.block_on(run_server())?;

    Ok(())
}
