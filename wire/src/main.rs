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
use wire::header::Question;
use wire::header::ReprFlags;
use wire::header::Response;
use wire::header::HeaderFlags;
use wire::ser::Serialize;
use wire::ser::Serializer;
use wire::de::Deserialize;
use wire::de::Deserializer;


use std::io;


pub fn handle_req(pkt: &[u8]) {
    let mut deserializer = Deserializer::new(&pkt);
    let ret = Request::deserialize(&mut deserializer);
    println!("{:?}", ret);
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
                    debug!("{:?}", data);
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("RUST_LOG", "debug");

    env_logger::init();

    println!("Record Size: {:?}", std::mem::size_of::<wire::record::Record>() );

    let req = Request {
        id: 0,
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

    let mut rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_server())?;

    Ok(())
}
