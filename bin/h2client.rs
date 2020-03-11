#![allow(unused_imports, unused_labels, unused_variables, dead_code)]

#[macro_use]
extern crate log;
extern crate resolver;
extern crate env_logger;
#[macro_use]
extern crate tokio;

#[macro_use]
extern crate clap;

use http;

use resolver::net::h2::client::H2Connection;

use std::io;
use std::env;


pub async fn h2get() -> Result<(), Box<dyn std::error::Error>> {
    // "1.1.1.1:443"
    // "video.qq.com:443"
    // let mut conn = H2Connection::connect("video.qq.com").await?;
    let mut conn = H2Connection::connect("127.0.0.1:8000").await?;
    
    // GET
    let request = http::Request::builder()
        .method(http::Method::GET)
        .uri("/dns-query?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(None)
        .unwrap();
    let response = conn.write_request(request).await?.read_response().await?;
    info!("{:?}", response);
    
    // POST
    let request = http::Request::builder()
        .method(http::Method::POST)
        .uri("/dns-query2?dns=AAABAAABAAAAAAAAA3d3dwdleGFtcGxlA2NvbQAAAQAB")
        .header("Content-Type", "application/dns-message")
        .header("Accept", "application/dns-message")
        .body(Some("hello world!".as_bytes().to_vec()))
        .unwrap();
    let response = conn.write_request(request).await?.read_response().await?;
    info!("{:?}", response);
    
    Ok(())
}

async fn send_dns_req_via_dot() -> Result<(), Box<dyn std::error::Error>> {
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;

    use resolver::wire;
    use resolver::net::tls;

    let qname = "www.baidu.com";
    let name_server_domain = "dns.google";
    let name_server = "8.8.8.8:853";

    info!("DNS Lookup Host {:?}", qname);

    let pkt = [0u8, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, 119, 119, 119, 7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1];

    let req = wire::Request {
        id: rand::random(),
        flags: wire::ReprFlags::default(),
        opcode: wire::OpCode::QUERY,
        client_subnet: None,
        questions: vec![
            wire::Question {
                name: String::from(qname),
                kind: wire::Kind::A,
                class: wire::Class::IN,
            }
        ],
    };

    let mut buf = vec![0u8; 4096];
    let amt = wire::serialize_req(&req, &mut buf[2..])?;
    &mut buf[..2].copy_from_slice(&(amt as u16).to_be_bytes());

    let pkt = &buf[..amt+2];


    let mut tls_stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tls::TlsStream::connect(name_server_domain, name_server)
    )
    .await??;

    tls_stream.write_all(&pkt).await?;

    let mut res = vec![0u8; 1024];
    
    let amt = tls_stream.read(&mut res).await?;
    let pkt = &res[2..amt];

    info!("Received {} bytes from {}", amt, name_server);
    
    let res = wire::deserialize_res(pkt)?;

    println!("{:?}", res);

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("RUST_LOG", "resolver=trace,h2client=trace");
    env_logger::init();
    
    let mut rt = tokio::runtime::Runtime::new()?;
    
    println!("Ret: {:?}", rt.block_on(h2get()));
    
    println!("Ret: {:?}", rt.block_on(send_dns_req_via_dot()));

    Ok(())
}
