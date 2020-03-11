#![allow(unused_imports, unused_labels, unused_variables, dead_code)]

#[macro_use]
extern crate log;
extern crate resolver;
extern crate env_logger;
#[macro_use]
extern crate tokio;
#[macro_use]
extern crate clap;


use resolver::net::tls;
use resolver::net::h2::server::H2Listener;
use resolver::net::h2::server::H2Connection;
use resolver::net::h2::server::Http2Stream;

use tokio::net::UdpSocket;
use tokio::net::TcpListener;

use std::io;
use std::env;


async fn handle_h2_conn(mut conn: H2Connection) -> Result<(), h2::Error> {
    while let Some(chanel_res) = conn.accept().await {
        let mut channel = chanel_res?;
        let req_head = channel.head();
        
        info!("Request:");
        println!("{} {} {:?}", req_head.method, req_head.uri, req_head.version);
        for (k, v) in req_head.headers.iter() {
            println!("{}: {:?}", k, v);
        }
        println!();

        let req_body: Vec<u8> = channel.read_body().await?;
        if req_body.len() > 0 {
            let hexdata = req_body.iter().fold(String::new(), |mut acc, n| {
                acc.push_str(&format!("{:x}", n));
                acc
            });
            println!("0x{}", hexdata);
        }
        
        let response_body = Some("来自 H2 Server.".as_bytes().to_vec());
        let response = http::Response::builder()
            .status(http::StatusCode::OK)
            .header("Accept", "application/dns-message")
            .header("Content-Type", "application/dns-message")
            .version(http::Version::HTTP_2)
            .body(response_body)
            .unwrap();

        channel.write_response(response).await?;
        info!("Write Response Done.");
    }

    Ok(())
}

async fn run_h2_server() -> Result<(), Box<dyn std::error::Error>> {
    let ident = tls::TlsIdentity::from_pkcs12_file("./keys/server.pfx", "test123")?;
    let tls_listener = tls::TlsListener::bind("127.0.0.1:8000", ident).await?;
    let mut https_listenner: H2Listener = H2Listener::new(tls_listener);

    info!("H2 Server Ready ...");

    loop {
        let conn = https_listenner.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_h2_conn(conn).await {
                error!("{:?}", e);
            }
        });
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("RUST_LOG", "resolver=trace,h2server=trace");
    env_logger::init();

    let mut rt = tokio::runtime::Runtime::new()?;

    println!("{:?}", rt.block_on(run_h2_server()));

    Ok(())
}