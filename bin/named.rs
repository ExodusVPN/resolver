#![allow(unused_imports, unused_labels, unused_variables, dead_code)]

#[macro_use]
extern crate log;
extern crate resolver;
extern crate env_logger;
#[macro_use]
extern crate tokio;
#[macro_use]
extern crate clap;


use resolver::name_server::NameServer;
use resolver::stub::Service;
use resolver::config::Config;

use tokio::net::UdpSocket;
use tokio::net::TcpListener;

use std::io;
use std::env;


async fn run() -> Result<(), io::Error> {
    try_join!(
        // run_udp_server("127.0.0.1:8000"),
        // run_tcp_server("127.0.0.1:3001")
    ).map(|_| ())
}


fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("RUST_LOG", "resolver=trace,named=trace");
    env_logger::init();

    println!("Example:

$ dig @127.0.0.1 video.qq.com -p 3000
$ dig @127.0.0.1 www.mypce.com -p 3000
$ dig @127.0.0.1 www.gov.cn -p 3000 AAAA

");

    let mut rt = tokio::runtime::Runtime::new()?;
    
    println!("{:?}", "udp+tcp://127.0.0.1?domain=dns.google&tcp_port=50".parse::<NameServer>() );
    
    let config = Config::default();
    let service = rt.block_on(Service::new(config))?;
    
    Ok(())
}