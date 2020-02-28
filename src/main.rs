#![allow(unused_imports, unused_labels, unused_variables, dead_code)]

#[macro_use]
extern crate log;
extern crate resolver;
extern crate env_logger;
#[macro_use]
extern crate tokio;

use resolver::run_udp_server;

use tokio::net::UdpSocket;
use tokio::net::TcpListener;

use std::io;
use std::env;




fn main() -> Result<(), Box<dyn std::error::Error>> {
    std::env::set_var("RUST_LOG", "debug");
    
    env_logger::init();
    
    let mut args = env::args();
    args.next();
    
    println!("Example:

$ dig @127.0.0.1 video.qq.com -p 3000
$ dig @127.0.0.1 www.mypce.com -p 3000
$ dig @127.0.0.1 www.gov.cn -p 3000 AAAA

");
    let mut rt = tokio::runtime::Runtime::new()?;
    
    rt.block_on(run_udp_server("127.0.0.1:3000"))?;
    
    Ok(())
}