use crate::wire;
use crate::net::UdpChannel;
use crate::net::TlsListener;
use crate::net::DtlsListener;

use std::fs;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::collections::HashMap;
use std::io::{self, Read, Write};

// MIO 初始状态
// TcpStream
//     N/A      -> writable
// TcpListenner
//     N/A      -> readable
// UdpSocket
//     writable -> readable/writable
// 

pub const TCP_SERVER: mio::Token  = mio::Token(5);
pub const UDP_SERVER: mio::Token  = mio::Token(6);
pub const TLS_SERVER: mio::Token  = mio::Token(7);
pub const DTLS_SERVER: mio::Token = mio::Token(8);

pub struct TcpStream {
    pub token: mio::Token,
    pub inner: mio::net::TcpStream,
}


pub enum StubState {
    Root,
    Toplevel,
}

pub enum State {
    Connected,
    HandleTlsHandshake,
    HandleHttpRequest,
    HandleDnsQuery,
    WaitDnsResponse,
}

pub trait ReadWrite: Read + Write { }


pub struct Task {
    pub token: mio::Token,
    // mio::net::TcpStream
    pub handle: Box<dyn ReadWrite>,
    pub state: State,
}

pub struct ServerConfig {
    pub tcp_addr: Option<SocketAddr>,      // 默认端口: 53
    pub udp_addr: Option<SocketAddr>,      // 默认端口: 53
    pub tls_addr: Option<SocketAddr>,      // 默认端口: 853
    pub dtls_addr: Option<SocketAddr>,     // 默认端口: 853
    pub tcp_dnscrypt: Option<SocketAddr>,  // 默认端口: 443 (跟 DNS over HTTPS 一样)
    pub udp_dnscrypt: Option<SocketAddr>,  // 默认端口: 443
}

pub struct Server {
    pub last_token: mio::Token,
    pub tcp_listener: Option<mio::net::TcpListener>,
    pub udp_listener: Option<UdpChannel>,
    pub tls_listener: Option<TlsListener>,
    pub dtls_listener: Option<DtlsListener>,

    // tcp/udp dnscrypt
}

impl Server {
    pub fn next_token(&mut self) -> mio::Token {
        self.last_token.0 += 1;

        self.last_token
    }
}

pub fn run_forever(config: ServerConfig) -> Result<(), Box<dyn std::error::Error>> {
    let mut buffer = wire::alloc();
    let mut events = mio::Events::with_capacity(1024);
    
    let poll = mio::Poll::new()?;

    let pkcs12_file  = fs::read("./keys/server.pfx")?;
    let tls_identity = native_tls::Identity::from_pkcs12(pkcs12_file.as_ref(), "test123")?;
    let mut tls_acceptor = native_tls::TlsAcceptor::builder(tls_identity)
        .min_protocol_version(Some(native_tls::Protocol::Tlsv11))
        .build()?;


    let mut root_names: HashMap<String, ()> = HashMap::new();
    let mut root_zone: HashMap<String, ()> = HashMap::new();

    let mut tasks: HashMap<mio::Token, Task> = HashMap::new();
    let mut subtasks: HashMap<mio::Token, mio::Token> = HashMap::new();

    // let ip = IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0));
    // let port = 9000u16;
    // let addr = SocketAddr::new(ip, port);
    // let mut tcp_listener = 
    // let mut udp_channel = UdpChannel::new(mio::net::UdpSocket::bind(&config.udp_addr)?);
    // println!("udp://{}", addr);

    // poll.register(&udp_channel, SERVER, mio::Ready::readable(), mio::PollOpt::edge())?;

    let mut buffer = [0u8; 1500];

    loop {
        poll.poll(&mut events, None)?;

        for event in events.iter() {
            let event_kind = event.readiness();
            let event_token = event.token();

            match event_token {
                TCP_SERVER => {
                    // let amt = udp_channel.read(&mut buffer)?;
                    // println!("read {:?} bytes from {}.", amt, udp_channel.peer_addr()?);
                    // println!("{:?}", &buffer[..amt]);

                    // let amt = udp_channel.write(&buffer[..amt])?;
                    // println!("write {:?} bytes to {}.", amt, udp_channel.peer_addr()?);
                },
                _ => unreachable!(),
            }
        }
    }
}