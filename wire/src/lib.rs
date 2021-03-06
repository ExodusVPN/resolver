#![allow(dead_code, unused_variables, unused_assignments, unused_imports)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;
extern crate base64;
extern crate punycode;
extern crate chrono;


/// 255 octets or less
pub const MAXIMUM_NAMES_SIZE: usize = 255;
/// 63 octets or less
pub const MAXIMUM_LABEL_SIZE: usize = 63;


mod error;

mod kind;
mod class;
mod opcode;
mod rcode;
mod header;

pub mod edns;
pub mod dnssec;
pub mod record;

pub mod ser;
pub mod de;

pub use self::error::Error;
pub use self::error::ErrorKind;
pub use self::kind::Kind;
pub use self::class::Class;
pub use self::opcode::OpCode;
pub use self::rcode::ResponseCode;
pub use self::header::{Header, Request, Response, Question, ReprFlags, HeaderFlags, };

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use self::ser::Serialize;
use self::ser::Serializer;
use self::de::Deserialize;
use self::de::Deserializer;


pub fn serialize_req(req: &Request, buf: &mut [u8]) -> Result<usize, Error> {
    let mut serializer = Serializer::new(buf);
    req.serialize(&mut serializer)?;
    
    Ok(serializer.position())
}

pub fn deserialize_req(buf: &[u8]) -> Result<Request, Error> {
    let mut deserializer = Deserializer::new(&buf);
    let req = Request::deserialize(&mut deserializer)?;
    
    Ok(req)
}

pub fn serialize_res(res: &Response, buf: &mut [u8]) -> Result<usize, Error> {
    let mut serializer = Serializer::new(buf);
    res.serialize(&mut serializer)?;
    
    Ok(serializer.position())
}

pub fn deserialize_res(buf: &[u8]) -> Result<Response, Error> {
    let mut deserializer = Deserializer::new(&buf);
    let res = Response::deserialize(&mut deserializer)?;
    
    Ok(res)
}


bitflags! {
    pub struct Protocols: u8 {
        /// DNS Transport over TCP
        const TCP      = 0b_0000_0001;
        /// DNS Transport over UDP
        const UDP      = 0b_0000_0010;
        /// DNS Transport over TLS (DoT)
        const TLS      = 0b_0000_0100;
        /// DNS Transport over DTLS
        const DTLS     = 0b_0000_1000;
        /// DNS Transport over HTTPS (DoH)
        const HTTPS    = 0b_0001_0000;
        /// TCP-DNSCrypt
        const TCP_DNSCRYPT = 0b_0010_0000;
        /// UDP-DNSCrypt
        const UDP_DNSCRYPT = 0b_0100_0000;
    }
}

impl Protocols {
    pub fn new_unchecked(bits: u8) -> Self {
        unsafe {
            Self::from_bits_unchecked(bits)
        }
    }
}

impl Default for Protocols {
    fn default() -> Self {
        // NOTE: 虽然协议上，TCP 和 UDP 是必须要要实现的两个传输协议。
        //       但是实际上，有些权威服务并不支持 TCP 协议的 DNS 查询。
        //       比如腾讯的 DNS-POD 服务就不支持 TCP 协议。
        Protocols::UDP | Protocols::TCP
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum RootServer {
    A,
    B,
    C,
    D,
    E,
    F,
    G,
    H,
    I,
    J,
    K,
    L,
    M,
}

impl RootServer {
    pub fn v4_addr(&self) -> std::net::Ipv4Addr {
        use self::RootServer::*;

        match *self {
            A => Ipv4Addr::new(198, 41, 0, 4),     // 198.41.0.4
            B => Ipv4Addr::new(199, 9, 14, 201),   // 199.9.14.201
            C => Ipv4Addr::new(192, 33, 4, 12),    // 192.33.4.12
            D => Ipv4Addr::new(199, 7, 91, 13),    // 199.7.91.13
            E => Ipv4Addr::new(192, 203, 230, 10), // 192.203.230.10
            F => Ipv4Addr::new(192, 5, 5, 241),    // 192.5.5.241
            G => Ipv4Addr::new(192, 112, 36, 4),   // 192.112.36.4
            H => Ipv4Addr::new(198, 97, 190, 53),  // 198.97.190.53
            I => Ipv4Addr::new(192, 36, 148, 17),  // 192.36.148.17
            J => Ipv4Addr::new(192, 58, 128, 30),  // 192.58.128.30
            K => Ipv4Addr::new(193, 0, 14, 129),   // 193.0.14.129
            L => Ipv4Addr::new(199, 7, 83, 42),    // 199.7.83.42
            M => Ipv4Addr::new(202, 12, 27, 33),   // 202.12.27.33
        }
    }

    pub fn v6_addr(&self) -> std::net::Ipv6Addr {
        use self::RootServer::*;

        match *self {
            A => Ipv6Addr::new(0x2001, 0x0503, 0xba3e, 0x0000, 0x0000, 0x0000, 0x0002, 0x0030), // 2001:503:ba3e::2:30
            B => Ipv6Addr::new(0x2001, 0x0500, 0x0200, 0x0000, 0x0000, 0x0000, 0x0000, 0x000b), // 2001:500:200::b
            C => Ipv6Addr::new(0x2001, 0x0500, 0x0002, 0x0000, 0x0000, 0x0000, 0x0000, 0x000c), // 2001:500:2::c
            D => Ipv6Addr::new(0x2001, 0x0500, 0x002d, 0x0000, 0x0000, 0x0000, 0x0000, 0x000d), // 2001:500:2d::d
            E => Ipv6Addr::new(0x2001, 0x0500, 0x00a8, 0x0000, 0x0000, 0x0000, 0x0000, 0x000e), // 2001:500:a8::e
            F => Ipv6Addr::new(0x2001, 0x0500, 0x002f, 0x0000, 0x0000, 0x0000, 0x0000, 0x000f), // 2001:500:2f::f
            G => Ipv6Addr::new(0x2001, 0x0500, 0x0012, 0x0000, 0x0000, 0x0000, 0x0000, 0x0d0d), // 2001:500:12::d0d
            H => Ipv6Addr::new(0x2001, 0x0500, 0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0053), // 2001:500:1::53
            I => Ipv6Addr::new(0x2001, 0x07fe, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0053), // 2001:7fe::53
            J => Ipv6Addr::new(0x2001, 0x0503, 0x0c27, 0x0000, 0x0000, 0x0000, 0x0002, 0x0030), // 2001:503:c27::2:30
            K => Ipv6Addr::new(0x2001, 0x07fd, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001), // 2001:7fd::1
            L => Ipv6Addr::new(0x2001, 0x0500, 0x009f, 0x0000, 0x0000, 0x0000, 0x0000, 0x0042), // 2001:500:9f::42
            M => Ipv6Addr::new(0x2001, 0x0dc3, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0035), // 2001:dc3::35
        }
    }

    pub fn addrs(&self) -> [ std::net::IpAddr; 2] {
        [ IpAddr::V4(self.v4_addr()), IpAddr::V6(self.v6_addr()) ]
    }

    pub fn domain_name(&self) -> &'static str {
        use self::RootServer::*;

        match *self {
            A => "a.root-servers.net",
            B => "b.root-servers.net",
            C => "c.root-servers.net",
            D => "d.root-servers.net",
            E => "e.root-servers.net",
            F => "f.root-servers.net",
            G => "g.root-servers.net",
            H => "h.root-servers.net",
            I => "i.root-servers.net",
            J => "j.root-servers.net",
            K => "k.root-servers.net",
            L => "l.root-servers.net",
            M => "m.root-servers.net",
        }
    }
}


// DOD INTERNET HOST TABLE SPECIFICATION
// https://tools.ietf.org/html/rfc952
#[cfg(unix)]
pub const DEFAULT_HOSTS_FILE_PATH: &str = "/etc/hosts";
#[cfg(windows)]
pub const DEFAULT_HOSTS_FILE_PATH: &str = "C:\\Windows\\System32\\Drivers\\etc\\hosts";

pub fn load_hosts<P: AsRef<std::path::Path>>(filepath: P) -> Result<Vec<(String, IpAddr)>, std::io::Error> {
    let hosts_file = std::fs::read_to_string(filepath)?;
    let mut hosts = Vec::new();

    for line in hosts_file.lines() {
        let mut val = line.trim();
        if val.starts_with("#") {
            continue;
        }

        if val.contains('#') {
            val = val.split('#').next().unwrap();
        }

        let tmp = val.split(' ').collect::<Vec<&str>>();
        if tmp.len() < 2 {
            debug!("invalid host line: {:?}", val);
            continue
        }

        let addr_str = tmp[0];
        match addr_str.parse::<IpAddr>() {
            Ok(addr) => {
                for hostname in &tmp[1..] {
                    let name = hostname.trim().to_string();
                    hosts.push((name, addr));
                }
            },
            Err(_) => {
                debug!("invalid IP address syntax: {}", addr_str);
            }
        }
    }

    Ok(hosts)
}