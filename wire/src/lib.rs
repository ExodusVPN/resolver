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