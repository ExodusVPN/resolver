use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;


pub enum Kind {
    V4,
    V6,
    ALL,
}

pub trait ToIpAddrs {
    fn to_ip_addrs(&self) -> Result<Vec<IpAddr>, io::Error>;
}

pub trait ToIpv4Addrs {
    fn to_ipv4_addrs(&self) -> Result<Vec<Ipv4Addr>, io::Error>;
}

pub trait ToIpv6Addrs {
    fn to_ipv6_addrs(&self) -> Result<Vec<Ipv6Addr>, io::Error>;
}

pub trait ToSocketAddrs {
    type Iter: Iterator<Item = SocketAddr>;
    fn to_socket_addrs(&self) -> Result<Self::Iter>;
}

// impl ToSocketAddrs for (String)