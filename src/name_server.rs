use crate::protocol::Protocol;
use crate::protocol::ProtocolSet;

use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;


pub const DEFAULT_UDP_PORT: u16  = 53;
pub const DEFAULT_TCP_PORT: u16  = 53;
pub const DEFAULT_DOT_PORT: u16  = 853;
pub const DEFAULT_DOH_PORT: u16  = 443;
pub const DEFAULT_MDNS_PORT: u16 = 5353;
pub const DEFAULT_TCP_DNSCRYPT_PORT: u16 = 443; // NOTE: 也许改为 5443 ?
pub const DEFAULT_UDP_DNSCRYPT_PORT: u16 = 443;


pub static ROOT_V4_SERVERS: [(&'static str, IpAddr); 13] = [
    ("a.root-servers.net", IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4))),     // 198.41.0.4
    ("b.root-servers.net", IpAddr::V4(Ipv4Addr::new(199, 9, 14, 201))),   // 199.9.14.201
    ("c.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12))),    // 192.33.4.12
    ("d.root-servers.net", IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13))),    // 199.7.91.13
    ("e.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10))), // 192.203.230.10
    ("f.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 5, 5, 241))),    // 192.5.5.241
    ("g.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 112, 36, 4))),   // 192.112.36.4
    ("h.root-servers.net", IpAddr::V4(Ipv4Addr::new(198, 97, 190, 53))),  // 198.97.190.53
    ("i.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 36, 148, 17))),  // 192.36.148.17
    ("j.root-servers.net", IpAddr::V4(Ipv4Addr::new(192, 58, 128, 30))),  // 192.58.128.30
    ("k.root-servers.net", IpAddr::V4(Ipv4Addr::new(193, 0, 14, 129))),   // 193.0.14.129
    ("l.root-servers.net", IpAddr::V4(Ipv4Addr::new(199, 7, 83, 42))),    // 199.7.83.42
    ("m.root-servers.net", IpAddr::V4(Ipv4Addr::new(202, 12, 27, 33))),   // 202.12.27.33
];

pub static ROOT_V6_SERVERS: [(&'static str, IpAddr); 13] = [
    ("a.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0503, 0xba3e, 0x0000, 0x0000, 0x0000, 0x0002, 0x0030))), // 2001:503:ba3e::2:30
    ("b.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x0200, 0x0000, 0x0000, 0x0000, 0x0000, 0x000b))), // 2001:500:200::b
    ("c.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x0002, 0x0000, 0x0000, 0x0000, 0x0000, 0x000c))), // 2001:500:2::c
    ("d.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x002d, 0x0000, 0x0000, 0x0000, 0x0000, 0x000d))), // 2001:500:2d::d
    ("e.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x00a8, 0x0000, 0x0000, 0x0000, 0x0000, 0x000e))), // 2001:500:a8::e
    ("f.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x002f, 0x0000, 0x0000, 0x0000, 0x0000, 0x000f))), // 2001:500:2f::f
    ("g.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x0012, 0x0000, 0x0000, 0x0000, 0x0000, 0x0d0d))), // 2001:500:12::d0d
    ("h.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0053))), // 2001:500:1::53
    ("i.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x07fe, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0053))), // 2001:7fe::53
    ("j.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0503, 0x0c27, 0x0000, 0x0000, 0x0000, 0x0002, 0x0030))), // 2001:503:c27::2:30
    ("k.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x07fd, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001))), // 2001:7fd::1
    ("l.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x009f, 0x0000, 0x0000, 0x0000, 0x0000, 0x0042))), // 2001:500:9f::42
    ("m.root-servers.net", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0dc3, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0035))), // 2001:dc3::35
];

// pub struct NameServer2 {
//     provider_name: &'static str,
//     domain_name: &'static str,
//     ip_addrs: &'static [std::net::IpAddr],
//     udp_port: Option<u16>,
//     tcp_port: Option<u16>,
//     tls_port: Option<u16>,
//     https_port: Option<u16>,
//     // https_port: Option<u16>,
//     dnscrypt_tcp_port: Option<u16>,
//     dnscrypt_udp_port: Option<u16>,

//     support_edns0: bool,
//     support_ecs: bool,
// }

// Example:
//      udp+tcp+tls+https://8.8.8.8?domain=dns.google&tcp_port=53
//      udp+tcp+tls+https://8.8.4.4?domain=dns.google&tcp_port=53
//      udp+tcp://1.1.1.1?domain=one.one.one.one
//      udp+tcp://9.9.9.9
// 
#[derive(Debug, Clone)]
pub struct NameServer {
    domain: Option<String>,
    protocol_set: ProtocolSet,
    ip: std::net::IpAddr,
    udp_port: Option<u16>,
    tcp_port: Option<u16>,
    tls_port: Option<u16>,
    https_port: Option<u16>,
    dnscrypt_udp_port: Option<u16>,
    dnscrypt_tcp_port: Option<u16>,
}

impl NameServer {
    pub fn new_default<A: Into<std::net::IpAddr>>(domain: Option<String>, ip: A) -> Self {
        // NOTE: 默认使用 TCP ，而不是 UDP.
        const DEFAULT_PROTOCOLS: [Protocol; 2] = [ Protocol::Tcp, Protocol::Udp, ];

        let ip = ip.into();

        NameServer {
            domain,
            protocol_set: ProtocolSet::new(&DEFAULT_PROTOCOLS).unwrap(),
            ip,
            udp_port: Some(DEFAULT_UDP_PORT),
            tcp_port: Some(DEFAULT_TCP_PORT),
            tls_port: None,
            https_port: None,
            dnscrypt_udp_port: None,
            dnscrypt_tcp_port: None,
        }
    }

    #[inline]
    pub fn domain(&self) -> Option<&str> {
        match self.domain {
            Some(ref s) => Some(s),
            None => None,
        }
    }

    #[inline]
    pub fn ip(&self) -> std::net::IpAddr {
        self.ip
    }
    
    pub fn socket_addr_by(&self, protocol: Protocol) -> Option<std::net::SocketAddr> {
        let port = match protocol {
            Protocol::Udp         => self.udp_port,
            Protocol::Tcp         => self.tcp_port,
            Protocol::Tls         => self.tls_port,
            Protocol::Https       => self.https_port,
            Protocol::DNSCryptUdp => self.dnscrypt_udp_port,
            Protocol::DNSCryptTcp => self.dnscrypt_tcp_port,
        };
        port.map(|port| std::net::SocketAddr::new(self.ip, port))
    }

    #[inline]
    pub fn protocols(&self) -> ProtocolSet {
        self.protocol_set
    }
}


impl std::str::FromStr for NameServer {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse::<http::uri::Uri>() {
            Ok(uri) => {
                

                let protocols = match uri.scheme_str() {
                    Some(scheme) => {
                        let mut protocols = vec![];
                        for s in scheme.split('+') {
                            match s.to_lowercase().as_str() {
                                "udp" => protocols.push(Protocol::Udp),
                                "tcp" => protocols.push(Protocol::Tcp),
                                "tls" => protocols.push(Protocol::Tls),
                                "https" => protocols.push(Protocol::Https),
                                "dnscrypt-udp" => protocols.push(Protocol::DNSCryptUdp),
                                "dnscrypt-tcp" => protocols.push(Protocol::DNSCryptTcp),
                                _ => { },
                            }
                        }
                        protocols
                    },
                    None => {
                        vec![ Protocol::Tcp, Protocol::Udp, ]
                    },
                };

                let protocol_set = match ProtocolSet::new(&protocols) {
                    Ok(p) => p,
                    Err(e) => {
                        error!("{:?}", e);
                        return Err(());
                    },
                };

                let ip = match uri.host() {
                    Some(host) => {
                        match host.parse::<std::net::IpAddr>() {
                            Ok(ip) => ip,
                            Err(e) => {
                                let host_iter = if !host.contains(":") {
                                    std::net::ToSocketAddrs::to_socket_addrs(&format!("{}:0", host))
                                } else {
                                    std::net::ToSocketAddrs::to_socket_addrs(&host)
                                };
                                match host_iter {
                                    Ok(mut iter) => {
                                        match iter.next() {
                                            Some(socket_addr) => socket_addr.ip(),
                                            None => {
                                                error!("No Host Ip.");
                                                return Err(());
                                            }
                                        }
                                    },
                                    Err(e) => {
                                        error!("No Host Ip.");
                                        return Err(());
                                    }
                                }
                                
                            }
                        }
                    },
                    None => {
                        error!("No Host.");
                        return Err(());
                    }
                };

                let mut domain = None;

                let mut tcp_port = None;
                let mut udp_port = None;
                let mut tls_port = None;
                let mut https_port = None;
                let mut dnscrypt_udp_port = None;
                let mut dnscrypt_tcp_port = None;

                match uri.query() {
                    Some(query) => {
                        for kv in query.split('&') {
                            let pair = kv.split('=').collect::<Vec<&str>>();
                            if pair.len() > 1 {
                                let key = pair[0];
                                let val = pair[1];
                                match key {
                                    "domain" => {
                                        if domain.is_none() {
                                            domain = Some(val.to_string());
                                        }
                                    },
                                    "tcp_port" => {
                                        if tcp_port.is_none() {
                                            if let Ok(port) = val.parse::<u16>() {
                                                tcp_port = Some(port);
                                            }
                                        }
                                    },
                                    "udp_port" => {
                                        if udp_port.is_none() {
                                            if let Ok(port) = val.parse::<u16>() {
                                                udp_port = Some(port);
                                            }
                                        }
                                    },
                                    "tls_port" => {
                                        if tls_port.is_none() {
                                            if let Ok(port) = val.parse::<u16>() {
                                                tls_port = Some(port);
                                            }
                                        }
                                    },
                                    "https_port" => {
                                        if https_port.is_none() {
                                            if let Ok(port) = val.parse::<u16>() {
                                                https_port = Some(port);
                                            }
                                        }
                                    },
                                    "dnscrypt_udp_port" => {
                                        if dnscrypt_udp_port.is_none() {
                                            if let Ok(port) = val.parse::<u16>() {
                                                dnscrypt_udp_port = Some(port);
                                            }
                                        }
                                    },
                                    "dnscrypt_tcp_port" => {
                                        if dnscrypt_tcp_port.is_none() {
                                            if let Ok(port) = val.parse::<u16>() {
                                                dnscrypt_tcp_port = Some(port);
                                            }
                                        }
                                    },
                                    _ => { },
                                }
                            }
                        }
                    },
                    None => {

                    }
                }

                for p in protocols.iter() {
                    match p {
                        Protocol::Udp => {
                            if udp_port.is_none() {
                                udp_port = Some(DEFAULT_UDP_PORT);
                            }
                        },
                        Protocol::Tcp => {
                            if tcp_port.is_none() {
                                tcp_port = Some(DEFAULT_TCP_PORT);
                            }
                        },
                        Protocol::Tls => {
                            if tls_port.is_none() {
                                tls_port = Some(DEFAULT_DOT_PORT);
                            }
                        },
                        Protocol::Https => {
                            if https_port.is_none() {
                                https_port = Some(DEFAULT_DOH_PORT);
                            }
                        },
                        Protocol::DNSCryptUdp => {
                            if dnscrypt_udp_port.is_none() {
                                dnscrypt_udp_port = Some(DEFAULT_UDP_DNSCRYPT_PORT);
                            }
                        },
                        Protocol::DNSCryptTcp => {
                            if dnscrypt_tcp_port.is_none() {
                                dnscrypt_tcp_port = Some(DEFAULT_TCP_DNSCRYPT_PORT);
                            }
                        },
                    }
                }

                Ok(NameServer {
                    domain,
                    protocol_set,
                    ip,
                    udp_port,
                    tcp_port,
                    tls_port,
                    https_port,
                    dnscrypt_udp_port,
                    dnscrypt_tcp_port,
                })
            },
            Err(e) => {
                error!("Parse NameServer URI Error: {:?}", e);
                Err(())
            }
        }
    }
}

// impl std::convert::TryFrom<http::uri::Uri> for NameServer {
//     type Error = &'static str;

//     fn try_from(uri: http::uri::Uri) -> Result<Self, Self::Error> {
//         todo!()
//     }
// }

// impl Into<http::uri::Uri> for NameServer {
//     fn into(self) -> http::uri::Uri {
//         todo!()
//     }
// }
