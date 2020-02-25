#![allow(unused_imports, unused_labels, unused_variables, dead_code)]

#[macro_use]
extern crate log;
pub extern crate wire;

pub mod cache;

// pub mod tcp;
// pub mod udp;
// pub mod tls;

use wire::Kind;
use wire::Class;
use wire::Request;
use wire::Response;
use wire::Protocols;
use wire::record::Record;
use wire::serialize_req;
use wire::serialize_res;
use wire::deserialize_req;
use wire::deserialize_res;


use std::io;
use std::env;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;

use tokio::net::UdpSocket;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::ToSocketAddrs;

const MAX_BUFF_SIZE: usize = 1 << 16 + 2; // 64 Kb
const MAX_NS_HOP: usize    = 16;
const MAX_CNAME_HOP: usize = 16;


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


#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NameServer {
    domain_name: Option<String>,
    socket_addr: SocketAddr,
    protocols: Protocols,
}

impl NameServer {
    pub fn new<A: std::net::ToSocketAddrs>(domain_name: Option<String>, addr: A, protocols: Protocols) -> Result<Self, io::Error> {
        let addrs = addr.to_socket_addrs()?;
        
        for addr in addrs {
            return Ok(Self { domain_name, socket_addr: addr, protocols });
        }

        Err(io::Error::new(io::ErrorKind::InvalidData, "could not resolve to any addresses"))
    }

    pub fn ip(&self) -> IpAddr {
        self.socket_addr.ip()
    }

    pub fn set_ip(&mut self, new_ip: IpAddr) {
        self.socket_addr.set_ip(new_ip)
    }

    pub fn port(&self) -> u16 {
        self.socket_addr.port()
    }

    pub fn set_port(&mut self, new_port: u16) {
        self.socket_addr.set_port(new_port)
    }

    pub fn is_ipv4(&self) -> bool {
        self.socket_addr.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.socket_addr.is_ipv6()
    }

    pub fn protocols(&self) -> Protocols {
        self.protocols
    }

    pub fn set_protocols(&mut self, protocols: Protocols) {
        self.protocols = protocols;
    }

    pub fn domain_name(&self) -> Option<&str>{
        match self.domain_name {
            Some(ref name) => Some(name),
            None => None,
        }
    }

    pub fn set_domain_name(&mut self, domain_name: Option<String>) {
        self.domain_name = domain_name;
    }

    pub fn is_tcp(&self) -> bool {
        self.protocols.contains(Protocols::TCP)
    }

    pub fn is_udp(&self) -> bool {
        self.protocols.contains(Protocols::UDP)
    }

    pub fn is_tls(&self) -> bool {
        self.protocols.contains(Protocols::TLS)
    }

    pub fn is_dtls(&self) -> bool {
        self.protocols.contains(Protocols::DTLS)
    }

    pub fn is_https(&self) -> bool {
        self.protocols.contains(Protocols::HTTPS)
    }

    pub async fn query(&self, req: &Request, buf: &mut [u8]) -> Result<Response, wire::Error> {
        if !self.is_tcp() && !self.is_udp() {
            return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "DNS Protocol not supported."))
        }

        if req.questions.len() == 0 {
            return Err(wire::Error::new(wire::ErrorKind::FormatError, "DNS Query must have questions."));
        }

        if req.questions.len() > 1 {
            warn!("Only the first question record will be sent to the query, the rest will be ignored");
        }

        debug!("Sent DNS Query to {:?}://{} {:?} ...", &self.protocols, &self.socket_addr, self.domain_name);
        debug!("{:?}", req);

        let amt = serialize_req(req, &mut buf[2..])?;

        if amt > std::u16::MAX as usize {
            return Err(wire::Error::from(wire::ErrorKind::ServerFailure));
        }

        &mut buf[..2].copy_from_slice(&(amt as u16).to_be_bytes());

        let mut stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::TcpStream::connect(&self.socket_addr)
        )
            .await
            .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))??;
        
        stream.write_all(&buf[..amt+2])
            .await
            .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;

        stream.read_exact(&mut buf[..2])
            .await
            .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;
        let amt = u16::from_be_bytes([buf[0], buf[1]]) as usize;

        if amt > std::cmp::min(buf.len(), std::u16::MAX as usize) {
            return Err(wire::Error::from(wire::ErrorKind::ServerFailure));
        }

        stream.read_exact(&mut buf[..amt])
            .await
            .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;

        let pkt = &buf[..amt];
        let res = deserialize_res(pkt)
            .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;

        if res.id != req.id {
            return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "DNS Message ID not match."));
        }

        debug!("{:?}", &res);

        Ok(res)
    }
}


#[derive(Debug, Clone)]
pub struct Resolver {
    cache: cache::Cache,
    name_server: NameServer,
}

fn root_server_l() -> SocketAddr {
    // ROOT SERVER L
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 41, 162, 30), 53))
}

impl Resolver {
    pub fn new() -> Result<Self, io::Error> {
        let ns = NameServer::new(Some(String::from("l.root-servers.net")), root_server_l(), Protocols::default())?;
        Ok(Self::with_name_server(ns))
    }

    pub fn with_name_server(name_server: NameServer) -> Self {
        Self { cache: cache::Cache::new(), name_server, }
    }

    pub async fn lookup_host_v4(&mut self, name: &str, buf: &mut [u8]) -> Result<Vec<Ipv4Addr>, wire::Error> {
        let res = self.lookup(name, wire::Kind::A, wire::Class::IN, buf).await?;
        
        let addrs = res.answers.iter().filter_map(|rr| {
            match rr {
                Record::A(inner) => Some(inner.value),
                _ => None,
            }
        }).collect::<Vec<Ipv4Addr>>();

        if addrs.is_empty() {
            return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "could not resolve to any addresses"));
        }

        Ok(addrs)
    }

    pub async fn lookup_host_v6(&mut self, name: &str, buf: &mut [u8]) -> Result<Vec<Ipv6Addr>, wire::Error> {
        let res = self.lookup(name, wire::Kind::AAAA, wire::Class::IN, buf).await?;

        let addrs = res.answers.iter().filter_map(|rr| {
            match rr {
                Record::AAAA(inner) => Some(inner.value),
                _ => None,
            }
        }).collect::<Vec<Ipv6Addr>>();

        if addrs.is_empty() {
            return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "could not resolve to any addresses"));
        }

        Ok(addrs)
    }

    pub async fn lookup_host(&mut self, name: &str, buf: &mut [u8]) -> Result<Vec<IpAddr>, wire::Error> {
        let res = self.lookup(name, wire::Kind::A, wire::Class::IN, buf).await?;
        
        let mut addrs = res.answers.iter().filter_map(|rr| {
            match rr {
                Record::A(inner) => Some(IpAddr::V4(inner.value)),
                _ => None,
            }
        }).collect::<Vec<IpAddr>>();

        let res = self.lookup(name, wire::Kind::AAAA, wire::Class::IN, buf).await?;
        for rr in res.answers {
            match rr {
                Record::AAAA(inner) => addrs.push(IpAddr::V6(inner.value)),
                _ => { },
            }
        }

        if addrs.is_empty() {
            return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "could not resolve to any addresses"));
        }

        Ok(addrs)
    }

    pub async fn lookup(&mut self, name: &str, kind: wire::Kind, class: wire::Class, buf: &mut [u8]) -> Result<Response, wire::Error> {
        let req = Request {
            id: 100,
            flags: wire::ReprFlags::default(),
            opcode: wire::OpCode::QUERY,
            client_subnet: None,
            questions: vec![
                wire::Question {
                    name: String::from(name),
                    kind: kind,
                    class: class,
                }
            ],
        };

        self.rquery(&req, None, buf).await
    }

    pub async fn query(&mut self, req: &Request, name_server: Option<&NameServer>, buf: &mut [u8]) -> Result<Response, wire::Error> {
        let name_server = name_server.unwrap_or(&self.name_server);
        let name_server_ip = name_server.ip();

        // NOTE: 也许使用 DomainName 作为缓存的键？
        match self.cache.get(req, name_server_ip) {
            Some(res) => {
                Ok(res.clone())
            },
            None => {
                let res = name_server.query(req, buf).await?;
                // Update DNS Cache
                self.cache.insert(req, name_server_ip, &res);

                Ok(res)
            }
        }
    }

    /// Recursive Query
    pub async fn rquery(&mut self, req: &Request, name_server: Option<&NameServer>, buf: &mut [u8]) -> Result<Response, wire::Error> {
        if req.questions.is_empty() {
            trace!("DNS Query must have questions.");
            return Err(wire::Error::from(wire::ErrorKind::FormatError));
        }

        let mut ns_hop_count = 0usize;
        // let mut cname_hop_count = 0usize;

        let mut res = self.nsquery(req, name_server, buf, &mut ns_hop_count).await?;
        let mut cnames = Vec::new();
        'LOOP1: loop {
            if res.answers.is_empty() {
                let ns_names = res.authorities.iter().rev().filter_map(|rr| {
                    match rr {
                        Record::NS(ref ns) => Some(ns.value.as_str()),
                        _ => None,
                    }
                }).collect::<Vec<&str>>();

                if ns_names.is_empty() {
                    return Ok(res);
                }

                // NOTE: Lookup NS Name.
                for ns_name in ns_names {
                    warn!("NS({:?}) IP Addr not found in additionals section.", &ns_name);

                    let mut req = req.clone();
                    let question = &mut req.questions[0];
                    question.name = ns_name.to_string();

                    match self.nsquery(&req, name_server, buf, &mut ns_hop_count).await {
                        Ok(res2) => {
                            res = res2;
                            continue 'LOOP1;
                        },
                        Err(e) => {
                            error!("{:?}", e);
                        },
                    }
                }
            }

            if cnames.len() > 16 {
                return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "Too many CNAME."));
            }

            let mut has_cname = false;
            'LOOP2: for rr in res.answers.iter().rev() {
                match rr {
                    Record::CNAME(ref cname) => {
                        has_cname = true;

                        let mut req = req.clone();
                        let question = &mut req.questions[0];
                        question.name = cname.value.clone();

                        let cname_rr_clone = rr.clone();

                        // NOTE: CNAME 是否允许失败？
                        //       这里暂时不支持失败！
                        res = self.nsquery(&req, name_server, buf, &mut ns_hop_count).await?;
                        cnames.push(cname_rr_clone);
                        break 'LOOP2;
                    },
                    _ => { }
                }
            }

            if !has_cname {
                break;
            }
        }

        cnames.reverse();

        for cname in cnames {
            res.answers.insert(0, cname);
        }

        Ok(res)
    }

    async fn nsquery(&mut self, req: &Request, name_server: Option<&NameServer>, buf: &mut [u8], ns_hop_count: &mut usize) -> Result<Response, wire::Error> {
        let mut res = self.query(req, name_server, buf).await?;
        *ns_hop_count += 1;

        'LOOP1: loop {
            if !res.answers.is_empty() {
                return Ok(res);
            }

            if res.authorities.is_empty() {
                warn!("Authority Section is empty.");
                return Ok(res);
            }

            if *ns_hop_count > MAX_NS_HOP {
                return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "Too many NS Hop."));
            }

            let mut name_servers: Vec<(&str, NameServer)> = Vec::new();
            let mut name_servers2: Vec<&str> = Vec::new();

            for rr in res.authorities.iter().rev() {
                match rr {
                    Record::NS(ref ns) => {
                        let mut has_ns_addr = false;
                        // for records in &[ &res.answers, &res.authorities, &res.additionals ] {
                        for records in &[ &res.additionals ] {
                            for rr2 in records.iter() {
                                match rr2 {
                                    Record::A(rdata) => {
                                        if rdata.name.as_str() != ns.value.as_str() {
                                            continue;
                                        }
                                        if !self.name_server.is_ipv4() {
                                            continue;
                                        }

                                        let ns_addr = SocketAddr::from((rdata.value, 53u16));
                                        let name_server = NameServer::new(Some(ns.value.clone()), ns_addr, Protocols::default())
                                            .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;

                                        has_ns_addr = true;
                                        name_servers.push((&ns.value, name_server));
                                    },
                                    Record::AAAA(rdata) => {
                                        if rdata.name.as_str() != ns.value.as_str() {
                                            continue;
                                        }
                                        if !self.name_server.is_ipv6() {
                                            continue;
                                        }

                                        let ns_addr = SocketAddr::from((rdata.value, 53u16));
                                        let name_server = NameServer::new(Some(ns.value.clone()), ns_addr, Protocols::default())
                                            .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;

                                        has_ns_addr = true;
                                        name_servers.push((&ns.value, name_server));
                                    },
                                    _ => { },
                                }
                            }
                        }

                        if !has_ns_addr {
                            // NOTE: 尝试从 ROOT_SERVERS 里面寻找
                            let root_servers = if self.name_server.is_ipv4() { &ROOT_V4_SERVERS } else { &ROOT_V6_SERVERS };

                            for  (root_name, root_addr) in root_servers.iter() {
                                if root_name != &ns.value.as_str() {
                                    continue;
                                }

                                let ns_addr = SocketAddr::new(*root_addr, 53u16);
                                let name_server = NameServer::new(Some(ns.value.clone()), ns_addr, Protocols::default())
                                    .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;

                                has_ns_addr = true;
                                name_servers.push((&ns.value, name_server));
                            }
                        }

                        if !has_ns_addr {
                            // TODO: 尝试从系统里面的 HOSTS 文件当中查找 (/etc/hosts)

                        }

                        if !has_ns_addr {
                            // NOTE: 无法找到该 NS 对应的 IP 地址。
                            name_servers2.push(&ns.value);
                        }
                    },
                    Record::CNAME(ref cname) => {
                        // WARN: 畸形的数据包。
                        warn!("Ignore CNAME Record in Authority Section.");
                    },
                    _ => { },
                }
            }

            if name_servers.is_empty() && name_servers2.is_empty() {
                // NOTE: 无法进行下一步的 NS 地址查询。
                warn!("Answers NotFound && NS Record NotFound.");
                return Ok(res);
            }

            let mut res2 = None;

            for (ns, name_server) in name_servers.iter() {
                debug!("Switch name server to: {:?}", name_server);

                match self.query(&req, Some(&name_server), buf).await {
                    Ok(res) => {
                        res2 = Some(res);
                        *ns_hop_count += 1;
                        break;
                    },
                    Err(e) => {
                        error!("{:?}", e);
                    }
                }
            }

            if name_servers.is_empty() && res2.is_none() {
                return Ok(res);
            }

            match res2 {
                Some(res2) => {
                    res = res2;
                },
                None => {
                    return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "NS DomainName cannot be resolved."));
                }
            }
        }
    }

    pub async fn resolv(&mut self, req: &Request, buf: &mut [u8]) -> Result<Response, wire::Error> {
        todo!()
    }
}



pub async fn run_udp_server<A: ToSocketAddrs>(addr: A) -> Result<(), tokio::io::Error> {
    let mut buf = [0u8; MAX_BUFF_SIZE];
    let mut listener = UdpSocket::bind(addr).await?;

    debug!("DNS service running at udp://{} ...", listener.local_addr()?);

    let mut resolver = Resolver::new()?;
    loop {
        match listener.recv_from(&mut buf).await {
            Ok((0, _)) => continue,
            Ok((amt, peer_addr)) => {
                let pkt = &buf[..amt];

                trace!("[UDP] received {:?} bytes from {:?}", pkt.len(), peer_addr);

                match deserialize_req(pkt) {
                    Ok(req) => {
                        match resolver.rquery(&req, None, &mut buf).await {
                            Ok(mut res) => {
                                debug!("{:?}", &res);
                                if res.answers.len() > 0 {
                                    info!("Answers Section:");
                                    for rr in res.answers.iter() {
                                        info!("{:?}", rr);
                                    }
                                }

                                res.questions = req.questions.clone();
                                res.id = req.id;
                                res.authorities.clear();
                                // res.additionals.clear();
                                res.flags |= wire::ReprFlags::RA;
                                if let Ok(amt) = serialize_res(&res, &mut buf) {
                                    let pkt = &buf[..amt];
                                    let _ = listener.send_to(pkt, peer_addr).await;
                                }
                            },
                            Err(e) => {
                                error!("{:?}", e);
                            },
                        }
                        debug!("QUERY DONE.\n\n");
                    },
                    Err(e) => {
                        error!("{:?}", e);
                    },
                }
            },
            Err(e) => error!("{:?}", e),
        }
    }
}


pub async fn run_tcp_server<A: ToSocketAddrs>(addr: A) -> Result<(), tokio::io::Error> {
    let mut listener = TcpListener::bind(addr).await?;
    
    debug!("DNS TCP service running at {:?} ...", listener.local_addr()?);

    loop {
        match listener.accept().await {
            Ok((mut tcp_stream, peer_addr)) => {

                tokio::spawn(async move {
                    let mut buf = [0u8; MAX_BUFF_SIZE];

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
                    debug!("{:?}", deserialize_req(data));
                    
                    Ok(())
                });

            },
            Err(e) => error!("{:?}", e),
        }
    }
}

