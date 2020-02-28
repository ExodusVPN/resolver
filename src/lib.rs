#![allow(unused_imports, unused_labels, unused_variables, dead_code)]

#[macro_use]
extern crate log;
extern crate rand;
pub extern crate wire;

pub mod cache;

// pub mod tcp;
// pub mod udp;
// pub mod tls;

use tokio::net::UdpSocket;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::ToSocketAddrs;


use wire::Kind;
use wire::Class;
use wire::Request;
use wire::Response;
use wire::ResponseCode;
use wire::Protocols;
use wire::record::Record;
use wire::serialize_req;
use wire::serialize_res;
use wire::deserialize_req;
use wire::deserialize_res;

use self::cache::Cache;


use std::io;
use std::env;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::time::Instant;
use std::time::Duration;
use std::sync::Arc;
use std::sync::RwLock;
use std::pin::Pin;
use std::future::Future;


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

    pub async fn query(&self, req: &Request) -> Result<Response, wire::Error> {
        let mut buf = [0u8; MAX_BUFF_SIZE];

        if !self.is_tcp() && !self.is_udp() {
            return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "DNS Protocol not supported."))
        }

        if req.questions.is_empty() {
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


pub async fn is_support_ipv4() -> bool {
    // example.com
    // 93.184.216.34
    // 2606:2800:220:1:248:1893:25c8:1946
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect("93.184.216.34:80")
    )
    .await;
    match stream {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            // macOS ERROR_CODE:  65,  MSG: No route to host
            // Linux ERROR_CODE: 101,  MSG: Network is unreachable
            false
        },
        // Timeout
        Err(_) => true,
    }
}

pub async fn is_support_ipv6() -> bool {
    // example.com
    // 93.184.216.34
    // 2606:2800:220:1:248:1893:25c8:1946
    let stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::TcpStream::connect("2606:2800:220:1:248:1893:25c8:1946:80")
    )
    .await;
    match stream {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            // macOS ERROR_CODE:  65,  MSG: No route to host
            // Linux ERROR_CODE: 101,  MSG: Network is unreachable
            false
        },
        // Timeout
        Err(_) => true,
    }
}

pub async fn root_name_servers() -> Vec<NameServer> {
    let mut servers = Vec::new();

    for (name, ip_addr) in ROOT_V4_SERVERS.iter().chain(ROOT_V6_SERVERS.iter()) {
        let now = Instant::now();
        let socket_addr = SocketAddr::new(*ip_addr, 53);
        let stream = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            tokio::net::TcpStream::connect(socket_addr)
        )
        .await;
        if let Ok(Ok(stream)) = stream {
            let duration = now.elapsed();
            let domain_name = Some(name.to_string());
            let name_server = NameServer::new(domain_name, socket_addr, Protocols::default()).unwrap();
            servers.push((duration, name_server));
        }
    }

    servers.sort_by_key(|item| item.0);
    servers.reverse();

    servers.into_iter()
        .map(|item| item.1).collect::<Vec<NameServer>>()
}


#[derive(Debug, Clone)]
pub struct Resolver {
    inner: Arc<ResolverInner>,
}

#[derive(Debug, Clone)]
struct ResolverInner {
    config: ResolvOptions,
    cache: Cache,
    name_servers: Vec<NameServer>,
}

impl Resolver {
    pub fn new() -> Self {
        todo!()
    }

    pub fn query(&self, req: Arc<Request>) -> Query {
        todo!()
    }

    pub fn resolv(&self, req: &Request) -> Result<(), ()> {
        todo!()
    }
}

pub async fn query(req: &Request, cache: &mut Cache, name_server: Option<&NameServer>) -> Result<Response, wire::Error> {
    // rquery(req, cache, name_server).await
    todo!()
}

pub fn iquery(query: Query) -> Pin<Box<dyn Future<Output = Result<Response, wire::Error> >>> {
    Box::pin(async move {
        let name_servers = &query.name_servers;
        if name_servers.is_empty() {
            return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "could not find next name server."));
        }

        let idx = name_servers.len() - 1;
        let name_server = &name_servers[idx];

        let name_server_ip = name_server.ip();
        let req = &query.request;

        if query.state.read().unwrap().attempts == 0 {
            return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "recursion limit."));
        }
        
        if let Some(ref cache) = query.cache {
            if let Some(res) = cache.get(&req, name_server_ip) {
                let mut state = query.state.write().unwrap();
                state.attempts -= 1;

                return Ok(res);
            }
        }

        let res = name_server.query(&req).await?;

        let mut state = query.state.write().unwrap();
        state.attempts -= 1;

        let mut cacheable = false;

        if let Some(mut cache) = query.cache {
            if res.rcode == wire::ResponseCode::OK {
                // Update DNS Cache
                if res.answers.is_empty() {
                    let mut has_ns_rr = false;
                    let mut has_soa_rr = false;
                    for rr in res.authorities.iter() {
                        match rr {
                            Record::NS(_) => {
                                has_ns_rr = true;
                            },
                            Record::SOA(_) => {
                                has_soa_rr = true;
                            },
                            _ => { },
                        }
                    }

                    if has_ns_rr && !has_soa_rr {
                        cacheable = true;
                    }
                } else {
                    cacheable = true;
                }
            }
            
            if cacheable {
                cache.insert(&req, name_server_ip, &res);
            }
        }

        Ok(res)
    })
}


#[derive(Debug, Clone)]
pub struct ResolvOptions {
    /// Timeout to wait for a response.
    pub timeout: Duration,
    /// Number of retries before giving up.
    pub attempts: usize,
    pub use_ipv4: bool,
    pub use_ipv6: bool,
}

#[derive(Debug, Clone)]
pub struct Query {
    state: Arc<RwLock<ResolvOptions>>,
    cache: Option<Cache>,
    request: Arc<Request>,
    name_servers: Arc<Vec<NameServer>>,
}

pub fn rquery(query: Query) -> Pin<Box<dyn Future<Output = Result<Response, wire::Error> >>> {
    Box::pin(async move {
        let req = &query.request;

        if req.questions.is_empty() {
            trace!("DNS Query must have questions.");
            return Err(wire::Error::from(wire::ErrorKind::FormatError));
        }

        let mut res = rquery2(query.clone()).await?;
        let mut cnames = Vec::new();
        
        'LOOP1: loop {
            if !res.answers.is_empty() {
                for rr in res.answers.iter().rev() {
                    match rr {
                        Record::CNAME(ref cname) => {
                            let mut req: Request = (*query.request).clone();

                            let question = &mut req.questions[0];
                            question.name = cname.value.clone();

                            let cname_rr_clone = rr.clone();

                            // NOTE: CNAME 跳转查询不允许失败！
                            let mut query = query.clone();
                            query.request = Arc::new(req);

                            res = rquery2(query).await?;
                            cnames.push(cname_rr_clone);
                            continue 'LOOP1;
                        },
                        _ => { },
                    }
                }
            }

            break;
        }

        cnames.reverse();

        for cname in cnames {
            res.answers.insert(0, cname);
        }

        Ok(res)
    })
}

pub fn rquery2(query: Query) -> Pin<Box<dyn Future<Output = Result<Response, wire::Error> >>> {
    Box::pin(async move {
        let mut res = iquery(query.clone()).await?;

        'LOOP1: loop {
            if res.rcode != ResponseCode::OK {
                return Ok(res);
            }

            if !res.answers.is_empty() {
                return Ok(res);
            }

            let name_servers = get_name_servers(&res);
            if name_servers.is_none() {
                return Ok(res);
            }

            let mut name_servers = name_servers.unwrap();
            let mut ns_names = Vec::new();

            let state = query.state.read().unwrap();
            let use_ipv4 = state.use_ipv4;
            let use_ipv6 = state.use_ipv6;
            drop(state);

            'LOOP2: for (ns_name, ns_name_servers) in name_servers.iter_mut() {
                if ns_name_servers.is_empty() {
                    warn!("NSLOOKUP: {:?}", ns_name);
                    ns_names.push(ns_name.to_string());

                    let kind = if use_ipv6 { wire::Kind::AAAA } else { wire::Kind::A };
                    let req = Request {
                        id: rand::random(),
                        flags: wire::ReprFlags::default(),
                        opcode: wire::OpCode::QUERY,
                        client_subnet: None,
                        questions: vec![
                            wire::Question {
                                name: ns_name.clone(),
                                kind: kind,
                                class: wire::Class::IN,
                            }
                        ],
                    };

                    let mut query = query.clone();
                    query.request = Arc::new(req);

                    match rquery(query).await {
                        Ok(ns_res) => {
                            for rr in ns_res.answers.iter() {
                                match rr {
                                    Record::A(ref a) => {
                                        let ns_addr = SocketAddr::from((a.value, 53u16));
                                        let name_server = NameServer::new(Some(ns_name.to_string()), ns_addr, Protocols::default())
                                            // .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;
                                            .unwrap();
                                        debug!("NS ADDR: {:?}", name_server);
                                        ns_name_servers.push(name_server);
                                    },
                                    Record::AAAA(ref aaaa) => {
                                        let ns_addr = SocketAddr::from((aaaa.value, 53u16));
                                        let name_server = NameServer::new(Some(ns_name.to_string()), ns_addr, Protocols::default())
                                            // .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;
                                            .unwrap();
                                        debug!("NS ADDR: {:?}", name_server);
                                        ns_name_servers.push(name_server);
                                    },
                                    _ => { },
                                }
                            }
                        },
                        Err(e) => {
                            error!("{:?}", e);
                        },
                    }
                }

                'LOOP3: for ns_name_server in ns_name_servers {
                    if ns_name_server.is_ipv4() {
                        if !use_ipv4 {
                            continue;
                        }
                    }
                    if ns_name_server.is_ipv6() {
                        if !use_ipv6 {
                            continue;
                        }
                    }

                    let mut query = query.clone();
                    query.name_servers = Arc::new(vec![ns_name_server.clone()]);

                    match iquery(query).await {
                        Ok(res_) => {
                            res = res_;
                            continue 'LOOP1;
                        },
                        Err(e) => {
                            error!("{:?}", e);
                        }
                    }
                }
            }

            return Ok(res);
        }
    })
}

fn get_name_servers(res: &Response) -> Option<Vec<(String, Vec<NameServer>)>> {
    if !res.answers.is_empty() {
        return None;
    }

    if res.authorities.is_empty() {
        warn!("Authority Section is empty.");
        return None;
    }

    let mut name_servers1 = Vec::new();
    let mut name_servers2 = Vec::new();
    for rr in res.authorities.iter().rev() {
        match rr {
            Record::NS(ref ns) => {
                let mut ns_name_servers = Vec::new();

                for rr in res.additionals.iter().rev() {
                    match rr {
                        Record::A(ref a) => {
                            let ns_addr = SocketAddr::from((a.value, 53u16));
                            let name_server = NameServer::new(Some(ns.value.clone()), ns_addr, Protocols::default())
                                // .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;
                                .unwrap();
                            ns_name_servers.push(name_server);
                        },
                        Record::AAAA(ref aaaa) => {
                            let ns_addr = SocketAddr::from((aaaa.value, 53u16));
                            let name_server = NameServer::new(Some(ns.value.clone()), ns_addr, Protocols::default())
                                // .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;
                                .unwrap();
                            ns_name_servers.push(name_server);
                        },
                        _ => { },
                    }
                }

                if ns_name_servers.is_empty() {
                    for root_servers in [ &ROOT_V4_SERVERS, &ROOT_V6_SERVERS ].iter() {
                        for  (root_name, root_addr) in root_servers.iter() {
                            if root_name != &ns.value.as_str() {
                                continue;
                            }

                            let ns_addr = SocketAddr::new(*root_addr, 53u16);
                            let name_server = NameServer::new(Some(ns.value.clone()), ns_addr, Protocols::default())
                                // .map_err(|e| wire::Error::new(wire::ErrorKind::ServerFailure, e))?;
                                .unwrap();
                            ns_name_servers.push(name_server);
                        }
                    }
                }

                if !ns_name_servers.is_empty() {
                    name_servers1.push((ns.value.clone(), ns_name_servers));
                } else {
                    name_servers2.push((ns.value.clone(), ns_name_servers));
                }
            },
            _ => { },
        }
    }

    name_servers1.extend(name_servers2);
    let name_servers = name_servers1;

    if name_servers.is_empty() {
        warn!("Authority Section has no NS records.");
        return None;
    } else {
        return Some(name_servers);
    }
}


pub async fn run_udp_server<A: ToSocketAddrs>(addr: A) -> Result<(), tokio::io::Error> {
    let mut buf = [0u8; MAX_BUFF_SIZE];
    let mut listener = UdpSocket::bind(addr).await?;

    let cache = Cache::new();
    let root_name_servers = Arc::new(root_name_servers().await);
    let use_ipv4 = is_support_ipv4().await;
    let use_ipv6 = is_support_ipv6().await;

    debug!("DNS service running at udp://{} ...", listener.local_addr()?);

    loop {
        match listener.recv_from(&mut buf).await {
            Ok((0, _)) => continue,
            Ok((amt, peer_addr)) => {
                let pkt = &buf[..amt];

                trace!("[UDP] received {:?} bytes from {:?}", pkt.len(), peer_addr);

                match deserialize_req(pkt) {
                    Ok(req) => {
                        let req_id = req.id;
                        let raw_questions = req.questions.clone();
                        let query = Query {
                            state: Arc::new(RwLock::new(ResolvOptions {
                                timeout: Duration::from_secs(30),
                                attempts: 32,
                                use_ipv4: use_ipv4,
                                use_ipv6: use_ipv6,
                            })),
                            cache: Some(cache.clone()),
                            request: Arc::new(req),
                            name_servers: root_name_servers.clone(),
                        };
                        match rquery(query).await {
                            Ok(mut res) => {
                                debug!("{:?}", &res);

                                if res.answers.len() > 0 {
                                    info!("Answers Section:");
                                    for rr in res.answers.iter() {
                                        info!("{:?}", rr);
                                    }
                                } else {

                                }

                                res.questions = raw_questions;
                                res.id = req_id;
                                // res.authorities.clear();
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

