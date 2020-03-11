use crate::config::Config;
use crate::config::ResolvOptions;
use crate::config::sort_root_name_servers;
use crate::cache::Cache;
use crate::name_server::NameServer;
use crate::protocol::Protocol;


use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::pin::Pin;
use std::future::Future;
use std::sync::Arc;
use std::sync::RwLock;


// https://tools.ietf.org/html/rfc952
#[cfg(any(target_os = "macos",
          target_os = "linux",
          target_os = "freebsd",
          target_os = "netbsd"))]
const DEFAULT_HOSTS_FILE_PATH: &str = "/etc/hosts";
#[cfg(windows)]
const DEFAULT_HOSTS_FILE_PATH: &str = "C:\\Windows\\System32\\Drivers\\etc\\hosts";


// http://man7.org/linux/man-pages/man5/resolv.conf.5.html
#[cfg(any(target_os = "macos",
          target_os = "linux",
          target_os = "freebsd",
          target_os = "netbsd"))]
const RESOLVER_CONFIG_FILE_PATH: &str = "/etc/resolv.conf";


static GLOBAL_MESSAGE_ID: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);

fn id() -> u16 {
    let prev_id = GLOBAL_MESSAGE_ID.load(std::sync::atomic::Ordering::SeqCst);
    let curr_id = prev_id.checked_add(1).unwrap_or(0);

    GLOBAL_MESSAGE_ID.store(curr_id, std::sync::atomic::Ordering::SeqCst);

    curr_id
}


#[derive(Debug, Clone)]
pub enum ResolverKind {
    // ZoneServer
    AuthoritativeServer,
    ProxyServer,
    RecursiveServer,

    Named,
    Proxy,
    Resolver,
}


#[derive(Debug)]
pub struct SystemHostsResolver {

}

#[derive(Debug, Clone)]
pub struct LocalMulticastResolver {
    pub options: ResolvOptions,
    pub cache: Cache,
}

#[derive(Debug, Clone)]
pub struct ProxyResolver {
    pub options: ResolvOptions,
    pub cache: Cache,
    pub upstream: Vec<NameServer>,
}

#[derive(Debug)]
pub struct RecursiveResolver {
    pub options: ResolvOptions,
    pub cache: Cache,
    pub root_name_servers: Vec<NameServer>,
}

#[derive(Debug)]
pub struct StubResolver {
    pub options: ResolvOptions,
    pub cache: Cache,
    // Note: 解析查询按顺序来:
    //      SystemHostsFile --> mDNS --> ProxyResolver --> RecursiveResolver
    pub system_hosts_resolver: Option<SystemHostsResolver>,
    pub local_multicast_resolver: Option<LocalMulticastResolver>,
    pub system_resolver: Option<ProxyResolver>,         // 系统 /etc/resolv.conf 文件里面设置的上游解析器。
    pub proxy_resolver: Option<ProxyResolver>,          // 用户自定义的上游解析器
    pub recursive_resolver: Option<RecursiveResolver>,  // 从 ROOT-SERVER 开始层层迭代的解析器
}

impl StubResolver {
    pub async fn new(config: Config) -> Result<Self, io::Error> {
        let cache = Cache::new();
        let root_name_servers = sort_root_name_servers().await;

        Ok(Self {
            options: config.resolv_options,
            cache: cache.clone(),
            system_hosts_resolver: None,
            local_multicast_resolver: None,
            system_resolver: None,
            proxy_resolver: None,
            recursive_resolver: Some(RecursiveResolver {
                options: config.resolv_options,
                cache: cache.clone(),
                root_name_servers,
            })
        })
    }

    pub fn query(&self, req: wire::Request) -> Pin<Box<dyn Future<Output = Result<wire::Response, wire::Error> > + Send >> {
        todo!()
    }

    pub fn resolve<B: AsRef<[u8]>>(&self, pkt: B) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, wire::Error> > + Send >> {
        todo!()
    }
}


#[derive(Debug, Clone)]
pub struct Query {
    state: Arc<RwLock<ResolvOptions>>,
    cache: Option<Cache>,
    request: Arc<wire::Request>,
    name_servers: Arc<Vec<NameServer>>,
}

unsafe impl Send for Query { }


pub enum ResolvError {
    Illegal,
    Unrecognized,
}

// pub async fn handle_req(buf: &mut [u8], amt: usize) -> Result<usize, ()> {
//     if amt < 12 {
//         return Err(());
//     }

//     let pkt = &buf[..amt];
//     match deserialize_req(pkt) {
//         Err(_) => {
//             let mut flags = wire::HeaderFlags::new_unchecked(u16::from_be_bytes([ buf[3], buf[4] ]));
//             flags.set_qr(true);
//             flags.set_rcode(wire::ResponseCode::FORMAT_ERROR);

//             let flags_bytes = flags.bits().to_be_bytes();
//             buf[3] = flags_bytes[0];
//             buf[4] = flags_bytes[1];

//             return Ok(amt);
//         },
//         Ok(req) => {
//             todo!()
//         },
//     }
// }

// pub async fn run_udp_server<A: ToSocketAddrs>(addr: A) -> Result<(), tokio::io::Error> {
//     let mut buf = [0u8; MAX_BUFF_SIZE];
//     let mut listener = UdpSocket::bind(addr).await?;

//     let cache = Cache::new();
//     let root_name_servers = Arc::new(root_name_servers().await);
//     let use_ipv4 = is_support_ipv4().await;
//     let use_ipv6 = is_support_ipv6().await;

//     info!("DNS service running at udp://{} ...", listener.local_addr()?);

//     loop {
//         match listener.recv_from(&mut buf).await {
//             Ok((0, _)) => continue,
//             Ok((amt, peer_addr)) => {
//                 let pkt = &buf[..amt];

//                 trace!("[UDP] received {:?} bytes from {:?}", pkt.len(), peer_addr);

//                 match deserialize_req(pkt) {
//                     Ok(req) => {
//                         let req_id = req.id;
//                         let raw_questions = req.questions.clone();
//                         let query = Query {
//                             state: Arc::new(RwLock::new(ResolvOptions {
//                                 timeout: Duration::from_secs(30),
//                                 attempts: 32,
//                                 use_ipv4: use_ipv4,
//                                 use_ipv6: use_ipv6,
//                             })),
//                             cache: Some(cache.clone()),
//                             request: Arc::new(req),
//                             name_servers: root_name_servers.clone(),
//                         };
//                         match rquery(query).await {
//                             Ok(mut res) => {
//                                 debug!("{:?}", &res);

//                                 if res.answers.len() > 0 {
//                                     info!("Answers Section:");
//                                     for rr in res.answers.iter() {
//                                         info!("{:?}", rr);
//                                     }
//                                 } else {

//                                 }

//                                 res.questions = raw_questions;
//                                 res.id = req_id;
//                                 // res.authorities.clear();
//                                 // res.additionals.clear();
//                                 res.flags |= wire::ReprFlags::RA;
//                                 if let Ok(amt) = serialize_res(&res, &mut buf) {
//                                     let pkt = &buf[..amt];
//                                     let _ = listener.send_to(pkt, peer_addr).await;
//                                 }
//                             },
//                             Err(e) => {
//                                 error!("{:?}", e);
//                             },
//                         }
                        
//                         debug!("QUERY DONE.\n\n");
//                     },
//                     Err(e) => {
//                         error!("{:?}", e);
//                     },
//                 }
//             },
//             Err(e) => error!("{:?}", e),
//         }
//     }
// }

pub struct Service {
    pub stub: StubResolver,
    pub udp_socket: Option<tokio::net::UdpSocket>,
    pub tcp_listener: Option<tokio::net::TcpListener>,
    pub tls_listener: Option<crate::net::tls::TlsListener>,
    pub h2_listener: Option<crate::net::h2::server::H2Listener>,
}

impl Service {
    pub async fn new(config: Config) -> Result<Self, io::Error> {
        let udp_socket = match config.bind.socket_addr_by(Protocol::Udp) {
            Some(sa) => Some(tokio::net::UdpSocket::bind(sa).await?),
            None => None,
        };
        let tcp_listener = match config.bind.socket_addr_by(Protocol::Tcp) {
            Some(sa) => Some(tokio::net::TcpListener::bind(sa).await?),
            None => None,
        };
        // let tls_listener = match config.bind.socket_addr_by(Protocol::Tls) {
        //     Some(sa) => Some(crate::net::tls::TlsListener::bind(sa).await?),
        //     None => None,
        // };
        let tls_listener = None;
        let h2_listener = None;

        let stub = StubResolver::new(config).await?;


        Ok(Self {
            stub,
            udp_socket,
            tcp_listener,
            tls_listener,
            h2_listener,
        })
    }

    pub async fn resolve<B: AsRef<[u8]>>(&self, pkt: B) -> Result<Vec<u8>, wire::Error> {
        todo!()
    }
    
    pub fn run_forever(&self) -> Result<(), io::Error> {
        todo!()
    }
}

