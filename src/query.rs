use crate::wire;
use crate::MAX_BUFF_SIZE;
use crate::protocol::Protocol;
use crate::name_server::NameServer;
use crate::name_server::ROOT_V4_SERVERS;
use crate::name_server::ROOT_V6_SERVERS;


use wire::serialize_req;
use wire::serialize_res;
use wire::deserialize_req;
use wire::deserialize_res;

use tokio::net::UdpSocket;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use std::sync::Arc;
use std::sync::RwLock;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;


pub async fn query2(req: &wire::Request, name_server: &NameServer) -> Result<wire::Response, wire::Error> {
    
    todo!()
}

pub async fn query(req: &wire::Request, name_server: &NameServer) -> Result<wire::Response, wire::Error> {
    let mut buf = [0u8; MAX_BUFF_SIZE];

    // if !self.is_tcp() && !self.is_udp() {
    //     return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "DNS Protocol not supported."))
    // }

    if req.questions.is_empty() {
        return Err(wire::Error::new(wire::ErrorKind::FormatError, "DNS Query must have questions."));
    }

    if req.questions.len() > 1 {
        warn!("Only the first question record will be sent to the query, the rest will be ignored");
    }

    // debug!("Sent DNS Query to {:?}://{} {:?} ...", &self.protocols, &self.socket_addr, self.domain_name);
    debug!("{:?}", req);

    let amt = serialize_req(req, &mut buf[2..])?;

    if amt > std::u16::MAX as usize {
        return Err(wire::Error::from(wire::ErrorKind::ServerFailure));
    }

    &mut buf[..2].copy_from_slice(&(amt as u16).to_be_bytes());

    let sa = name_server.socket_addr_by(Protocol::Tcp).unwrap();

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::net::TcpStream::connect(&sa)
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




#[derive(Debug, Clone)]
pub struct Query {
    // pub max_hop: usize,
    // pub use_ipv4: bool,
    // pub use_ipv6: bool,

    state: Arc<RwLock<ResolvOptions>>,
    cache: Option<Cache>,
    request: Arc<Request>,
    name_servers: Arc<Vec<NameServer>>,
}

pub fn iquery(query: Query) -> Pin<Box<dyn Future<Output = Result<Response, wire::Error> > + Send >> {
    Box::pin(async move {
        let name_servers = &query.name_servers;
        if name_servers.is_empty() {
            return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "could not find next name server."));
        }

        let idx = name_servers.len() - 1;
        let name_server = &name_servers[idx];

        let req = &query.request;

        if query.state.read().unwrap().attempts == 0 {
            return Err(wire::Error::new(wire::ErrorKind::ServerFailure, "recursion limit."));
        }
        
        if let Some(ref cache) = query.cache {
            if let Some(res) = cache.get(&req, name_server) {
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
                cache.insert(&req, name_server, &res);
            }
        }

        Ok(res)
    })
}


pub fn rquery(query: Query) -> Pin<Box<dyn Future<Output = Result<Response, wire::Error> > + Send >> {
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

pub fn rquery2(query: Query) -> Pin<Box<dyn Future<Output = Result<Response, wire::Error> > + Send >> {
    Box::pin(async move {
        let query = query;
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

            let (use_ipv4, use_ipv6) = {
                let state = query.state.read().unwrap();
                (state.use_ipv4, state.use_ipv6)
            };

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

                'LOOP3: for ns_name_server in ns_name_servers.iter() {
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