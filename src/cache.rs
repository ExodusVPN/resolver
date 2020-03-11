use crate::name_server::NameServer;

use wire::record::Record;


use std::net::IpAddr;
use std::time::Instant;
use std::time::Duration;
use std::hash::Hash;
use std::hash::Hasher;
use std::hash::BuildHasher;
use std::collections::hash_map::HashMap;

use std::sync::Arc;
use std::sync::RwLock;


const DEFAULT_DURATION: Duration = Duration::from_secs(60*60); // 1H

#[derive(Debug, Clone)]
pub struct Ttl<T> {
    pub ctime: Instant,
    pub ttl: Duration,
    pub item: T,
}

impl<T> Ttl<T> {
    pub fn new(item: T, ttl: Duration) -> Self {
        let ctime = Instant::now();

        Ttl { ctime, ttl, item }
    }

    pub fn is_expired(&self) -> bool {
        let now = Instant::now();
        
        if let Some(duration) = now.checked_duration_since(self.ctime) {
            if self.ttl <= duration {
                return true
            }
        }
        
        false
    }
}


#[derive(Debug, Clone)]
pub struct Cache {
    inner: Arc<RwLock<CacheInner>>,
}

unsafe impl Send for Cache { }


impl Cache {
    pub fn new() -> Self {
        let inner = Arc::new(RwLock::new(CacheInner::new()));
        Self { inner }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().unwrap().is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().len()
    }

    pub fn insert(&mut self, req: &wire::Request, name_server: &NameServer, res: &wire::Response) {
        let mut cache = self.inner.write().unwrap();
        cache.insert(req, name_server, res);
    }

    pub fn get(&self, req: &wire::Request, name_server: &NameServer) -> Option<wire::Response> {
        let inner = self.inner.read().unwrap();
        let (item, expired) = inner.get(req, name_server)?;

        if !expired {
            return Some(item.clone());
        }

        self.inner.write().unwrap().remove(req, name_server);

        return None
    }

    pub fn remove_expired(&self) {
        self.inner.write().unwrap().remove_expired()
    }
}


#[derive(Debug, Clone)]
pub struct CacheInner {
    inner: HashMap<u64, Ttl<wire::Response>>,
}

impl CacheInner {
    pub fn new() -> Self {
        let inner = HashMap::new();

        Self { inner }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    fn req_key_gen(&self, req: &wire::Request, name_server: &NameServer) -> u64 {
        // NOTE: 客户端在请求的时候需要注意 CIDR 信息的范围。
        let ecs_ip_cidr = match req.client_subnet {
            Some(ref subnet) => Some((subnet.address, subnet.src_prefix_len)),
            None => None,
        };

        assert!(!req.questions.is_empty());

        let question = &req.questions[0];

        let mut hasher = self.inner.hasher().build_hasher();

        match name_server.domain() {
            Some(name) => name.hash(&mut hasher),
            None => name_server.ip().hash(&mut hasher),
        }
        (&question.name).hash(&mut hasher);
        question.kind.hash(&mut hasher);
        question.class.hash(&mut hasher);
        ecs_ip_cidr.hash(&mut hasher);

        hasher.finish()
    }

    pub fn insert(&mut self, req: &wire::Request, name_server: &NameServer, res: &wire::Response) {
        if req.questions.is_empty() {
            return ();
        }

        let req_key = self.req_key_gen(req, name_server);

        if !self.inner.contains_key(&req_key) {
            let mut ttl = DEFAULT_DURATION;
            for records in &[ &res.answers, &res.authorities, &res.additionals ] {
                for rr in records.iter() {
                    match rr {
                        Record::A(_)
                        | Record::AAAA(_)
                        | Record::NS(_)
                        | Record::CNAME(_)
                        | Record::DNAME(_)
                        | Record::TXT(_)
                        | Record::MX(_)
                        | Record::DNSKEY(_)
                        | Record::RRSIG(_)
                        | Record::NSEC(_)
                        | Record::NSEC3(_)
                        | Record::NSEC3PARAM(_)
                        | Record::DS(_)
                        | Record::CAA(_) => {
                            ttl = std::cmp::min(Duration::from_secs(rr.ttl() as u64), ttl);
                        }
                        _ => {
                            // ignore TTL.
                        }
                    }
                }
            }

            self.inner.insert(req_key, Ttl::new(res.clone(), ttl));
        } else {
            // Update TTL.
            let res = self.inner.get_mut(&req_key).unwrap();
            res.ctime = Instant::now();
        }
    }
    
    pub fn get(&self, req: &wire::Request, name_server: &NameServer) -> Option<(&wire::Response, bool)> {
        if req.questions.is_empty() {
            return None;
        }
        
        let req_key = self.req_key_gen(req, name_server);
        let item = self.inner.get(&req_key)?;
        
        Some((&item.item, item.is_expired()))
    }
    
    pub fn remove(&mut self, req: &wire::Request, name_server: &NameServer) {
        let req_key = self.req_key_gen(req, name_server);
        self.inner.remove(&req_key);
    }
    
    pub fn remove_expired(&mut self) {
        let mut keys: Vec<u64> = vec![];

        for (key, item) in self.inner.iter() {
            if item.is_expired() {
                keys.push(*key);
            }
        }

        for key in keys {
            self.inner.remove(&key);
        }
    }
}

