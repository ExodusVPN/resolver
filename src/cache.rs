use wire::record::Record;

use std::net::IpAddr;
use std::time::Instant;
use std::time::Duration;
use std::hash::Hash;
use std::hash::Hasher;
use std::hash::BuildHasher;
use std::collections::hash_map::HashMap;


const DEFAULT_DURATION: Duration = Duration::from_secs(24*60*60); // 24H

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
    inner: HashMap<u64, Ttl<wire::Response>>,
    nscache: HashMap<String, Vec<Ttl<IpAddr>>>,
}

impl Cache {
    pub fn new() -> Self {
        let inner = HashMap::new();
        let nscache = HashMap::new();

        Self { inner, nscache }
    }

    pub fn nslookup<N: AsRef<str>>(&self, name: N) -> Option<Vec<IpAddr>> {
        let name = name.as_ref();

        todo!()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    fn req_key_gen(&self, req: &wire::Request, name_server_ip: IpAddr) -> u64 {
        // NOTE: 客户端在请求的时候需要注意 CIDR 信息的范围。
        let ecs_ip_cidr = match req.client_subnet {
            Some(ref subnet) => Some((subnet.address, subnet.src_prefix_len)),
            None => None,
        };

        assert!(!req.questions.is_empty());

        let question = &req.questions[0];

        let mut hasher = self.inner.hasher().build_hasher();

        name_server_ip.hash(&mut hasher);
        &question.name.hash(&mut hasher);
        question.kind.hash(&mut hasher);
        question.class.hash(&mut hasher);
        ecs_ip_cidr.hash(&mut hasher);

        hasher.finish()
    }

    pub fn insert(&mut self, req: &wire::Request, name_server_ip: IpAddr, res: &wire::Response) {
        if req.questions.is_empty() {
            return ();
        }

        let req_key = self.req_key_gen(req, name_server_ip);

        if !self.inner.contains_key(&req_key) {
            // Update NS CACHE
            // for records in &[ &res.answers, &res.authorities, &res.additionals ] {
            //     for rr in records.iter() {
            //         match rr {
            //             wire::record::Record::A(v) => {
            //                 let addr = IpAddr::from(v.value);
            //                 self.nscache.insert(v.name.clone(), Ttl::new(addr, DEFAULT_DURATION));
            //             },
            //             wire::record::Record::AAAA(v) => {
            //                 let addr = IpAddr::from(v.value);
            //                 self.nscache.insert(v.name.clone(), Ttl::new(addr, DEFAULT_DURATION));
            //             },
            //             _ => { },
            //         }
            //     }
            // }

            self.inner.insert(req_key, Ttl::new(res.clone(), DEFAULT_DURATION));
        } else {
            // Update TTL.
            let res = self.inner.get_mut(&req_key).unwrap();
            res.ctime = Instant::now();
        }
    }

    pub fn get(&self, req: &wire::Request, name_server_ip: IpAddr) -> Option<&wire::Response> {
        if req.questions.is_empty() {
            return None;
        }

        let req_key = self.req_key_gen(req, name_server_ip);

        match self.inner.get(&req_key) {
            Some(item) => {
                if item.is_expired() {
                    None
                } else {
                    Some(&item.item)
                }
            },
            None => None,
        }
    }

    pub fn remove_expired(&mut self) {
        todo!()
    }
}

