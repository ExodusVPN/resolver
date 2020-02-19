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
pub struct Entry {
    pub instant: Instant,
    pub item: Record,
}

#[derive(Debug, Clone)]
pub struct RecordSet {
    key: u64,
    last_instant: Instant,
    inner: Vec<Entry>,
}

impl RecordSet {
    pub fn new(key: u64) -> Self {
        Self { key, last_instant: Instant::now(), inner: Vec::new() }
    }

    pub fn contains(&self, record: &Record) -> bool {
        self.inner.iter().any(|entry| &entry.item == record)
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn add(&mut self, record: Record) {
        if !self.contains(&record) {
            self.inner.push(Entry { instant: Instant::now(), item: record });
            self.last_instant = Instant::now();
        }
    }

    pub fn remove_expired(&mut self) {
        self.inner.sort_by_key(|entry| entry.item.ttl());

        let now = Instant::now();
        let mut idx = 0usize;

        loop {
            if idx >= self.inner.len() {
                break;
            }

            let entry = &self.inner[idx];
            let earlier = entry.instant;
            let duration = match now.checked_duration_since(earlier) {
                Some(v) => v,
                None => return (),
            };
            let ttl = Duration::from_secs(entry.item.ttl() as u64);

            if ttl <= duration {
                self.inner.remove(idx);
            } else {
                idx += 1;
            }
        }
    }
}

type IpCidr = (IpAddr, u8);

#[derive(Debug, Clone)]
pub struct Cache {
    inner: HashMap<u64, RecordSet>,
}

impl Cache {
    pub fn new() -> Self {
        let inner = HashMap::new();

        Self { inner }
    }

    pub fn hash_key(&mut self, name: &str, kind: wire::Kind, class: wire::Class, ecs_ip_cidr: Option<IpCidr>) -> u64 {
        let mut hasher = self.inner.hasher().build_hasher();

        name.hash(&mut hasher);
        kind.hash(&mut hasher);
        class.hash(&mut hasher);
        ecs_ip_cidr.hash(&mut hasher);

        hasher.finish()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn add(&mut self, record: Record, ecs_ip_cidr: Option<IpCidr>) {
        let ttl = record.ttl();

        if ttl == 0 {
            return ();
        }

        let key = self.hash_key(record.name(), record.kind(), record.class(), ecs_ip_cidr);

        if !self.inner.contains_key(&key) {
            let mut record_set = RecordSet::new(key);
            record_set.add(record);

            self.inner.insert(key, record_set);
        } else {
            let record_set = self.inner.get_mut(&key).unwrap();
            record_set.add(record);
        }
    }

    pub fn get(&self, key_hash: u64) -> Option<&RecordSet> {
        self.inner.get(&key_hash)
    }
    
    pub fn remove_expired(&mut self) {
        let now = Instant::now();

        let mut expired_keys = Vec::new();
        for (_domain_name, records) in self.inner.iter_mut() {
            records.remove_expired();

            if records.is_empty() {
                match now.checked_duration_since(records.last_instant) {
                    Some(duration) => {
                        if duration >= DEFAULT_DURATION {
                            expired_keys.push(records.key);
                        }
                    },
                    None => { },
                }
            }
        }

        for k in expired_keys.iter() {
            self.inner.remove(k);
        }
    }
}

