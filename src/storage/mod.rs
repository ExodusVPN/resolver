use crate::wire;

use std::time;
use std::collections::HashMap;
use std::collections::HashSet;
use core::hash::Hash;
use core::borrow::Borrow;


#[derive(Debug, Clone)]
pub struct Entry {
    instant: time::Instant,
    strong: usize,
    record: wire::Record,
}

impl PartialEq for Entry {
    fn eq(&self, other: &Self) -> bool {
        self.record.name == other.record.name
        && self.record.kind == other.record.kind
        && self.record.class == other.record.class
        && self.record.value == other.record.value
    }
}

impl Eq for Entry { }


const MAX_NAMES: usize   = 1024;
const MAX_RECORDS: usize = 1024 * 8;
const MAX_DURATION: time::Duration = time::Duration::from_secs(4*60*60); // 1 Hour


#[derive(Debug)]
pub struct Cache {
    inner: HashMap<String, Vec<Entry>>,
    size: usize,
    last_gc_time: time::Instant,
}

impl Cache {
    #[inline]
    pub fn new() -> Self {
        Self::with_capacity(MAX_NAMES)
    }

    #[inline]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: HashMap::with_capacity(capacity),
            size: 0usize,
            last_gc_time: time::Instant::now(),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.size
    }

    #[inline]
    pub fn names_len(&self) -> usize {
        self.inner.len()
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.inner.capacity()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[inline]
    pub fn contains_key<K: Borrow<str>>(&mut self, k: K) -> bool {
        self.inner.contains_key(k.borrow())
    }

    #[inline]
    pub fn get_mut<K: Borrow<str>>(&mut self, k: K) -> Option<Entries<'_>> {
        self.get_mut_by(k, None, None)
    }

    #[inline]
    pub fn get_mut_by<K: Borrow<str>>(&mut self, k: K,
                                      kind: Option<wire::Kind>,
                                      class: Option<wire::Class>) -> Option<Entries<'_>> {
        let mut val = self.inner.get_mut(k.borrow())?;
        Some(Entries {
            inner: val.iter_mut(),
            kind: kind,
            class: class,
        })
    }

    #[inline]
    pub fn get_mut_by_kind<K: Borrow<str>>(&mut self, k: K, kind: wire::Kind) -> Option<Entries<'_>> {
        self.get_mut_by(k, Some(kind), None)
    }

    #[inline]
    pub fn get_mut_by_class<K: Borrow<str>>(&mut self, k: K, class: wire::Class) -> Option<Entries<'_>> {
        self.get_mut_by(k, None, Some(class))
    }

    pub fn insert(&mut self, v: wire::Record) {
        if self.names_len() > MAX_NAMES {
            self.gc_names();
        }

        if self.len() > MAX_RECORDS {
            self.gc();
        }

        if self.last_gc_time.elapsed() > MAX_DURATION {
            self.gc();
        }

        let now = time::Instant::now();
        let now = now.checked_sub(time::Duration::from_secs(v.ttl as u64)).unwrap_or(now);
        
        let k = v.name.clone();
        let mut entry = Entry {
            instant: now,
            strong: 0,
            record: v,
        };

        let entries = self.inner.get_mut(&k);
        if let Some(entries) = entries {
            for x in entries.iter_mut() {
                if x == &mut entry {
                    x.instant = entry.instant;
                    x.strong = entry.strong;
                    return ();
                }
            }

            entries.push(entry);
        } else {
            self.inner.insert(k, vec![entry]);
        }

        self.size += 1;
    }

    pub fn remove(&mut self, v: &wire::Record) {
        match self.inner.get_mut(&v.name) {
            Some(entries) => {
                let mut idx = 0usize;
                let mut index = None;
                for x in entries.iter_mut() {
                    if v.name == x.record.name
                        && v.kind == x.record.kind
                        && v.class == x.record.class
                        && v.value == x.record.value {

                        index = Some(idx);
                        break;
                    }

                    idx += 1;
                }

                if let Some(idx) = index {
                    self.size -= 1;
                    entries.remove(idx);
                }
            },
            None => {

            },
        }
    }

    #[inline]
    pub fn clear(&mut self) {
        self.inner.clear()
    }

    pub fn gc(&mut self) {
        for entries in self.inner.values_mut() {
            let mut idx = 0usize;
            loop {
                if idx >= entries.len() {
                    break;
                }

                let entry = &entries[idx];
                let elapsed = entry.instant.elapsed();
                if elapsed > MAX_DURATION {
                    entries.remove(idx);
                    self.size -= 1;
                    idx = 0;
                    continue;
                }

                idx += 1;
            }
        }

        if self.len() < MAX_RECORDS {
            return ();
        }

        let mut items: HashSet<(usize, time::Instant)> = HashSet::new();
        for entries in self.inner.values_mut() {
            for entry in entries.iter_mut() {
                items.insert((entry.strong, entry.instant));
            }
        }
        
        let mut items = items.into_iter().collect::<Vec<(usize, time::Instant)>>();
        items.sort();
        // items.reverse();
        
        let len = std::cmp::min(items.len(), MAX_RECORDS / 2);
        let items = &items[..len];

        for entries in self.inner.values_mut() {
            let mut idx = 0usize;
            loop {
                if idx >= entries.len() {
                    break;
                }

                let entry = &entries[idx];
                let item = (entry.strong, entry.instant);
                if items.contains(&item) {
                    entries.remove(idx);
                    self.size -= 1;
                    idx = 0;
                    continue;
                }

                idx += 1;
            }
        }
    }

    fn gc_names(&mut self) {
        let mut names: Vec<(usize, String)> = Vec::new();
        for key in self.inner.keys() {
            let val = self.inner.get(key).unwrap();
            let strong = val.iter().map(|entry| entry.strong).sum::<usize>();
            names.push((strong, key.to_string()));
        }
        names.sort_by_key(|&(strong, _)| strong);
        names.reverse();

        let len = std::cmp::min(names.len(), MAX_NAMES / 2);
        for (_, name) in &names[len..] {
            let val = self.inner.get(name).unwrap();
            self.size -= val.len();
            self.inner.remove(name);
        }
    }
}


pub struct Entries<'a> {
    inner: std::slice::IterMut<'a, Entry>,
    kind: Option<wire::Kind>,
    class: Option<wire::Class>,
}

impl<'a> Iterator for Entries<'a> {
    type Item = &'a mut wire::Record;

    fn next(&mut self) -> Option<Self::Item> {
        let mut item = self.inner.next()?;
        if let Some(kind) = self.kind {
            if kind != item.record.kind {
                return self.next();
            }
        }

        if let Some(class) = self.class {
            if class != item.record.class {
                return self.next();
            }
        }

        item.strong += 1;

        const MAX_TTL: u64 = std::u32::MAX as u64;

        let elapsed = item.instant.elapsed();
        if elapsed > MAX_DURATION {
            return self.next();
        }

        let mut ttl = elapsed.as_secs();
        if ttl > MAX_TTL {
            ttl = MAX_TTL;
        }
        
        item.record.ttl = ttl as u32;

        Some(&mut item.record)
    }
}


#[test]
fn test_cache() {
    let mut cache = Cache::new();
    cache.insert(wire::Record {
        name: "www.example.com".to_string(),
        kind: wire::Kind::A,
        class: wire::Class::IN,
        ttl: 0,
        value: wire::Value::A(std::net::Ipv4Addr::new(192, 168, 1, 1)),
    });

    assert_eq!(cache.len(), 1);
    assert_eq!(cache.names_len(), 1);

    let entries = cache.get_mut("www.example.com");
    assert!(entries.is_some());

    let records = entries.unwrap().map(|record| record.clone()).collect::<Vec<wire::Record>>();
    assert_eq!(records.len(), 1);

    cache.remove(&records[0]);
    
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.names_len(), 1);

    let records = cache.get_mut("www.example.com")
        .map(|entries| {
            entries.map(|record| record.clone()).collect::<Vec<wire::Record>>()
        });
    assert!(records.is_some());
    
    let records = records.unwrap();
    assert_eq!(records.len(), 0);
}

