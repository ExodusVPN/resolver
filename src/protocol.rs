
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Protocol {
    Udp = 1u8,
    Tcp,
    Tls,         // DoT
    Https,       // DoH
    DNSCryptUdp,
    DNSCryptTcp,
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct ProtocolSet {
    sets: u32,
    len: usize,
}

impl ProtocolSet {
    pub fn new<S: AsRef<[Protocol]>>(protocols: S) -> Result<Self, &'static str> {
        let protocols = protocols.as_ref();
        if protocols.is_empty() {
            return Err("protocols is empty");
        }

        if protocols.len() > 8 {
            return Err("too many protocols")
        }

        let mut sets = 0u32;
        let mut idx = 0usize;
        let mut len = 0usize;

        loop {
            if idx >= protocols.len() {
                break;
            }

            let p = protocols[idx];
            if !&protocols[..idx].contains(&p) {
                let p = p as u8;
                assert!(p < 16);
                match idx {
                    0 => sets |= (p as u32) << 28,
                    1 => sets |= (p as u32) << 24,
                    2 => sets |= (p as u32) << 20,
                    3 => sets |= (p as u32) << 16,
                    4 => sets |= (p as u32) << 12,
                    5 => sets |= (p as u32) << 8,
                    6 => sets |= (p as u32) << 4,
                    7 => sets |= p as u32,
                    _ => unreachable!(),
                }

                len += 1;
            }

            idx += 1;
        }
        
        Ok(Self { sets, len, })
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    pub fn iter(&self) -> ProtocolSetIter {
        ProtocolSetIter { sets: self.sets, idx: 0 }
    }
}

impl std::fmt::Debug for ProtocolSet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let protocols = self.iter().collect::<Vec<Protocol>>();
        write!(f, "{:?}", &protocols)
    }
}

#[derive(Debug)]
pub struct ProtocolSetIter {
    idx: usize,
    sets: u32,
}

impl Iterator for ProtocolSetIter {
    type Item = Protocol;

    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= 8 {
            return None;
        }

        let p = match self.idx {
            0 => (self.sets & 0b_11110000_00000000_00000000_00000000) >> 28,
            1 => (self.sets & 0b_00001111_00000000_00000000_00000000) >> 24,
            2 => (self.sets & 0b_00000000_11110000_00000000_00000000) >> 20,
            3 => (self.sets & 0b_00000000_00001111_00000000_00000000) >> 16,
            4 => (self.sets & 0b_00000000_00000000_11110000_00000000) >> 12,
            5 => (self.sets & 0b_00000000_00000000_00001111_00000000) >> 8,
            6 => (self.sets & 0b_00000000_00000000_00000000_11110000) >> 4,
            7 =>  self.sets & 0b_00000000_00000000_00000000_00001111,
            _ => return None,
        };
        assert!(p < 16);

        self.idx += 1;

        match p {
            1 => Some(Protocol::Udp),
            2 => Some(Protocol::Tcp),
            3 => Some(Protocol::Tls),
            4 => Some(Protocol::Https),
            5 => Some(Protocol::DNSCryptUdp),
            6 => Some(Protocol::DNSCryptTcp),
            _ => None,
        }
    }
}
