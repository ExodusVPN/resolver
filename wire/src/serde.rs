use crate::error::Error;
use crate::kind::Kind;

use punycode;

use std::hash::Hasher;
use std::hash::BuildHasher;
use std::collections::HashMap;


pub trait BinSerialize {
    fn serialize(&self, serializer: &mut Serializer) -> Result<usize, Error>;
}

pub trait BinDeserialize: Sized {
    // type 
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, Error>;
}

pub trait Codec: Sized {
    fn bin_serialize(&self, serializer: &mut Serializer) -> Result<usize, Error>;
    fn bin_deserialize(deserializer: &mut Deserializer) -> Result<Self, Error>;

    fn presentation_serialize(&self) -> Result<String, Error>;
    fn presentation_deserialize(line: &str) -> Result<Self, Error>;
}

/// 255 octets or less
pub const MAXIMUM_NAMES_SIZE: usize = 255;
/// 63 octets or less
pub const MAXIMUM_LABEL_SIZE: usize = 63;


// Serializer
// Deserializer

pub struct Serializer<'a> {
    buffer: &'a mut [u8],
    position: usize,
    names_dict: HashMap<u64, u16>,
}

impl<'a> Serializer<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self {
            buffer,
            position: 0,
            names_dict: HashMap::new(),
        }
    }
    
    #[inline]
    pub fn position(&self) -> usize {
        self.position
    }

    fn name_hash(&self, name: &str) -> u64 {
        let mut hasher = self.names_dict.hasher().build_hasher();
        hasher.write(name.as_bytes());
        hasher.finish()
    }

    pub fn get_name_pointer(&self, name: &str) -> Option<&u16> {
        let key = self.name_hash(name);
        self.names_dict.get(&key)
    }

    #[inline]
    pub fn advance(&mut self, amt: usize) {
        self.position += amt;
    }

    #[inline]
    pub fn clear(&mut self) {
        for x in self.buffer.iter_mut() {
            *x = 0;
        }
        self.names_dict.clear();
        self.position = 0;
    }
}

impl<'a> Serializer<'a> {
    #[inline]
    pub fn write_ip_addr(&mut self, val: std::net::IpAddr) -> Result<usize, Error> {
        match val {
            std::net::IpAddr::V4(addr) => self.write_ipv4_addr(addr),
            std::net::IpAddr::V6(addr) => self.write_ipv6_addr(addr),
        }
    }

    #[inline]
    pub fn write_ipv4_addr(&mut self, val: std::net::Ipv4Addr) -> Result<usize, Error> {
        let num = u32::from(val);
        self.write_u32(num)
    }

    #[inline]
    pub fn write_ipv6_addr(&mut self, val: std::net::Ipv6Addr) -> Result<usize, Error> {
        const LEN: usize = 16;
        if self.position + LEN > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        let octets: [u8; LEN] = val.octets();
        
        (&mut self.buffer[self.position..self.position + LEN]).copy_from_slice(&octets);
        self.position += LEN;
        Ok(LEN)
    }

    // 域名字符集
    // 
    // 2.3.1. Preferred name syntax
    // https://tools.ietf.org/html/rfc1035#section-2.3.1
    // 
    // Domain name syntax
    // https://en.wikipedia.org/wiki/Domain_name#Domain_name_syntax
    // 
    #[inline]
    fn write_label(&mut self, label: &str) -> Result<usize, Error> {
        if self.position + label.len() + 1 > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        if label.len() > MAXIMUM_LABEL_SIZE {
            debug!("Label Size Limit Exceeded.");
            return Err(Error::Unrecognized);
        }
        
        let label_len_pos = self.position;
        self.position += 1;

        for byte in label.as_bytes() {
            match byte {
                b'a' ..= b'z' | b'A' ..= b'Z' | b'0' ..= b'9' | b'-' | b'_' => {
                    self.buffer[self.position] = *byte;
                    self.position += 1;
                },
                b'.' => {
                    debug!("Invalid Domain Name Label.");
                    return Err(Error::Unrecognized);
                },
                _ => {
                    debug!("Invalid Domain Name Label.");
                    return Err(Error::Unrecognized);
                }
            }
        }

        self.buffer[label_len_pos] = label.len() as u8;

        Ok(label.len() + 1)
    }

    #[inline]
    pub fn write_name(&mut self, name: &str) -> Result<usize, Error> {
        if name.len() == 0 {
            // ROOT Name (.)
            return self.write_u8(0);
        }

        if name.ends_with('.') {
            debug!("Invalid Domain Name.");
            return Err(Error::Unrecognized);
        }
        
        if let Some(pointer) = self.get_name_pointer(name) {
            let n = 0b_1100_0000_0000_0000 | pointer;
            return self.write_u16(n);
        }

        let name_pos = self.position;
        if name_pos > std::u16::MAX as usize {
            return Err(Error::Unrecognized);
        }

        let mut amt = 0usize;
        for label in name.split('.') {
            let mut is_internationalized = false;

            // Check domain name syntax
            for ch in label.chars() {
                if ch.is_ascii() {
                    match ch {
                        'a' ..= 'z' | 'A' ..= 'Z' | '0' ..= '9' | '-' | '_' => { },
                        _ => return Err(Error::Unrecognized),
                    }
                } else {
                    // internationalized domain name
                    is_internationalized = true;
                    break;
                }
            }

            if is_internationalized {
                let mut label = punycode::encode(label).map_err(|_| Error::Unrecognized)?;
                label.insert_str(0, "xn--");

                amt += self.write_label(&label)?;
            } else {
                amt += self.write_label(&label)?;
            }
        }

        if amt > MAXIMUM_NAMES_SIZE {
            debug!("Names Size Limit Exceeded.");
            return Err(Error::Unrecognized);
        }

        if self.position + 1 > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        // NOTE: 设定 C Style 的终结符.
        self.buffer[self.position] = 0;
        self.position += 1;
        amt += 1;

        // Cache
        let key = self.name_hash(name);
        self.names_dict.insert(key, name_pos as u16);

        Ok(amt)
    }

    #[inline]
    pub fn write_u8(&mut self, val: u8) -> Result<usize, Error> {
        if self.position + 1 > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        self.buffer[self.position] = val;
        self.position += 1;
        Ok(1)
    }

    #[inline]
    pub fn write_u16(&mut self, val: u16) -> Result<usize, Error> {
        if self.position + 2 > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        let [a, b] = val.to_be_bytes();
        self.buffer[self.position] = a;
        self.buffer[self.position + 1] = b;
        self.position += 2;
        Ok(2)
    }

    #[inline]
    pub fn write_u32(&mut self, val: u32) -> Result<usize, Error> {
        if self.position + 4 > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        let [a, b, c, d] = val.to_be_bytes();
        self.buffer[self.position] = a;
        self.buffer[self.position + 1] = b;
        self.buffer[self.position + 2] = c;
        self.buffer[self.position + 3] = d;
        self.position += 4;
        Ok(4)
    }

    #[inline]
    pub fn write_u64(&mut self, val: u64) -> Result<usize, Error> {
        if self.position + 8 > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        let [a, b, c, d, e, f, g, h] = val.to_be_bytes();
        self.buffer[self.position] = a;
        self.buffer[self.position + 1] = b;
        self.buffer[self.position + 2] = c;
        self.buffer[self.position + 3] = d;
        self.buffer[self.position + 4] = e;
        self.buffer[self.position + 5] = f;
        self.buffer[self.position + 6] = g;
        self.buffer[self.position + 7] = h;
        self.position += 8;
        Ok(8)
    }

    #[inline]
    pub fn write_usize(&mut self, val: usize) -> Result<usize, Error> {
        let octets = val.to_be_bytes();
        let len = octets.len();
        if self.position + len > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        (&mut self.buffer[self.position..self.position + len]).copy_from_slice(&octets);
        self.position += len;
        Ok(len)
    }

    #[inline]
    pub fn write_i8(&mut self, val: i8) -> Result<usize, Error> {
        self.write_u8(val as u8)
    }

    #[inline]
    pub fn write_i16(&mut self, val: i16) -> Result<usize, Error> {
        self.write_u16(val as u16)
    }

    #[inline]
    pub fn write_i32(&mut self, val: i32) -> Result<usize, Error> {
        self.write_u32(val as u32)
    }

    #[inline]
    pub fn write_i64(&mut self, val: i64) -> Result<usize, Error> {
        self.write_u64(val as u64)
    }

    #[inline]
    pub fn write_isize(&mut self, val: isize) -> Result<usize, Error> {
        self.write_usize(val as usize)
    }

    #[inline]
    pub fn write_slice(&mut self, val: &[u8]) -> Result<usize, Error> {
        let len = val.len();
        if self.position + len > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        &mut self.buffer[self.position..self.position + len].copy_from_slice(val);
        self.position += len;

        Ok(len)
    }

    pub fn write_type_bit_maps(&mut self, input: &[Kind]) -> Result<usize, Error> {
        // WARN: 确保 input 已经是按照大小排序过的。
        assert!(input.len() > 0);

        let mut amt = 0usize;
        
        let mut window = 0u8;
        let mut bitmap_len = 0u8;
        let mut bitmap_idx = 0u8;
        let mut bitmap_len_offset = 0usize;

        for (idx, kind) in input.iter().enumerate() {
            let [hi, lo] = kind.0.to_be_bytes();

            let is_last_kind = idx == input.len() - 1;
            let is_new_window = hi != window;

            if idx == 0 || is_new_window {
                if idx > 0 {
                    self.buffer[bitmap_len_offset] = bitmap_len + 1;
                    amt += bitmap_len as usize + 3;
                    self.position += bitmap_len as usize + 1;
                }
                
                self.write_u8(hi)?;
                bitmap_len_offset = self.position;
                self.write_u8(0)?;

                window = hi;
                bitmap_len = 0;
                bitmap_idx = 0;
            }

            let bit_idx = lo % 8;
            let byte_idx = lo / 8;

            assert!(byte_idx >= bitmap_len);

            bitmap_len = byte_idx;
            bitmap_idx = bit_idx;
            
            let byte_idx = self.position + byte_idx as usize;
            if byte_idx > self.buffer.len() {
                return Err(Error::Exhausted);
            }

            match bit_idx {
                0 => self.buffer[byte_idx] |= 0b_1000_0000,
                1 => self.buffer[byte_idx] |= 0b_0100_0000,
                2 => self.buffer[byte_idx] |= 0b_0010_0000,
                3 => self.buffer[byte_idx] |= 0b_0001_0000,
                4 => self.buffer[byte_idx] |= 0b_0000_1000,
                5 => self.buffer[byte_idx] |= 0b_0000_0100,
                6 => self.buffer[byte_idx] |= 0b_0000_0010,
                7 => self.buffer[byte_idx] |= 0b_0000_0001,
                _ => unreachable!(),
            };

            if is_last_kind {
                self.buffer[bitmap_len_offset] = bitmap_len + 1;
                amt += bitmap_len as usize + 3;
                self.position += bitmap_len as usize + 1;
            }
        }

        Ok(amt)
    }
}


pub struct Deserializer<'a> {
    buffer: &'a [u8],
    position: usize,
}


impl<'a> Deserializer<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self {
            buffer,
            position: 0,
        }
    }

    fn read_name_inner(&self, offset: usize, output: &mut String, recursion_count: u8) -> Result<usize, Error> {
        if recursion_count > 5 {
            debug!("Invalid Domain Name.");
            return Err(Error::Exhausted);
        }

        let packet = self.buffer;
        let mut position = offset;

        loop {
            if position >= packet.len() {
                return Err(Error::Exhausted);
            }

            let label_len = packet[position];
            let label_kind = label_len >> 6;

            // DNS Label Types
            // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-10
            match label_kind {
                0b00 => {
                    // Normal label lower 6 bits is the length of the label    Standard    [RFC1035]
                    // a sequence of labels ending in a zero octet
                    // or a sequence of labels ending with a pointer
                    if label_len == 0 {
                        position += 1;
                        break;
                    }

                    if label_len as usize > MAXIMUM_LABEL_SIZE {
                        return Err(Error::Malformed);
                    }

                    let start = position + 1;
                    let end = start + label_len as usize;
                    
                    if end >= packet.len() {
                        return Err(Error::Truncated);
                    }

                    let data = &packet[start..end];
                    let s = std::str::from_utf8(data)
                        .map_err(|_| Error::Malformed)?;

                    // Check domain name syntax
                    for ch in s.as_bytes() {
                        match ch {
                            b'a' ..= b'z' | b'A' ..= b'Z' | b'0' ..= b'9' | b'-' | b'_' => { },
                            // Format Error
                            _ => return Err(Error::Malformed),
                        }
                    }

                    output.push_str(s);
                    output.push('.');

                    position = end;
                },
                0b11 => {
                    // Compressed label the lower 6 bits and the 8 bits from next octet form a pointer to the compression target.
                    // Standard    [RFC1035]
                    let index = u16::from_be_bytes([ label_len << 2 >> 2, packet[position+1] ]) as usize;
                    
                    if index >= packet.len() {
                        return Err(Error::Malformed);
                    }

                    let _amt = self.read_name_inner(index as usize, output, recursion_count + 1)?;
                    if position == offset {
                        // a pointer
                        let amt = 2usize;
                        return Ok(amt);
                    } else {
                        // a sequence of labels ending with a pointer
                        let amt = position + 2 - offset;
                        return Ok(amt)
                    }
                },
                0b01 => {
                    // Extended label type the lower 6 bits of this type (section 3) indicate the type of label in use
                    // Proposed  [RFC6891]
                    // 
                    // WARN: deprecated by RFC6891
                    // 
                    // 5.  Extended Label Types
                    // https://tools.ietf.org/html/rfc6891#section-5
                    let ext_label_kind = label_len << 2 >> 2;
                    match ext_label_kind {
                        0b00_0001 => {
                            // Binary Label     Historic    [RFC3364] [RFC3363] [RFC2673] [RFC6891]
                            return Err(Error::Malformed);
                        },
                        0b11_1111 => {
                            // https://tools.ietf.org/html/rfc2671#section-3.2
                            // Reserved for future expansion.   Proposed    [RFC6891]
                            return Err(Error::Malformed);
                        },
                        _ => {
                            return Err(Error::Malformed);
                        },
                    }
                },
                0b10 => {
                    // Unallocated
                    return Err(Error::Malformed);
                },
                _ => unreachable!(),
            }
        }

        let amt = position - offset;

        if output.ends_with('.') {
            output.pop();
        }

        return Ok(amt);
    }

    #[inline]
    pub fn read_name(&mut self) -> Result<String, Error> {
        let mut output = String::new();

        let amt = self.read_name_inner(self.position, &mut output, 0)?;
        self.position += amt;
        
        return Ok(output);
    }

    #[inline]
    pub fn read_ipv4_addr(&mut self) -> Result<std::net::Ipv4Addr, Error> {
        self.read_u32().map(|n| std::net::Ipv4Addr::from(n))
    }

    #[inline]
    pub fn read_ipv6_addr(&mut self) -> Result<std::net::Ipv6Addr, Error> {
        const LEN: usize = 16;
        if self.position + LEN > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        let mut octets = [0u8; LEN];
        &mut octets.copy_from_slice(&self.buffer[self.position..self.position + LEN]);
        self.position += LEN;

        Ok(std::net::Ipv6Addr::from(octets))
    }

    #[inline]
    pub fn read_u8(&mut self) -> Result<u8, Error> {
        if self.position + 1 > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        let byte = self.buffer[self.position];
        self.position += 1;

        Ok(byte)
    }

    #[inline]
    pub fn read_u16(&mut self) -> Result<u16, Error> {
        const LEN: usize = 2;
        if self.position + LEN > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        let mut octets = [0u8; LEN];
        &mut octets.copy_from_slice(&self.buffer[self.position..self.position + LEN]);
        self.position += LEN;

        Ok(u16::from_be_bytes(octets))
    }

    #[inline]
    pub fn read_u32(&mut self) -> Result<u32, Error> {
        const LEN: usize = 4;
        if self.position + LEN > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        let mut octets = [0u8; LEN];
        &mut octets.copy_from_slice(&self.buffer[self.position..self.position + LEN]);
        self.position += LEN;

        Ok(u32::from_be_bytes(octets))
    }

    #[inline]
    pub fn read_u64(&mut self) -> Result<u64, Error> {
        const LEN: usize = 8;
        if self.position + LEN > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        let mut octets = [0u8; LEN];
        &mut octets.copy_from_slice(&self.buffer[self.position..self.position + LEN]);
        self.position += LEN;

        Ok(u64::from_be_bytes(octets))
    }

    #[inline]
    pub fn read_usize(&mut self) -> Result<usize, Error> {
        const LEN: usize = std::mem::size_of::<usize>();
        if self.position + LEN > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        let mut octets = [0u8; LEN];
        &mut octets.copy_from_slice(&self.buffer[self.position..self.position + LEN]);
        self.position += LEN;

        Ok(usize::from_be_bytes(octets))
    }

    #[inline]
    pub fn read_i8(&mut self) -> Result<i8, Error> {
        Ok(self.read_u8()? as i8)
    }

    #[inline]
    pub fn read_i16(&mut self) -> Result<i16, Error> {
        Ok(self.read_u16()? as i16)
    }

    #[inline]
    pub fn read_i32(&mut self) -> Result<i32, Error> {
        Ok(self.read_u32()? as i32)
    }

    #[inline]
    pub fn read_i64(&mut self) -> Result<i64, Error> {
        Ok(self.read_u64()? as i64)
    }

    #[inline]
    pub fn read_isize(&mut self) -> Result<isize, Error> {
        Ok(self.read_usize()? as isize)
    }

    #[inline]
    pub fn read_slice(&mut self, len: usize) -> Result<&'a [u8], Error> {
        if self.position + len > self.buffer.len() {
            return Err(Error::Exhausted);
        }

        let data = &self.buffer[self.position..self.position + len];
        self.position += len;
        Ok(data)
    }

    // NSEC RDATA Wire Format
    // 
    // 2.1.2.  The List of Type Bit Map(s) Field
    // https://tools.ietf.org/html/rfc3845#section-2.1.2
    // 
    // NSEC3 RDATA Wire Format
    // 
    // 3.2.1.  Type Bit Maps Encoding
    // https://tools.ietf.org/html/rfc5155#section-3.2.1
    pub fn read_type_bit_maps(&mut self, buffer_len: usize) -> Result<Vec<Kind>, Error> {
        let buffer_len = self.position + buffer_len;
        let mut kinds = Vec::new();

        while self.position < buffer_len {
            if self.position + 2 > buffer_len {
                return Err(Error::Exhausted);
            }

            let window = self.read_u8()?;
            let bitmap_len = self.read_u8()?;
            if bitmap_len == 0 || bitmap_len > 32 {
                // bitmap length (from 1 to 32)
                return Err(Error::Unrecognized);
            }

            if self.position + bitmap_len as usize > buffer_len {
                return Err(Error::Exhausted);
            }
            let bitmap = self.read_slice(bitmap_len as usize)?;

            let mut bitmap_idx = 0u16;
            for bits in bitmap {
                let start = window as u16 * (std::u8::MAX as u16 + 1);
                for i in 0usize..8 {
                    let bit = bits << i >> 7;
                    // if bitmap_idx > 0 && bit == 1 {
                    if bit == 1 {
                        let n = start + bitmap_idx;
                        kinds.push(Kind(n));
                    }

                    bitmap_idx += 1;
                }
            }
        }

        Ok(kinds)
    }
}



#[test]
fn test_name() {
    let mut buffer = [0u8; 512];

    let mut serializer = Serializer::new(&mut buffer);
    assert_eq!(serializer.write_name("www.中国"), Ok(16));
    assert_eq!(serializer.write_name("www.中国"), Ok(2));
    assert_eq!(&serializer.buffer[..serializer.position()], &[
        3, 119, 119, 119, 10, 120, 110, 45, 45, 102, 105, 113, 115, 56, 115, 0,
        192, 0,
    ]);

    let mut deserializer = Deserializer::new(&buffer);

    assert_eq!(deserializer.read_name(), Ok("www.xn--fiqs8s".to_string()));
    assert_eq!(&deserializer.buffer[deserializer.position..deserializer.position + 2], &[192, 0]);
    assert_eq!(deserializer.read_name(), Ok("www.xn--fiqs8s".to_string()));
}

#[test]
fn test_type_bit_maps() {
    // encode
    let mut buffer = [0u8; 1024];
    let mut serializer = Serializer::new(&mut buffer);

    let mut kinds = vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM];
    kinds.sort();
    let amt = serializer.write_type_bit_maps(&kinds);
    assert!(amt.is_ok());
    let amt = amt.unwrap();
    assert_eq!(&serializer.buffer[..amt], &[0u8, 7, 34, 0, 0, 0, 0, 2, 144]);
    serializer.clear();

    let mut kinds = vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::URI];
    kinds.sort();
    let amt = serializer.write_type_bit_maps(&kinds);
    assert!(amt.is_ok());
    let amt = amt.unwrap();
    assert_eq!(&serializer.buffer[..amt], &[0u8, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 128]);
    serializer.clear();

    let mut kinds = vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::CAA];
    kinds.sort();
    let amt = serializer.write_type_bit_maps(&kinds);
    assert!(amt.is_ok());
    let amt = amt.unwrap();
    assert_eq!(&serializer.buffer[..amt], &[0, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 64]);
    serializer.clear();

    let mut kinds = vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::CAA, Kind::URI, Kind::TA];
    kinds.sort();
    let amt = serializer.write_type_bit_maps(&kinds);
    assert!(amt.is_ok());
    let amt = amt.unwrap();
    assert_eq!(&serializer.buffer[..amt], &[0u8, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 192, 128, 1, 128]);
    serializer.clear();

    // decode
    let bitmap = [0, 7, 34, 0, 0, 0, 0, 2, 144];
    let mut deserializer = Deserializer::new(&bitmap);
    assert_eq!(deserializer.read_type_bit_maps(bitmap.len()),
        Ok(vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM]));

    let bitmap = [0, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 128];
    let mut deserializer = Deserializer::new(&bitmap);
    assert_eq!(deserializer.read_type_bit_maps(bitmap.len()),
        Ok(vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::URI]));

    let bitmap = [0, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 64];
    let mut deserializer = Deserializer::new(&bitmap);
    assert_eq!(deserializer.read_type_bit_maps(bitmap.len()),
        Ok(vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::CAA]));

    let bitmap = [0, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 192, 128, 1, 128];
    let mut deserializer = Deserializer::new(&bitmap);
    assert_eq!(deserializer.read_type_bit_maps(bitmap.len()),
        Ok(vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::URI, Kind::CAA, Kind::TA]));
}
