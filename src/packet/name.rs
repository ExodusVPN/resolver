use crate::error::Error;
use crate::MAXIMUM_LABEL_SIZE;
use crate::MAXIMUM_NAMES_SIZE;

use std::hash::Hasher;
use std::hash::BuildHasher;
use std::collections::HashMap;

// Example of IDNA encoding
// https://en.wikipedia.org/wiki/Internationalized_domain_name#Example_of_IDNA_encoding
// 
// Example of IDNA encoding
// 
// IDNA encoding may be illustrated using the example domain Bücher.example. (German: Bücher, lit. 'books'.) 
// This domain name has two labels, Bücher and example. 
// The second label is pure ASCII, and is left unchanged. 
// The first label is processed by Nameprep to give bücher, 
// and then converted to Punycode to result in bcher-kva. 
// It is then prefixed with xn-- to produce xn--bcher-kva. 
// The resulting name suitable for use in DNS records and queries is therefore "xn--bcher-kva.example. 
// 
// 互联网中心.中国  --> xn--fiq7iq58bfy3a8bb.xn--fiqs8s
// 互联网中心      --> xn--fiq7iq58bfy3a8bb
// 中国           --> xn--fiqs8s
// 

const NAME_POINTER_MASK: u8 = 0b_1100_0000;


// 
// Note that while upper and lower case letters are allowed in domain
// names, no significance is attached to the case.  That is, two names with
// the same spelling but different case are to be treated as if identical.
// 
// The labels must follow the rules for ARPANET host names.  They must
// start with a letter, end with a letter or digit, and have as interior
// characters only letters, digits, and hyphen.  There are also some
// restrictions on the length.  Labels must be 63 characters or less.
pub fn write_label<'a>(label: &str, offset: usize, packet: &mut [u8], cache: &mut HashMap<u64, u16>) -> Result<usize, Error> {
    if label.len() == 0 {
        return Err(Error::InvalidDomainNameLabel);
    }

    let mut hasher = cache.hasher().build_hasher();
    hasher.write(label.as_bytes());
    let key = hasher.finish();

    if let Some(pointer) = cache.get(&key) {
        let n = 0b_1100_0000_0000_0000 | pointer;
        let octets = n.to_be_bytes();
        packet[offset+0] = octets[0];
        packet[offset+1] = octets[1];

        return Ok(2);
    }

    let mut amt = 0usize;
    for byte in label.as_bytes() {
        if amt >= MAXIMUM_LABEL_SIZE {
            return Err(Error::LabelSizeLimitExceeded);
        }
        match byte {
            b'a' ..= b'z' | b'A' ..= b'Z' | b'0' ..= b'9' | b'-' => {
                packet[offset + amt + 1] = *byte;
                amt += 1;
            },
            b'.' => {
                return Err(Error::InvalidDomainNameLabel);
            },
            _ => {
                return Err(Error::InvalidDomainNameLabel);
            }
        }
    }

    if amt > MAXIMUM_LABEL_SIZE {
        return Err(Error::LabelSizeLimitExceeded);
    }

    packet[offset] = amt as u8;

    amt += 1;

    // Cache
    cache.insert(key, offset as u16);

    Ok(amt)
}


// 域名字符集
// 
// 2.3.1. Preferred name syntax
// https://tools.ietf.org/html/rfc1035#section-2.3.1
// 
// Domain name syntax
// https://en.wikipedia.org/wiki/Domain_name#Domain_name_syntax
// 
pub fn write_name<'a>(name: &str, offset: usize, packet: &mut [u8], cache: &mut HashMap<u64, u16>) -> Result<usize, Error> {
    let name_start = offset;
    let mut offset = offset;

    if name.len() == 0 {
        return Err(Error::InvalidDomainName);
    }

    for label in name.split('.') {
        let mut is_internationalized = false;

        // Check
        for ch in label.chars() {
            if ch.is_ascii() {
                match ch {
                    'a' ..= 'z' | 'A' ..= 'Z' | '0' ..= '9' | '-' => { },
                    _ => return Err(Error::InvalidDomainNameLabel),
                }
            } else {
                // internationalized domain name
                is_internationalized = true;
            }
        }

        let label_size = if is_internationalized {
            // TODO: Punycode 的算法代码需要提高！
            //       避免返回一个需要 Alloc 的 String 类型。
            let mut label = crate::punycode::encode(label).map_err(|_| Error::InvalidDomainNameLabel)?;
            label.insert_str(0, "xn--");

            write_label(&label, offset, packet, cache)?
        } else {
            write_label(&label, offset, packet, cache)?
        };

        offset += label_size;
    }

    let amt = offset - name_start;
    if amt > MAXIMUM_NAMES_SIZE {
        return Err(Error::NamesSizeLimitExceeded);
    }

    // NOTE: 设定 C Style 的终结符.
    packet[offset] = 0;

    Ok(amt + 1)
}


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Label<'a> {
    // The OFFSET field specifies an offset from the start of the message
    offset: usize,
    data: &'a [u8],
}

impl<'a> Label<'a> {
    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn bytes(&self) -> &[u8] {
        self.data
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn to_str(&self) -> Result<&str, Error> {
        std::str::from_utf8(self.data)
            .map_err(|_| Error::InvalidUtf8Sequence)
    }

    pub fn to_str_unchecked(&self) -> &str {
        unsafe { std::str::from_utf8_unchecked(self.data) }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Labels<'a> {
    // The OFFSET field specifies an offset from the start of the message
    offset: usize,
    packet: &'a [u8],
}

impl<'a> Iterator for Labels<'a> {
    type Item = Label<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let label_len = self.packet[self.offset];
        if label_len & NAME_POINTER_MASK == NAME_POINTER_MASK {
            // a pointer
            let a = self.packet[self.offset];
            let b = self.packet[self.offset+1];
            let pointer = (u16::from_be_bytes([a, b]) & 0b_0011_1111_1111_1111) as usize;
            let label_len = self.packet[pointer];

            self.offset += 2;

            if label_len == 0 {
                // a sequence of labels ending with a pointer
                return None;
            }

            let start = pointer + 1;
            let end = start + label_len as usize;

            Some(Label {
                offset: pointer,
                data: &self.packet[start..end],
            })
        } else {
            // a sequence of labels ending in a zero octet
            if label_len == 0 {
                return None;
            }

            let pointer = self.offset;
            let start = self.offset + 1;
            let end = start + label_len as usize;
            
            self.offset = end;

            Some(Label {
                offset: pointer,
                data: &self.packet[start..end],
            })
        }
    }
}


// 4.1.4. Message compression
// https://tools.ietf.org/html/rfc1035#section-4.1.4
// 
// The pointer takes the form of a two octet sequence:
// 
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     | 1  1|                OFFSET                   |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 
// The first two bits are ones.  This allows a pointer to be distinguished
// from a label, since the label must begin with two zero bits because
// labels are restricted to 63 octets or less.  (The 10 and 01 combinations
// are reserved for future use.)  The OFFSET field specifies an offset from
// the start of the message (i.e., the first octet of the ID field in the
// domain header).  A zero offset specifies the first byte of the ID field,
// etc.
// 
// The compression scheme allows a domain name in a message to be
// represented as either:
// 
//    - a sequence of labels ending in a zero octet
// 
//    - a pointer
// 
//    - a sequence of labels ending with a pointer
// 
// Pointers can only be used for occurances of a domain name where the
// format is not class specific.  If this were not the case, a name server
// or resolver would be required to know the format of all RRs it handled.
// As yet, there are no such cases, but they may occur in future RDATA
// formats.
// 
// If a domain name is contained in a part of the message subject to a
// length field (such as the RDATA section of an RR), and compression is
// used, the length of the compressed name is used in the length
// calculation, rather than the length of the expanded name.
// 
// Programs are free to avoid using pointers in messages they generate,
// although this will reduce datagram capacity, and may cause truncation.
// However all programs are required to understand arriving messages that
// contain pointers.
// 
//    - a sequence of labels ending in a zero octet
//    - a pointer
//    - a sequence of labels ending with a pointer

#[derive(Debug, Clone, Copy)]
pub struct Name<'a> {
    // The OFFSET field specifies an offset from the start of the message
    offset: usize,
    packet: &'a [u8],
    len: usize,
}

impl<'a> Name<'a> {
    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn labels(&self) -> Labels<'a> {
        Labels { offset: self.offset, packet: self.packet }
    }

    pub fn to_string(&self) -> Result<String, Error> {
        let mut s = String::new();
        for label in self.labels() {
            s.push_str(label.to_str()?);
            s.push('.');
        }

        if s.ends_with('.') {
            s.pop();
        }

        Ok(s)
    }

    pub fn to_string_unchecked(&self) -> String {
        let mut s = String::new();
        for label in self.labels() {
            s.push_str(label.to_str_unchecked());
            s.push('.');
        }

        if s.ends_with('.') {
            s.pop();
        }

        s
    }

    pub fn len(&self) -> usize {
        self.len
    }
    
    pub fn bytes(&self) -> &[u8] {
        &self.packet[self.offset..self.offset+self.len]
    }
}


pub fn read_name<'a>(packet_offset: usize, packet: &'a [u8]) -> Result<Name<'a>, Error> {
    if packet.len() == 0 {
        return Err(Error::InvalidDomainName);
    }

    let mut offset = packet_offset;
    loop {
        let label_len = packet[offset];
        if label_len & NAME_POINTER_MASK == NAME_POINTER_MASK {
            // a pointer
            let pointer = (u16::from_be_bytes([ packet[offset], packet[offset+1] ]) & 0b_0011_1111_1111_1111) as usize;
            if pointer > packet.len() - 1 {
                return Err(Error::InvalidDomainNameLabel);
            }

            // NOTE: 会有嵌套问题吗？ (比如 packet[offset] 得到的还是一个 pointer .)
            let label_len = packet[pointer];
            offset += 2;

            // if label_len == 0 {
            //     // a sequence of labels ending with a pointer
            //     break;
            // }

            if label_len as usize > MAXIMUM_LABEL_SIZE {
                return Err(Error::LabelSizeLimitExceeded);
            }

            // break;
            let len = 2;
            return Ok(Name { offset: pointer as usize, packet, len });
            // return read_name(pointer as usize, packet);

        } else {
            // a sequence of labels ending in a zero octet
            if label_len == 0 {
                offset += 1;
                break;
            }

            if label_len as usize > MAXIMUM_LABEL_SIZE {
                return Err(Error::LabelSizeLimitExceeded);
            }

            offset += 1 + label_len as usize;
        }
    }

    let len = offset - packet_offset;

    Ok(Name { offset: packet_offset, packet, len })
}


#[test]
fn test_name() {
    let mut buffer = [0u8; 512];
    let mut cache: HashMap<u64, u16> = HashMap::new();

    let offset = 2usize;
    let packet = &mut buffer[..];

    let amt = write_name("www.中国", offset, packet, &mut cache).unwrap();
    let amt2 = write_name("www.hi.中国", offset + amt, packet, &mut cache).unwrap();
    assert_eq!(amt, 16);
    assert_eq!(amt2, 8);
    assert_eq!(&packet[..offset+amt+amt2], &[
        0, 0,
        3, 119, 119, 119, 10, 120, 110, 45, 45, 102, 105, 113, 115, 56, 115, 0,
        192, 2, 2, 104, 105, 192, 6, 0,
    ]);

    let name1 = read_name(offset, packet).unwrap();
    let name2 = read_name(offset+amt, packet).unwrap();

    assert_eq!(name1.to_string(), Ok("www.xn--fiqs8s".to_string()));
    assert_eq!(name2.to_string(), Ok("www.hi.xn--fiqs8s".to_string()));
}
