use std::io;
use std::io::Read;
use std::io::Cursor;

use crate::kind::Kind;
use crate::MAXIMUM_NAMES_SIZE;
use crate::MAXIMUM_LABEL_SIZE;


pub struct Deserializer<'a> {
    cursor: Cursor<&'a [u8]>,
}

impl<'a> Deserializer<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Deserializer {
            cursor: Cursor::new(buf),
        }
    }

    #[inline]
    #[cfg(target_pointer_width = "32")]
    pub fn position(&self) -> usize {
        let pos = self.cursor.position();
        if pos <= std::usize::MAX {
            pos as usize
        } else {
            // NOTE: 因为 Position 类型是 u64 ，所以在 32 位系统里面，转换成 usize 时，需要注意一下。
            //       考虑到这个库的实际情况并不需要需要超过 usize 大小的缓冲区，所以我们基本也不需要担心
            //       此处的 Panic.
            panic!("Ooops ...");
        }
    }

    #[inline]
    #[cfg(target_pointer_width = "64")]
    pub fn position(&self) -> usize {
        self.cursor.position() as usize
    }

    #[inline]
    pub fn set_position(&mut self, pos: usize) {
        self.cursor.set_position(pos as u64)
    }

    #[inline]
    pub fn get_ref(&self) -> &[u8] {
        self.cursor.get_ref()
    }

    #[inline]
    pub fn into_inner(self) -> &'a [u8] {
        self.cursor.into_inner()
    }

    #[inline]
    pub fn reset(&mut self) {
        self.cursor.set_position(0);
    }
}

impl<'a> Read for Deserializer<'a> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.cursor.read(buf)
    }
}

pub trait Deserialize: Sized {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error>;
}


impl Deserialize for u8 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let mut buf = [0u8; 1];
        deserializer.cursor.read_exact(&mut buf)?;
        Ok(buf[0])
    }
}

impl Deserialize for u16 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let mut buf = [0u8; 2];
        deserializer.cursor.read_exact(&mut buf)?;
        Ok(u16::from_be_bytes(buf))
    }
}

impl Deserialize for u32 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let mut buf = [0u8; 4];
        deserializer.cursor.read_exact(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }
}

impl Deserialize for u64 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let mut buf = [0u8; 8];
        deserializer.cursor.read_exact(&mut buf)?;
        Ok(u64::from_be_bytes(buf))
    }
}

impl Deserialize for u128 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let mut buf = [0u8; 16];
        deserializer.cursor.read_exact(&mut buf)?;
        Ok(u128::from_be_bytes(buf))
    }
}

impl Deserialize for usize {
    #[cfg(target_pointer_width = "32")]
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let n = u32::deserialize(deserializer)?;
        Ok(n as usize)
    }

    #[cfg(target_pointer_width = "64")]
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let n = u64::deserialize(deserializer)?;
        Ok(n as usize)
    }
}


impl Deserialize for i8 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let n = u8::deserialize(deserializer)?;
        Ok(n as i8)
    }
}

impl Deserialize for i16 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let mut buf = [0u8; 2];
        deserializer.cursor.read_exact(&mut buf)?;
        Ok(i16::from_be_bytes(buf))
    }
}

impl Deserialize for i32 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let mut buf = [0u8; 4];
        deserializer.cursor.read_exact(&mut buf)?;
        Ok(i32::from_be_bytes(buf))
    }
}

impl Deserialize for i64 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let mut buf = [0u8; 8];
        deserializer.cursor.read_exact(&mut buf)?;
        Ok(i64::from_be_bytes(buf))
    }
}

impl Deserialize for i128 {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let mut buf = [0u8; 16];
        deserializer.cursor.read_exact(&mut buf)?;
        Ok(i128::from_be_bytes(buf))
    }
}

impl Deserialize for isize {
    #[cfg(target_pointer_width = "32")]
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let n = i32::deserialize(deserializer)?;
        Ok(n as isize)
    }

    #[cfg(target_pointer_width = "64")]
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let n = i64::deserialize(deserializer)?;
        Ok(n as isize)
    }
}


impl Deserialize for std::net::Ipv4Addr {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        Ok(std::net::Ipv4Addr::from(u32::deserialize(deserializer)?))
    }
}

impl Deserialize for std::net::Ipv6Addr {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        Ok(std::net::Ipv6Addr::from(u128::deserialize(deserializer)?))
    }
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
pub fn read_type_bit_maps(deserializer: &mut Deserializer, bitmaps_len: usize) -> Result<Vec<Kind>, io::Error> {
    let end_pos = deserializer.position() + bitmaps_len;
    let mut kinds = Vec::new();

    while deserializer.position() < end_pos {
        if deserializer.position() + 2 > end_pos {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
        }
        
        let window = u8::deserialize(deserializer)?;
        let bitmap_len = u8::deserialize(deserializer)?;

        if bitmap_len == 0 || bitmap_len > 32 {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "bitmap length must between 1 and 32."));
        }

        if deserializer.position() + bitmap_len as usize > end_pos {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
        }

        let start = deserializer.position();
        let end = start + bitmap_len as usize;
        deserializer.set_position(start + end);
        let buffer = deserializer.get_ref();
        let bitmap = &buffer[start..end];

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


impl Deserialize for String {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let mut output = String::new();

        let amt = read_name_inner(deserializer, deserializer.position(), &mut output, 0)?;
        deserializer.set_position(deserializer.position() + amt);

        return Ok(output);
    }
}

fn read_name_inner(deserializer: &mut Deserializer, offset: usize, output: &mut String, recursion_count: u8) -> Result<usize, io::Error> {
    if recursion_count > 5 {
        return Err(io::Error::new(io::ErrorKind::Other, "recursion limit"));
    }

    let packet = deserializer.get_ref();
    let mut position = offset;

    loop {
        if position >= packet.len() {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
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
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "Label Size Limit Exceeded."));
                }

                let start = position + 1;
                let end = start + label_len as usize;
                
                if end >= packet.len() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                }

                let data = &packet[start..end];
                let s = std::str::from_utf8(data)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf-8 sequence"))?;

                // Check domain name syntax
                for ch in s.as_bytes() {
                    match ch {
                        b'a' ..= b'z' | b'A' ..= b'Z' | b'0' ..= b'9' | b'-' | b'_' => { },
                        // Format Error
                        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DNS name syntax")),
                    }
                }

                output.push_str(s);
                output.push('.');

                position = end;
            },
            0b11 => {
                // Compressed label the lower 6 bits and the 8 bits from next octet form a pointer to the compression target.
                // Standard    [RFC1035]
                let lo = label_len << 2 >> 2;
                let hi = packet[position+1];
                let index = u16::from_be_bytes([lo, hi,]) as usize;
                if index >= packet.len() {
                    debug!("invalid label pointer: {:?}", index);
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                }

                let _amt = read_name_inner(deserializer, index as usize, output, recursion_count + 1)?;
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
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported Extended Label Types"))
                    },
                    0b11_1111 => {
                        // https://tools.ietf.org/html/rfc2671#section-3.2
                        // Reserved for future expansion.   Proposed    [RFC6891]
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported Extended Label Types"))
                    },
                    _ => {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported Extended Label Types"))
                    },
                }
            },
            0b10 => {
                // Unallocated
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Unsupported Extended Label Types"));
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

