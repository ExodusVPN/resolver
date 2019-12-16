use std::io;
use std::io::Write;
use std::io::Cursor;
use std::hash::Hasher;
use std::hash::BuildHasher;
use std::collections::HashMap;

use crate::kind::Kind;
use crate::MAXIMUM_NAMES_SIZE;
use crate::MAXIMUM_LABEL_SIZE;


pub struct Serializer<'a> {
    cursor: io::Cursor<&'a mut [u8]>,
    names: HashMap<u64, u16>,
}

impl<'a> Serializer<'a> {
    pub fn new(buf: &'a mut [u8]) -> Self {
        Serializer {
            cursor: Cursor::new(buf),
            names: HashMap::new(),
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
    pub fn get_mut(&mut self) -> &mut [u8] {
        self.cursor.get_mut()
    }

    #[inline]
    pub fn into_inner(self) -> &'a [u8] {
        self.cursor.into_inner()
    }

    #[inline]
    pub fn reset(&mut self) {
        self.names.clear();
        self.cursor.set_position(0);
    }
}

impl<'a> Write for Serializer<'a> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        self.cursor.write(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.cursor.flush()
    }
}


pub trait Serialize: Sized {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error>;
}


impl Serialize for u8 {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&[*self])
    }
}

impl Serialize for u16 {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.to_be_bytes())
    }
}

impl Serialize for u32 {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.to_be_bytes())
    }
}

impl Serialize for u64 {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.to_be_bytes())
    }
}

impl Serialize for u128 {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.to_be_bytes())
    }
}

impl Serialize for usize {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.to_be_bytes())
    }
}


impl Serialize for i8 {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        (*self as u8).serialize(serializer)
    }
}

impl Serialize for i16 {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.to_be_bytes())
    }
}

impl Serialize for i32 {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.to_be_bytes())
    }
}

impl Serialize for i64 {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.to_be_bytes())
    }
}

impl Serialize for i128 {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.to_be_bytes())
    }
}

impl Serialize for isize {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.to_be_bytes())
    }
}

impl Serialize for std::net::IpAddr {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        match self {
            &std::net::IpAddr::V4(addr) => addr.serialize(serializer),
            &std::net::IpAddr::V6(addr) => addr.serialize(serializer),
        }
    }
}

impl Serialize for std::net::Ipv4Addr {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.octets())
    }
}

impl Serialize for std::net::Ipv6Addr {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(&self.octets())
    }
}


impl Serialize for &[u8] {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(self)
    }
}

impl Serialize for &Vec<u8> {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(self.as_ref())
    }
}

impl Serialize for Vec<u8> {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        serializer.write_all(self.as_ref())
    }
}


impl Serialize for Vec<Kind> {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        self.as_slice().serialize(serializer)
    }
}

impl Serialize for &Vec<Kind> {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        self.as_slice().serialize(serializer)
    }
}

impl Serialize for &[Kind] {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        // WARN: 确保 input 已经是按照大小排序过的。
        let input = self;
        if input.is_empty() {
            return Ok(());
        }

        let mut amt = 0usize;
        
        let mut window = 0u8;
        let mut bitmap_len = 0u8;
        let mut bitmap_idx = 0u8;
        let mut bitmap_len_offset = 0usize;

        let buffer_len = serializer.get_ref().len();
        
        for (idx, kind) in input.iter().enumerate() {
            let [hi, lo] = kind.0.to_be_bytes();

            let is_last_kind = idx == input.len() - 1;
            let is_new_window = hi != window;

            if idx == 0 || is_new_window {
                if idx > 0 {
                    let buffer = serializer.get_mut();
                    buffer[bitmap_len_offset] = bitmap_len + 1;

                    amt += bitmap_len as usize + 3;
                    serializer.set_position(serializer.position() + bitmap_len as usize + 1);
                }
                
                hi.serialize(serializer)?;
                bitmap_len_offset = serializer.position();
                0u8.serialize(serializer)?;

                window = hi;
                bitmap_len = 0;
                bitmap_idx = 0;
            }

            let bit_idx = lo % 8;
            let byte_idx = lo / 8;

            assert!(byte_idx >= bitmap_len);

            bitmap_len = byte_idx;
            bitmap_idx = bit_idx;
            
            let byte_idx = serializer.position() + byte_idx as usize;
            if byte_idx > buffer_len {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
            }

            let buffer = serializer.get_mut();
            match bit_idx {
                0 => buffer[byte_idx] |= 0b_1000_0000,
                1 => buffer[byte_idx] |= 0b_0100_0000,
                2 => buffer[byte_idx] |= 0b_0010_0000,
                3 => buffer[byte_idx] |= 0b_0001_0000,
                4 => buffer[byte_idx] |= 0b_0000_1000,
                5 => buffer[byte_idx] |= 0b_0000_0100,
                6 => buffer[byte_idx] |= 0b_0000_0010,
                7 => buffer[byte_idx] |= 0b_0000_0001,
                _ => unreachable!(),
            };

            if is_last_kind {
                buffer[bitmap_len_offset] = bitmap_len + 1;
                amt += bitmap_len as usize + 3;
                serializer.set_position(serializer.position() + bitmap_len as usize + 1);
            }
        }

        Ok(())
    }
}


impl Serialize for &String {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        self.as_str().serialize(serializer)
    }
}

impl Serialize for String {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        self.as_str().serialize(serializer)
    }
}

// 域名字符集
// 
// 2.3.1. Preferred name syntax
// https://tools.ietf.org/html/rfc1035#section-2.3.1
// 
// Domain name syntax
// https://en.wikipedia.org/wiki/Domain_name#Domain_name_syntax
// 
impl Serialize for &str {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        let name = self;
        if name.len() == 0 {
            // ROOT Name (.)
            return 0u8.serialize(serializer);
        }

        if name.ends_with('.') {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Domain Name."));
        }
        
        let mut hasher = serializer.names.hasher().build_hasher();
        hasher.write(name.as_bytes());
        let key = hasher.finish();
        if let Some(pointer) = serializer.names.get(&key) {
            let n = 0b_1100_0000_0000_0000 | pointer;
            return n.serialize(serializer);
        }

        let name_pos = serializer.position();
        if name_pos > std::u16::MAX as usize {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Domain Name."));
        }

        let mut amt = 0usize;
        for label in name.split('.') {
            let mut is_internationalized = false;

            // Check domain name syntax
            for ch in label.chars() {
                if ch.is_ascii() {
                    match ch {
                        'a' ..= 'z' | 'A' ..= 'Z' | '0' ..= '9' | '-' | '_' => { },
                        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Domain Name.")),
                    }
                } else {
                    // internationalized domain name
                    is_internationalized = true;
                    break;
                }
            }

            if is_internationalized {
                let mut label = punycode::encode(label).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Invalid Domain Name."))?;
                label.insert_str(0, "xn--");

                amt += write_label(serializer, &label)?;
            } else {
                amt += write_label(serializer, &label)?;
            }
        }

        if amt > MAXIMUM_NAMES_SIZE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Names Size Limit Exceeded."));
        }

        let buffer_len = serializer.get_ref().len();
        if serializer.position() + 1 > buffer_len {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
        }

        // NOTE: 设定 C Style 的终结符.
        let pos = serializer.position();
        let buffer = serializer.get_mut();
        buffer[pos] = 0;
        serializer.set_position(serializer.position() + 1);

        amt += 1;

        // Cache
        serializer.names.insert(key, name_pos as u16);

        Ok(())
    }
}

#[inline]
fn write_label(serializer: &mut Serializer, label: &str) -> Result<usize, io::Error> {
    let buffer_len = serializer.get_ref().len();

    if serializer.position() + label.len() + 1 > buffer_len {
        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
    }

    if label.len() > MAXIMUM_LABEL_SIZE {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Label Size Limit Exceeded."));
    }
    
    let label_len_pos = serializer.position();
    serializer.set_position(serializer.position() + 1);

    
    for byte in label.as_bytes() {
        match byte {
            b'a' ..= b'z' | b'A' ..= b'Z' | b'0' ..= b'9' | b'-' | b'_' => {
                let pos = serializer.position();
                let buffer = serializer.get_mut();
                buffer[pos] = *byte;
                serializer.set_position(serializer.position() + 1);
            },
            b'.' => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Domain Name Label."));
            },
            _ => {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Domain Name Label."));
            }
        }
    }

    let buffer = serializer.get_mut();
    buffer[label_len_pos] = label.len() as u8;

    Ok(label.len() + 1)
}
