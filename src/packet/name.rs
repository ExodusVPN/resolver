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

// 
// Note that while upper and lower case letters are allowed in domain
// names, no significance is attached to the case.  That is, two names with
// the same spelling but different case are to be treated as if identical.
// 
// The labels must follow the rules for ARPANET host names.  They must
// start with a letter, end with a letter or digit, and have as interior
// characters only letters, digits, and hyphen.  There are also some
// restrictions on the length.  Labels must be 63 characters or less.
pub fn write_label<'a>(label: &str, offset: usize, packet: &mut [u8], _cache: &mut HashMap<u64, u16>) -> Result<usize, Error> {
    if label.len() == 0 {
        return Err(Error::InvalidDomainNameLabel);
    }

    // let mut hasher = cache.hasher().build_hasher();
    // hasher.write(label.as_bytes());
    // let key = hasher.finish();

    // if let Some(pointer) = cache.get(&key) {
    //     let n = 0b_1100_0000_0000_0000 | pointer;
    //     let octets = n.to_be_bytes();
    //     packet[offset+0] = octets[0];
    //     packet[offset+1] = octets[1];

    //     return Ok(2);
    // }

    let mut amt = 0usize;
    for byte in label.as_bytes() {
        if amt >= MAXIMUM_LABEL_SIZE {
            return Err(Error::LabelSizeLimitExceeded);
        }
        match byte {
            b'a' ..= b'z' | b'A' ..= b'Z' | b'0' ..= b'9' | b'-' | b'_' => {
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
    // cache.insert(key, offset as u16);

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

    // FIXME: 允许空字符串？
    //        如果查询 ROOT Servers，或许在 Request 里面探测到后，直接回复固定的内容比较好(Root servers list)。
    //        不需要有数据包的构建步骤。
    if name.len() == 0 || name.ends_with('.') {
        return Err(Error::InvalidDomainName);
    }

    let mut hasher = cache.hasher().build_hasher();
    hasher.write(name.as_bytes());
    let key = hasher.finish();

    if let Some(pointer) = cache.get(&key) {
        let n = 0b_1100_0000_0000_0000 | pointer;
        let octets = n.to_be_bytes();
        packet[offset+0] = octets[0];
        packet[offset+1] = octets[1];

        return Ok(2);
    }

    // TODO: 启用最大化的压缩？
    //       缺点是如果数据量不多的话，其实没什么效果。
    //       另外，也需要单独的内存分配。
    //       
    //       目前只做最简单的压缩处理。
    for label in name.split('.') {
        let mut is_internationalized = false;

        // Check domain name syntax
        for ch in label.chars() {
            if ch.is_ascii() {
                match ch {
                    'a' ..= 'z' | 'A' ..= 'Z' | '0' ..= '9' | '-' | '_' => { },
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

    // Cache
    cache.insert(key, name_start as u16);

    Ok(amt + 1)
}

pub fn read_name<'a>(packet_offset: usize, packet: &'a [u8], output: &mut String, recursion_count: u8) -> Result<usize, Error> {
    if recursion_count > 5 {
        return Err(Error::InvalidDomainName);
    }

    let mut offset = packet_offset;
    loop {

        if offset >= packet.len() {
            return Err(Error::Truncated);
        }

        let label_len = packet[offset];
        let label_kind = label_len >> 6;

        // DNS Label Types
        // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-10
        match label_kind {
            0b00 => {
                // Normal label lower 6 bits is the length of the label    Standard    [RFC1035]
                // a sequence of labels ending in a zero octet
                // or
                // a sequence of labels ending with a pointer
                if label_len == 0 {
                    offset += 1;
                    break;
                }

                if label_len as usize > MAXIMUM_LABEL_SIZE {
                    return Err(Error::LabelSizeLimitExceeded);
                }

                let start = offset + 1;
                let end = start + label_len as usize;
                
                if end >= packet.len() {
                    return Err(Error::Truncated);
                }

                let data = &packet[start..end];
                let s = std::str::from_utf8(data)
                    .map_err(|_| Error::InvalidUtf8Sequence)?;

                // Check domain name syntax
                for ch in s.as_bytes() {
                    match ch {
                        b'a' ..= b'z' | b'A' ..= b'Z' | b'0' ..= b'9' | b'-' | b'_' => { },
                        _ => {
                            // Format Error
                            return Err(Error::InvalidDomainName);
                        }
                    }
                }

                output.push_str(s);
                output.push('.');

                offset = end;
            },
            0b11 => {
                // Compressed label the lower 6 bits and the 8 bits from next octet form a pointer to the compression target.
                // Standard    [RFC1035]
                let index = u16::from_be_bytes([ label_len << 2 >> 2, packet[offset+1] ]) as usize;
                
                if index >= packet.len() {
                    return Err(Error::InvalidDomainNameLabel);
                }

                let _amt = read_name(index as usize, packet, output, recursion_count + 1)?;
                if offset == packet_offset {
                    // a pointer
                    let amt = 2usize;
                    return Ok(amt);
                } else {
                    // a sequence of labels ending with a pointer
                    let amt = offset + 2 - packet_offset;
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
                        return Err(Error::InvalidExtLabelKind);
                    },
                    0b11_1111 => {
                        // https://tools.ietf.org/html/rfc2671#section-3.2
                        // Reserved for future expansion.   Proposed    [RFC6891]
                        return Err(Error::InvalidExtLabelKind);
                    },
                    _ => {
                        return Err(Error::InvalidExtLabelKind);
                    },
                }
            },
            0b10 => {
                // Unallocated
                return Err(Error::InvalidLabelKind);
            },
            _ => unreachable!(),
        }
    }

    let amt = offset - packet_offset;

    if output.ends_with('.') {
        output.pop();
    }

    return Ok(amt);
}


#[test]
fn test_name() {
    let mut buffer = [0u8; 512];
    let mut cache: HashMap<u64, u16> = HashMap::new();

    let offset = 2usize;
    let packet = &mut buffer[..];

    let amt = write_name("www.中国", offset, packet, &mut cache).unwrap();
    let amt2 = write_name("www.中国", offset + amt, packet, &mut cache).unwrap();
    assert_eq!(amt, 16);
    assert_eq!(amt2, 2);
    assert_eq!(&packet[..offset+amt+amt2], &[
        0, 0,
        3, 119, 119, 119, 10, 120, 110, 45, 45, 102, 105, 113, 115, 56, 115, 0,
        192, 2,
    ]);

    let mut qname = String::new();
    let name1_amt = read_name(offset, packet, &mut qname, 0).unwrap();
    assert_eq!(name1_amt, amt);
    assert_eq!(qname, "www.xn--fiqs8s");

    qname.clear();
    let name2_amt = read_name(offset+amt, packet, &mut qname, 0).unwrap();
    assert_eq!(name2_amt, amt2);
    assert_eq!(qname, "www.xn--fiqs8s");
}
