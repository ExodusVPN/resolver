use chrono::TimeZone;

use crate::error::Error;
use crate::wire;
use crate::wire::Kind;

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};


#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SOA {
    pub mname: String,
    pub rname: String,
    pub serial: u32,
    pub refresh: i32,
    pub retry: i32,
    pub expire: i32,
    pub minimum: u32,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MX {
    pub preference: i16,
    pub exchange: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DNSKEY {
    pub flags: wire::DNSKEYFlags,         // 16 bits
    pub protocol: wire::DNSKEYProtocol,   //  8 bits
    pub algorithm: wire::Algorithm,       //  8 bits
    pub public_key: wire::Digest<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct RRSIG {
    pub type_covered: wire::Kind,
    pub algorithm: wire::Algorithm,       //  8 bits
    pub labels: u8,
    pub original_ttl: u32,
    pub signature_expiration: u32,
    pub signature_inception: u32,
    pub key_tag: u16,
    pub signer_name: String,
    pub signature: wire::Digest<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NSEC {
    pub next_domain_name: String,
    pub type_bit_maps: Vec<wire::Kind>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NSEC3 {
    pub hash_algorithm: wire::Algorithm,
    pub flags: wire::NSEC3Flags,
    pub iterations: u16,
    pub salt_length: u8,
    pub salt: wire::Digest<Vec<u8>>,
    pub hash_length: u8,
    pub next_hashed_owner_name: wire::Digest<Vec<u8>>, // It is the unmodified binary hash value.
    pub type_bit_maps: Vec<wire::Kind>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct NSEC3PARAM {
    pub hash_algorithm: wire::Algorithm,
    pub flags: u8,
    pub iterations: u16,
    pub salt_length: u8,
    pub salt: wire::Digest<Vec<u8>>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct DS {
    pub key_tag: u16,
    pub algorithm: wire::Algorithm,
    pub digest_type: wire::DigestKind,
    pub digest: wire::Digest<Vec<u8>>,
}

// 5.1.1.  Canonical Presentation Format
// https://tools.ietf.org/html/rfc6844#section-5.1.1
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CAA {
    // Is an unsigned integer between 0 and 255.
    // 
    // 7.3.  Certification Authority Restriction Flags
    // https://tools.ietf.org/html/rfc6844#section-7.3
    // 
    // Flag         Meaning                            Reference
    // -----------  ---------------------------------- ---------
    // 0            Issuer Critical Flag               [RFC6844]
    // 1-7          Reserved>                          [RFC6844]
    pub flags: u8,
    // Is a non-zero sequence of US-ASCII letters and numbers in lower case.
    // 
    // 7.2.  Certification Authority Restriction Properties
    // https://tools.ietf.org/html/rfc6844#section-7.2
    // 
    // Tag          Meaning                                Reference
    // -----------  -------------------------------------- ---------
    // issue        Authorization Entry by Domain          [RFC6844]
    // issuewild    Authorization Entry by Wildcard Domain [RFC6844]
    // iodef        Report incident by IODEF report        [RFC6844]
    // auth         Reserved                               [HB2011]
    // path         Reserved                               [HB2011]
    // policy       Reserved                               [HB2011]
    pub tag: String,
    // Is the <character-string> encoding of the value field as specified in [RFC1035], Section 5.1.
    pub value: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ClientSubnet {
    pub src_prefix_len: u8,
    pub scope_prefix_len: u8,
    pub address: IpAddr,
}

impl std::fmt::Display for ClientSubnet {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "CLIENT={}/{} SCOPED={}/{}",
            self.address, self.src_prefix_len, self.address, self.scope_prefix_len)
    }
}

impl<R: Into<wire::IpCidr>> From<R> for ClientSubnet {
    fn from(cidr: R) -> Self {
        let cidr = cidr.into();
        let addr = cidr.address();
        let prefix_len = cidr.prefix_len();

        ClientSubnet {
            src_prefix_len: prefix_len,
            scope_prefix_len: 0,
            address: addr,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OptValue {
    None,
    ECS(ClientSubnet),
}

// 6.1.  OPT Record Definition
// https://tools.ietf.org/html/rfc6891#section-6.1
// 
// DNS EDNS0 Option Codes (OPT)
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
// 
// https://tools.ietf.org/html/rfc3225#section-3
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OPT {
    pub udp_size: u16,
    pub rcode: u8,
    pub version: u8,
    pub flags: wire::ExtensionFlags,
    pub value: OptValue,
}

/// Resource Record Value
#[derive(PartialEq, Eq, Clone)]
pub enum Value {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    // 3.3.13. SOA RDATA format
    // https://tools.ietf.org/html/rfc1035#section-3.3.13
    SOA(SOA),
    // 3.3.9. MX RDATA format
    // https://tools.ietf.org/html/rfc1035#section-3.3.9
    MX(MX),
    // 3.3.11. NS RDATA format
    // https://tools.ietf.org/html/rfc1035#section-3.3.11
    NS(String),
    CNAME(String),
    // DNAME Redirection in the DNS
    // https://tools.ietf.org/html/rfc6672
    DNAME(String),
    // https://tools.ietf.org/html/rfc1035#section-3.3.14
    // 
    // Using the Domain Name System To Store Arbitrary String Attributes
    // https://tools.ietf.org/html/rfc1464
    TXT(String),  // WARN: ascii extended characters

    // 5.1.  DS RDATA Wire Format
    // https://tools.ietf.org/html/rfc4034#section-5.1
    DS(DS),
    // 4.  The NSEC Resource Record
    // https://tools.ietf.org/html/rfc4034#page-12
    NSEC(NSEC),
    // 3.  The NSEC3 Resource Record
    // https://tools.ietf.org/html/rfc5155#section-3.2
    NSEC3(NSEC3),
    // 4.2.  NSEC3PARAM RDATA Wire Format
    // https://tools.ietf.org/html/rfc5155#page-13
    NSEC3PARAM(NSEC3PARAM),
    // 3.  The RRSIG Resource Record
    // https://tools.ietf.org/html/rfc4034#section-3
    RRSIG(RRSIG),
    // https://tools.ietf.org/html/rfc4034
    DNSKEY(DNSKEY),

    // 5.1.1.  Canonical Presentation Format
    // https://tools.ietf.org/html/rfc6844#section-5.1.1
    CAA(CAA),
    
    // OPT(OPT),

    // 4.2.  Answer with a Synthesized HINFO RRset
    // https://tools.ietf.org/html/rfc8482#section-4.2
    // 
    // The CPU field of the HINFO RDATA SHOULD be set to "RFC8482".
    // The OS field of the HINFO RDATA SHOULD be set to the null string to minimize the size of the response.
    // 
    // Note: 当客户端发起 Class=ANY 的查询时，必须要要返回该 Record.
    // HINFO,
}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::A(addr) => write!(f, "A({:?})", addr),
            Self::AAAA(addr) => write!(f, "AAAA({:?})", addr),
            Self::SOA(v) => write!(f, "{:?}", v),
            Self::MX(v) => write!(f, "{:?}", v),
            Self::NS(v) => write!(f, "NS({:?})", v),
            Self::CNAME(v) => write!(f, "CNAME({:?})", v),
            Self::DNAME(v) => write!(f, "DNAME({:?})", v),
            Self::TXT(v) => write!(f, "TXT({:?})", v),
            Self::DS(v) => write!(f, "{:?}", v),
            Self::NSEC(v) => write!(f, "{:?}", v),
            Self::NSEC3(v) => write!(f, "{:?}", v),
            Self::NSEC3PARAM(v) => write!(f, "{:?}", v),
            Self::RRSIG(v) => write!(f, "{:?}", v),
            Self::DNSKEY(v) => write!(f, "{:?}", v),
            Self::CAA(v) => write!(f, "{:?}", v),
        }
    }
}

// 3.3. Standard RRs
// https://tools.ietf.org/html/rfc1035#section-3.3
// 
// 
// List_of_DNS_record_types
// https://en.wikipedia.org/wiki/List_of_DNS_record_types
/// Resource Record
#[derive(PartialEq, Eq, Clone)]
pub struct Record {
    pub name: String,
    pub kind: wire::Kind,
    pub class: wire::Class,
    pub ttl: u32,
    pub value: Value,
}

impl Record {
    pub fn serialize(&self, offset: &mut usize, name_dict: &mut HashMap<u64, u16>, buffer: &mut [u8]) -> Result<usize, Error> {
        let begin = *offset;

        let amt = wire::write_name(&self.name, *offset, buffer, name_dict)?;
        *offset += amt;

        let mut pkt = wire::RecordPacket::new_unchecked(&mut buffer[*offset..]);
        pkt.set_kind(self.kind);
        pkt.set_class(self.class);
        pkt.set_ttl(self.ttl);

        let start = *offset + 8 + 2;
        let mut rdlen = 0usize;

        match &self.value {
            &Value::A(ref v) => {
                let rdata = &mut buffer[start..];
                let octets = v.octets();
                rdata[0] = octets[0];
                rdata[1] = octets[1];
                rdata[2] = octets[2];
                rdata[3] = octets[3];
                rdlen += 4;
            },
            &Value::AAAA(ref v) => {
                let rdata = &mut buffer[start..];
                let octets = v.octets();
                (&mut rdata[..16]).copy_from_slice(&octets);
                rdlen += 16;
            },
            &Value::SOA(ref v) => {
                let amt = wire::write_name(&v.mname, start, buffer, name_dict)?;
                rdlen += amt;
                let amt = wire::write_name(&v.rname, start + amt, buffer, name_dict)?;
                rdlen += amt;

                let rdata = &mut buffer[start..];
                (&mut rdata[rdlen..rdlen+4]).copy_from_slice(&v.serial.to_be_bytes());
                rdlen += 4;
                (&mut rdata[rdlen..rdlen+4]).copy_from_slice(&v.refresh.to_be_bytes());
                rdlen += 4;
                (&mut rdata[rdlen..rdlen+4]).copy_from_slice(&v.retry.to_be_bytes());
                rdlen += 4;
                (&mut rdata[rdlen..rdlen+4]).copy_from_slice(&v.expire.to_be_bytes());
                rdlen += 4;
                (&mut rdata[rdlen..rdlen+4]).copy_from_slice(&v.minimum.to_be_bytes());
                rdlen += 4;
            },
            &Value::MX(ref v) => {
                let rdata = &mut buffer[start..];
                (&mut rdata[rdlen..rdlen+2]).copy_from_slice(&v.preference.to_be_bytes());
                rdlen += 2;
                let amt = wire::write_name(&v.exchange, start + 2, buffer, name_dict)?;
                rdlen += amt;
            },
            &Value::NS(ref v) => {
                let amt = wire::write_name(&v, start, buffer, name_dict)?;
                rdlen += amt;
            },
            &Value::CNAME(ref v) => {
                let amt = wire::write_name(&v, start, buffer, name_dict)?;
                rdlen += amt;
            },
            &Value::DNAME(ref v) => {
                let amt = wire::write_name(&v, start, buffer, name_dict)?;
                rdlen += amt;
            },
            &Value::TXT(ref v) => {
                assert!(v.is_ascii());
                let rdata = &mut buffer[start..];
                (&mut rdata[rdlen..rdlen+v.len()]).copy_from_slice(&v.as_bytes());
                rdlen += v.len();
            },
            &Value::DS(ref v) => {
                let rdata = &mut buffer[start..];
                (&mut rdata[rdlen..rdlen+2]).copy_from_slice(&v.key_tag.to_be_bytes());
                rdlen += 2;

                rdata[rdlen] = v.algorithm.0;
                rdlen += 1;

                rdata[rdlen] = v.digest_type.0;
                rdlen += 1;
                
                (&mut rdata[rdlen..rdlen+v.digest.len()]).copy_from_slice(&v.digest.as_bytes());
                rdlen += v.digest.len();
            },
            &Value::NSEC(ref v) => {
                let amt = wire::write_name(&v.next_domain_name, start, buffer, name_dict)?;
                rdlen += amt;

                let rdata = &mut buffer[start..];

                let mut type_bit_maps = v.type_bit_maps.clone();
                let type_bit_maps_len = encode_type_bit_maps(&mut type_bit_maps, &mut rdata[rdlen..])?;
                rdlen += type_bit_maps_len;

                // (&mut rdata[rdlen..rdlen+v.type_bit_maps.len()]).copy_from_slice(&v.type_bit_maps);
                // rdlen += v.type_bit_maps.len();
            },
            &Value::NSEC3(ref v) => {
                let rdata = &mut buffer[start..];
                rdata[rdlen] = v.hash_algorithm.0;
                rdlen += 1;
                
                rdata[rdlen] = v.flags.bits();
                rdlen += 1;
                
                (&mut rdata[rdlen..rdlen+2]).copy_from_slice(&v.iterations.to_be_bytes());
                rdlen += 2;

                rdata[rdlen] = v.salt_length;
                rdlen += 1;
                
                (&mut rdata[rdlen..rdlen+v.salt.len()]).copy_from_slice(&v.salt.as_bytes());
                rdlen += v.salt.len();
                
                rdata[rdlen] = v.hash_length;
                rdlen += 1;
                
                (&mut rdata[rdlen..rdlen+v.next_hashed_owner_name.len()]).copy_from_slice(&v.next_hashed_owner_name.as_bytes());
                rdlen += v.next_hashed_owner_name.len();
                
                let mut type_bit_maps = v.type_bit_maps.clone();
                let type_bit_maps_len = encode_type_bit_maps(&mut type_bit_maps, &mut rdata[rdlen..])?;
                rdlen += type_bit_maps_len;

                // (&mut rdata[rdlen..rdlen+v.type_bit_maps.len()]).copy_from_slice(&v.type_bit_maps);
                // rdlen += v.type_bit_maps.len();
            },
            &Value::NSEC3PARAM(ref v) => {
                let rdata = &mut buffer[start..];
                rdata[rdlen] = v.hash_algorithm.0;
                rdlen += 1;

                rdata[rdlen] = v.flags;
                rdlen += 1;

                (&mut rdata[rdlen..rdlen+2]).copy_from_slice(&v.iterations.to_be_bytes());
                rdlen += 2;

                rdata[rdlen] = v.salt_length;
                rdlen += 1;
                
                (&mut rdata[rdlen..rdlen+v.salt.len()]).copy_from_slice(&v.salt.as_bytes());
                rdlen += v.salt.len();
            },
            &Value::RRSIG(ref v) => {
                let rdata = &mut buffer[start..];

                (&mut rdata[rdlen..rdlen+2]).copy_from_slice(&v.type_covered.0.to_be_bytes());
                rdlen += 2;

                rdata[rdlen] = v.algorithm.0;
                rdlen += 1;

                rdata[rdlen] = v.labels;
                rdlen += 1;
                
                (&mut rdata[rdlen..rdlen+4]).copy_from_slice(&v.original_ttl.to_be_bytes());
                rdlen += 4;

                (&mut rdata[rdlen..rdlen+4]).copy_from_slice(&v.signature_expiration.to_be_bytes());
                rdlen += 4;
                
                (&mut rdata[rdlen..rdlen+4]).copy_from_slice(&v.signature_inception.to_be_bytes());
                rdlen += 4;

                (&mut rdata[rdlen..rdlen+2]).copy_from_slice(&v.key_tag.to_be_bytes());
                rdlen += 2;

                let amt = wire::write_name(&v.signer_name, start + rdlen as usize, buffer, name_dict)?;
                rdlen += amt;

                let rdata = &mut buffer[start..];
                (&mut rdata[rdlen..rdlen+v.signature.len()]).copy_from_slice(&v.signature.as_bytes());
                rdlen += v.signature.len();
            },
            &Value::DNSKEY(ref v) => {
                let rdata = &mut buffer[start..];
                (&mut rdata[rdlen..rdlen+2]).copy_from_slice(&v.flags.bits().to_be_bytes());
                rdlen += 2;

                rdata[rdlen] = v.protocol.0;
                rdlen += 1;

                rdata[rdlen] = v.algorithm.0;
                rdlen += 1;
                
                (&mut rdata[rdlen..rdlen+v.public_key.len()]).copy_from_slice(&v.public_key.as_bytes());
                rdlen += v.public_key.len();
            },
            &Value::CAA(ref v) => {
                let rdata = &mut buffer[start..];
                rdata[rdlen] = v.flags;
                rdlen += 1;

                rdata[rdlen] = v.tag.len() as u8;
                rdlen += 1;

                (&mut rdata[rdlen..rdlen+v.tag.len()]).copy_from_slice(&v.tag.as_bytes());
                rdlen += v.tag.len();

                (&mut rdata[rdlen..rdlen+v.value.len()]).copy_from_slice(&v.value.as_bytes());
                rdlen += v.value.len();
            },
        }

        let mut pkt = wire::RecordPacket::new_unchecked(&mut buffer[*offset..]);
        assert!(rdlen <= std::u16::MAX as usize);
        pkt.set_rdlen(rdlen as u16);

        *offset += pkt.total_len();

        Ok(*offset - begin)
    }
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.kind == wire::Kind::OPT {
            write!(f, "Record {{ name: {:?}, kind: {:?}, value: {:?} }}",
                self.name,
                self.kind,
                self.value)
        } else {
            f.debug_struct("Record")
                .field("name", &self.name)
                .field("kind", &self.kind)
                .field("class", &self.class)
                .field("ttl", &self.ttl)
                .field("value", &self.value)
                .finish()
        }
    }
}

impl std::fmt::Display for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::str::FromStr for Record {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // 支持解析的 Kinds
        // ['A', 'AAAA', 'DNSKEY', 'DS', 'NS', 'NSEC', 'RRSIG', 'SOA']
        // 
        // https://tools.ietf.org/html/rfc1035#section-5.1
        // 两种文本格式:
        //     1. DOMAIN_NAME [<TTL>] [<class>] <type> <RDATA>
        //     2. DOMAIN_NAME [<class>] [<TTL>] <type> <RDATA>
        // 这里支持的是第一种格式.
        // 
        let bytes = s.as_bytes();

        let mut name: Option<String> = None;
        let mut kind: Option<wire::Kind> = None;
        let mut class: Option<wire::Class> = None;
        let mut ttl: Option<u32> = None;
        let mut rdata: Option<&str> = None;

        let mut offset = 0usize;
        let mut idx = 0usize;
        while offset < bytes.len() {
            let ch = bytes[offset];
            if ch != b'\t' {
                let start = offset;
                offset += 1;
                while offset < bytes.len() {
                    if bytes[offset] == b'\t' {
                        break;
                    } else {
                        offset += 1;
                    }
                }
                
                assert!(offset == bytes.len() || bytes[offset] == b'\t');
                
                let end = offset;
                let data = &s[start..end];
                if idx == 0 {
                    // Domain Name
                    let mut domain_name = s[start..end].to_lowercase();
                    if !domain_name.ends_with('.') {
                        debug!("Invalid DNS Name field: {:?} ", domain_name);
                        return Err(Error::Unrecognized);
                    }

                    domain_name.pop();

                    name = Some(domain_name);
                    
                } else if idx == 1 {
                    // TTL
                    match data.parse::<u32>() {
                        Ok(n) => {
                            ttl = Some(n);
                        },
                        Err(_) => {
                            debug!("Invalid DNS TTL field: {:?} ", data);
                            return Err(Error::Unrecognized);
                        }
                    }
                } else if idx == 2 {
                    // Class
                    match data.parse::<wire::Class>() {
                        Ok(v) => {
                            class = Some(v);
                        },
                        Err(e) => {
                            debug!("Invalid DNS Class field: {:?} ", data);
                            return Err(Error::Unrecognized);
                        }
                    }
                } else if idx == 3 {
                    // Kind (Type)
                    match data.parse::<wire::Kind>() {
                        Ok(v) => {
                            kind = Some(v);
                        },
                        Err(e) => {
                            debug!("Invalid DNS Type field: {:?} ", data);
                            return Err(Error::Unrecognized);
                        }
                    }
                } else if idx == 4 {
                    // Data
                    rdata = Some(data);
                } else {
                    unreachable!();
                }
                
                idx += 1;
            } else {
                offset += 1;
            }
        }

        if name.is_none() || kind.is_none() || class.is_none() || ttl.is_none() || rdata.is_none() {
            return Err(Error::Unrecognized);
        }

        let name = name.unwrap();
        let kind = kind.unwrap();
        let class = class.unwrap();
        let ttl = ttl.unwrap();
        let rdata = rdata.unwrap();
        
        let value = match kind {
            wire::Kind::A => {
                let v = rdata.parse::<Ipv4Addr>()
                    .map_err(|_| Error::Unrecognized)?;
                wire::Value::A(v)
            },
            wire::Kind::AAAA => {
                let v = rdata.parse::<Ipv6Addr>()
                    .map_err(|_| Error::Unrecognized)?;
                wire::Value::AAAA(v)
            },
            wire::Kind::NS => {
                let mut v = rdata.to_string();
                if v.ends_with('.') {
                    v.pop();
                }
                wire::Value::NS(v)
            },
            wire::Kind::DS => {
                // "40387 8 2 F2A6E4458136145067FCA10141180BAC9FD4CA768908707D98E5E2412039A1E3"
                let mut tmp = rdata.split(' ');
                let key_tag = tmp.next().ok_or(Error::Unrecognized)?.parse::<u16>().map_err(|_| Error::Unrecognized)?;
                let algorithm = wire::Algorithm(tmp.next().ok_or(Error::Unrecognized)?.parse::<u8>().map_err(|_| Error::Unrecognized)?);
                let digest_type = wire::DigestKind(tmp.next().ok_or(Error::Unrecognized)?.parse::<u8>().map_err(|_| Error::Unrecognized)?);
                let digest = hex::decode(tmp.next().ok_or(Error::Unrecognized)?).map_err(|_| Error::Unrecognized)?;
                let digest = wire::Digest::new(digest);

                wire::Value::DS(wire::DS { key_tag, algorithm, digest_type, digest })
            },
            wire::Kind::DNSKEY => {
                // "256 3 8 AwEAAbPwrxwtOMENWvblQbUFwBllR7ZtXsu9rg="
                let mut tmp = rdata.split(' ');
                
                let flags = tmp.next().ok_or(Error::Unrecognized)?.parse::<u16>().map_err(|_| Error::Unrecognized)?;
                let flags = wire::DNSKEYFlags::new_unchecked(flags);
                let protocol = tmp.next().ok_or(Error::Unrecognized)?.parse::<u8>().map_err(|_| Error::Unrecognized)?;
                let protocol = wire::DNSKEYProtocol(protocol);
                let algorithm = wire::Algorithm(tmp.next().ok_or(Error::Unrecognized)?.parse::<u8>().map_err(|_| Error::Unrecognized)?);
                let public_key = base64::decode(tmp.next().ok_or(Error::Unrecognized)?).map_err(|_| Error::Unrecognized)?;
                let public_key = wire::Digest::new(public_key);

                wire::Value::DNSKEY(wire::DNSKEY { flags, protocol, algorithm, public_key })
            },
            wire::Kind::NSEC => {
                // "ye. NS DS RRSIG NSEC"
                let mut tmp = rdata.split(' ');
                let mut next_domain_name = tmp.next().ok_or(Error::Unrecognized)?.to_string();
                if next_domain_name.ends_with('.') {
                    next_domain_name.pop();
                }

                let mut type_bit_maps = Vec::new();
                for kind in tmp {
                    if let Ok(kind) = kind.parse::<wire::Kind>() {
                        type_bit_maps.push(kind);
                    }
                }

                wire::Value::NSEC(wire::NSEC {
                    next_domain_name,
                    type_bit_maps,
                })
            },
            wire::Kind::RRSIG => {
                // zw.          86400   IN  RRSIG   
                // NSEC 8 1 86400 20191026050000 20191013040000 22545 . EGhf+lJQq8egDzxVATTj8CdW4p6fPZIjr2Y4bLZ1hEx
                let mut tmp = rdata.split(' ');
                
                let type_covered = tmp.next().ok_or(Error::Unrecognized)?.parse::<wire::Kind>().map_err(|_| Error::Unrecognized)?;
                let algorithm = wire::Algorithm(tmp.next().ok_or(Error::Unrecognized)?.parse::<u8>().map_err(|_| Error::Unrecognized)?);
                let labels = tmp.next().ok_or(Error::Unrecognized)?.parse::<u8>().map_err(|_| Error::Unrecognized)?;
                let original_ttl = tmp.next().ok_or(Error::Unrecognized)?.parse::<u32>().map_err(|_| Error::Unrecognized)?;

                // 20191026050000
                let signature_expiration = tmp.next().ok_or(Error::Unrecognized)?;
                let signature_expiration = chrono::Utc.datetime_from_str(signature_expiration, "%Y%m%d%H%M%S")
                    .map_err(|_| Error::Unrecognized)?.timestamp();
                // 20191013040000
                let signature_inception = tmp.next().ok_or(Error::Unrecognized)?;
                let signature_inception = chrono::Utc.datetime_from_str(signature_inception, "%Y%m%d%H%M%S")
                    .map_err(|_| Error::Unrecognized)?.timestamp();

                const SAFE_TIMESTAMP: i64 = 1571875200i64; // 2019/10/24 00:00:00 UTC+8
                if signature_expiration < SAFE_TIMESTAMP || signature_expiration > std::u32::MAX as i64 {
                    return Err(Error::Unrecognized);
                }
                if signature_inception < SAFE_TIMESTAMP - 3*24*60*60 || signature_inception > std::u32::MAX as i64 {
                    return Err(Error::Unrecognized);
                }
                let signature_expiration = signature_expiration as u32;
                let signature_inception = signature_inception as u32;

                let key_tag = tmp.next().ok_or(Error::Unrecognized)?.parse::<u16>().map_err(|_| Error::Unrecognized)?;
                let mut signer_name = tmp.next().ok_or(Error::Unrecognized)?.to_string();
                if signer_name.ends_with('.') {
                    signer_name.pop();
                }
                let signature = base64::decode(tmp.next().ok_or(Error::Unrecognized)?).map_err(|_| Error::Unrecognized)?;
                let signature = wire::Digest::new(signature);
                
                wire::Value::RRSIG(wire::RRSIG {
                    type_covered,
                    algorithm, 
                    labels, 
                    original_ttl, 
                    signature_expiration, 
                    signature_inception, 
                    key_tag, 
                    signer_name, 
                    signature,
                })
            },
            wire::Kind::SOA => {
                // .            86400   IN  SOA 
                // a.root-servers.net. nstld.verisign-grs.com. 2019101300 1800 900 604800 86400
                let mut tmp = rdata.split(' ');
                let mut mname = tmp.next().ok_or(Error::Unrecognized)?.to_string();
                let mut rname = tmp.next().ok_or(Error::Unrecognized)?.to_string();
                let serial = tmp.next().ok_or(Error::Unrecognized)?.parse::<u32>().map_err(|_| Error::Unrecognized)?;
                let refresh = tmp.next().ok_or(Error::Unrecognized)?.parse::<i32>().map_err(|_| Error::Unrecognized)?;
                let retry = tmp.next().ok_or(Error::Unrecognized)?.parse::<i32>().map_err(|_| Error::Unrecognized)?;
                let expire = tmp.next().ok_or(Error::Unrecognized)?.parse::<i32>().map_err(|_| Error::Unrecognized)?;
                let minimum = tmp.next().ok_or(Error::Unrecognized)?.parse::<u32>().map_err(|_| Error::Unrecognized)?;
                
                if mname.ends_with('.') {
                    mname.pop();
                }
                if rname.ends_with('.') {
                    rname.pop();
                }

                wire::Value::SOA(wire::SOA { mname, rname, serial, refresh, retry, expire, minimum })
            },
            _ => {
                return Err(Error::Unrecognized);
            }
        };

        let record = wire::Record {
            name,
            kind,
            class,
            ttl,
            value,
        };

        Ok(record)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum PseudoRecord {
    // pseudo resource records
    // *        255     RFC 1035[1]     All cached records
    // AXFR     252     RFC 1035[1]     Authoritative Zone Transfer 
    // IXFR     251     RFC 1996        Incremental Zone Transfer
    // OPT       41     RFC 6891        Option 

    // TODO:
    // ALL(ALL),
    // AXFR(AXFR),
    // IXFR(IXFR),
    OPT(OPT),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum AnyRecord {
    Normal(Record),
    Pseudo(PseudoRecord),
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SectionKind {
    Answer,
    Authority,
    Additional,
}

pub fn deserialize_record(offset: &mut usize, buffer: &[u8]) -> Result<Option<AnyRecord>, Error> {
    let mut name = String::new();
    let amt = wire::read_name(*offset, &buffer, &mut name, 0)?;
    *offset += amt;

    let rr = wire::RecordPacket::new_checked(&buffer[*offset..])?;
    let kind = rr.kind();

    if kind.is_pseudo_record_kind() {
        match deserialize_pseudo_record(offset, name, buffer)? {
            Some(pseudo_record) => Ok(Some(AnyRecord::Pseudo(pseudo_record))),
            None => Ok(None),
        }
    } else {
        match deserialize_normal_record(offset, name, buffer)? {
            Some(record) => Ok(Some(AnyRecord::Normal(record))),
            None => Ok(None),
        }
    }
}

pub fn deserialize_pseudo_record(offset: &mut usize, name: String, buffer: &[u8]) -> Result<Option<PseudoRecord>, Error> {
    let rr = wire::RecordPacket::new_checked(&buffer[*offset..])?;
    let kind = rr.kind();
    let rdlen = rr.rdlen();

    let record = match kind {
        Kind::ALL | Kind::AXFR | Kind::IXFR => {
            // NOTE: 暂不支持对这些 Record 的解析
            None
        },
        Kind::OPT => {
            if !name.is_empty() {
                debug!("OPT Record Name must be empty (ROOT).");
                return Err(Error::Unrecognized);
            }

            let ext_rr = wire::ExtensionPacket::new_checked(&buffer[*offset..])?;
            let udp_size = ext_rr.udp_size();
            let ext_rcode = ext_rr.rcode();
            let ext_version = ext_rr.version();
            let ext_flags = ext_rr.flags();
            let rdlen = ext_rr.rdlen();
            let rdata = ext_rr.rdata();

            let opt_value = if rdlen == 0 {
                OptValue::None
            } else {
                let opt_data = wire::ExtensionDataPacket::new_checked(rdata)?;
                let opt_code = opt_data.option_code();
                let opt_length = opt_data.option_length();

                if opt_code == wire::OptionCode::EDNS_CLIENT_SUBNET {
                    let opt_data_pkt = wire::ClientSubnetPacket::new_checked(opt_data.option_data())?;
                    let client_subnet = ClientSubnet {
                        src_prefix_len: opt_data_pkt.src_prefixlen(),
                        scope_prefix_len: opt_data_pkt.scope_prefixlen(),
                        address: opt_data_pkt.address(),
                    };

                    OptValue::ECS(client_subnet)
                } else {
                    debug!("unknow opt record data: CODE={} RDATA={:?}", opt_code, opt_data.option_data());
                    OptValue::None
                }
            };

            Some(PseudoRecord::OPT(OPT {
                udp_size, 
                rcode: ext_rcode,
                version: ext_version,
                flags: ext_flags,
                value: opt_value,
            }))
        },
        _ => None,
    };

    *offset += rr.total_len();

    Ok(record)
}

pub fn deserialize_normal_record(offset: &mut usize, name: String, buffer: &[u8]) -> Result<Option<Record>, Error> {
    let rr = wire::RecordPacket::new_checked(&buffer[*offset..])?;
    let kind = rr.kind();
    let class = rr.class();
    let ttl = rr.ttl();
    let rdlen = rr.rdlen();
    let rdata = rr.rdata();
    if rdata.len() < rdlen as usize {
        return Err(Error::Truncated);
    }

    *offset += rr.header_len();

    // parse record data
    let start = *offset; // rdata offset
    *offset += rdlen as usize;

    let record_value = match kind {
        Kind::A => {
            if rdlen < 4 {
                return Err(Error::Truncated);
            }

            Some(Value::A(std::net::Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])))
        },
        Kind::AAAA => {
            if rdlen < 16 {
                return Err(Error::Truncated);
            }

            let mut octets = [0u8; 16];
            &mut octets.copy_from_slice(&rdata[..16]);

            Some(Value::AAAA(std::net::Ipv6Addr::from(octets)))
        },
        Kind::NS => {
            let mut name = String::new();
            let _amt = wire::read_name(start, &buffer, &mut name, 0)?;

            Some(Value::NS(name))
        },
        Kind::CNAME => {
            let mut name = String::new();
            let _amt = wire::read_name(start, &buffer, &mut name, 0)?;

            Some(Value::CNAME(name))
        },
        Kind::DNAME => {
            let mut name = String::new();
            let _amt = wire::read_name(start, &buffer, &mut name, 0)?;

            Some(Value::DNAME(name))
        },
        Kind::TXT => {
            let txt = (&rdata).iter().map(|b| *b as char).collect::<String>();
            Some(Value::TXT(txt))
        },
        Kind::MX  => {
            if rdlen < 2 {
                return Err(Error::Truncated);
            }

            let preference = i16::from_be_bytes([rdata[0], rdata[1]]);
            let mut exchange = String::new();
            let _amt = wire::read_name(start+2, &buffer, &mut exchange, 0)?;

            Some(Value::MX(MX { preference, exchange }))
        },
        Kind::SOA => {
            let mut mname = String::new();
            let amt = wire::read_name(start, &buffer, &mut mname, 0)?;
            if (rdlen as usize) < amt {
                return Err(Error::Truncated);
            }

            let mut rname = String::new();
            let amt2 = wire::read_name(start + amt, &buffer, &mut rname, 0)?;
            if (rdlen as usize) < amt + amt2 + 20 {
                return Err(Error::Truncated);
            }

            let start = amt + amt2;
            let serial = u32::from_be_bytes([rdata[start+0], rdata[start+1], rdata[start+2], rdata[start+3]]);

            let start = start + 4;
            let refresh = i32::from_be_bytes([rdata[start+0], rdata[start+1], rdata[start+2], rdata[start+3]]);

            let start = start + 4;
            let retry = i32::from_be_bytes([rdata[start+0], rdata[start+1], rdata[start+2], rdata[start+3]]);

            let start = start + 4;
            let expire = i32::from_be_bytes([rdata[start+0], rdata[start+1], rdata[start+2], rdata[start+3]]);

            let start = start + 4;
            let minimum = u32::from_be_bytes([rdata[start+0], rdata[start+1], rdata[start+2], rdata[start+3]]);

            Some(Value::SOA(SOA { mname, rname, serial, refresh, retry, expire, minimum }))
        },
        // DNSSEC
        Kind::DS => {
            if rdlen < 4 {
                return Err(Error::Truncated);
            }

            let key_tag = u16::from_be_bytes([buffer[start], buffer[start+1]]);
            let algorithm = wire::Algorithm(buffer[start+2]);
            // 1      SHA-1                   MANDATORY
            // 2      SHA-256
            let digest_type = wire::DigestKind(buffer[start+3]);
            let digest = &rdata[4..];

            Some(Value::DS(DS {
                key_tag,
                algorithm,
                digest_type,
                digest: wire::Digest::new(digest.to_vec()),
            }))
        },
        Kind::NSEC => {
            let mut next_domain_name = String::new();
            let amt = wire::read_name(start, &buffer, &mut next_domain_name, 0)?;
            if (rdlen as usize) < amt {
                return Err(Error::Truncated);
            }

            let type_bit_maps = &rdata[amt..];
            let type_bit_maps = decode_type_bit_maps(type_bit_maps)?;

            Some(Value::NSEC( NSEC {
                next_domain_name,
                type_bit_maps: type_bit_maps,
            }))
        },
        Kind::NSEC3 => {
            if rdlen < 6 {
                return Err(Error::Truncated);
            }

            let hash_algorithm = wire::Algorithm(buffer[start]);
            let flags = wire::NSEC3Flags::new_unchecked(buffer[start+1]);
            let iterations = u16::from_be_bytes([buffer[start+2], buffer[start+3]]);
            let salt_length = buffer[start+4];

            let salt_end = 5 + salt_length as usize;
            if rdata.len() < salt_end + 1 {
                return Err(Error::Truncated);
            }
            let salt = wire::Digest::new((&rdata[5..salt_end]).to_vec());
            
            let hash_length = rdata[salt_end];
            let hash_start = salt_end + 1;
            let hash_end = hash_start + hash_length as usize;
            if rdata.len() < hash_end + 1 {
                return Err(Error::Truncated);
            }

            let next_hashed_owner_name = wire::Digest::new(rdata[hash_start..hash_end].to_vec());
            let type_bit_maps = &rdata[hash_end..];
            let type_bit_maps = decode_type_bit_maps(type_bit_maps)?;
            
            Some(Value::NSEC3(NSEC3 {
                hash_algorithm,
                flags,
                iterations,
                salt_length,
                salt,
                hash_length,
                next_hashed_owner_name,
                type_bit_maps,
            }))
        },
        Kind::NSEC3PARAM => {
            if rdlen < 5 {
                return Err(Error::Truncated);
            }

            let hash_algorithm = wire::Algorithm(buffer[start]);
            let flags = buffer[start+1];
            let iterations = u16::from_be_bytes([buffer[start+2], buffer[start+3]]);
            let salt_length = buffer[start+4];
            let salt_end = 5 + salt_length as usize;
            if rdata.len() < salt_end + 1 {
                return Err(Error::Truncated);
            }
            let salt = wire::Digest::new((&rdata[5..salt_end]).to_vec());

            Some(Value::NSEC3PARAM(NSEC3PARAM {
                hash_algorithm,
                flags,
                iterations,
                salt_length,
                salt,
            }))
        },
        Kind::RRSIG => {
            if rdlen < 19 {
                return Err(Error::Truncated);
            }

            let type_covered = wire::Kind(u16::from_be_bytes([buffer[start], buffer[start+1]]));
            let algorithm = wire::Algorithm(buffer[start+2]);
            let labels = buffer[start+3];
            let original_ttl = u32::from_be_bytes([buffer[start+4], buffer[start+5], buffer[start+6], buffer[start+7]]);
            let signature_expiration = u32::from_be_bytes([buffer[start+8], buffer[start+9], buffer[start+10], buffer[start+11]]);
            let signature_inception = u32::from_be_bytes([buffer[start+12], buffer[start+13], buffer[start+14], buffer[start+15]]);
            let key_tag = u16::from_be_bytes([buffer[start+16], buffer[start+17]]);

            let mut signer_name = String::new();
            let amt = wire::read_name(start+18, &buffer, &mut signer_name, 0)?;
            
            if rdata.len() < 19 + amt {
                return Err(Error::Truncated);
            }

            let signature = wire::Digest::new(rdata[18+amt..].to_vec());

            Some(Value::RRSIG(RRSIG {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                signature_expiration,
                signature_inception,
                key_tag,
                signer_name,
                signature,
            }))
        },
        Kind::DNSKEY => {
            if rdata.len() < 4 {
                return Err(Error::Truncated);
            }

            let flags = wire::DNSKEYFlags::new_unchecked(u16::from_be_bytes([buffer[start], buffer[start+1]]));
            let protocol = wire::DNSKEYProtocol(buffer[start+2]);
            let algorithm = wire::Algorithm(buffer[start+3]);
            let public_key = wire::Digest::new(rdata[4..].to_vec());

            if protocol != wire::DNSKEYProtocol::V3 {
                // protocol must be 0x03;

            }

            Some(Value::DNSKEY(DNSKEY { flags, protocol, algorithm, public_key }))
        },

        Kind::CAA => {
            if rdata.len() < 2 {
                return Err(Error::Truncated);
            }

            let flags = rdata[0];
            let tag_len = rdata[1];

            if rdata.len() < 2 + tag_len as usize {
                return Err(Error::Truncated);
            }

            let tag_end = 2 + tag_len as usize;
            let tag = (&rdata[2..tag_end]).iter().map(|b| *b as char).collect::<String>();

            let value = (&rdata[tag_end..]).iter().map(|b| *b as char).collect::<String>();

            Some(Value::CAA(CAA { flags, tag, value }))
        },

        Kind::OPT | Kind::ALL | Kind::AXFR | Kind::IXFR => {
            // pseudo record
            None
        },
        _ => {
            None
        }
    };
    
    match record_value {
        Some(value) => {
            let record = Record {
                name, kind, class, ttl, value
            };

            Ok(Some(record))
        },
        None => {
            Ok(None)
        }
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
pub fn decode_type_bit_maps(buffer: &[u8]) -> Result<Vec<wire::Kind>, Error> {
    let mut kinds = Vec::new();
    let mut offset = 0usize;

    while offset < buffer.len() {
        if buffer.len() < offset + 2 {
            return Err(Error::Truncated);
        }

        let window = buffer[offset];
        let mut bitmap_len = buffer[offset + 1];
        if bitmap_len == 0 || bitmap_len > 32 {
            // bitmap length (from 1 to 32)
            return Err(Error::Unrecognized);
        }

        offset += 2;
        
        let bitmap_start = offset;
        let bitmap_end   = offset + bitmap_len as usize;
        if buffer.len() < bitmap_end {
            return Err(Error::Truncated);
        }

        let bitmap = &buffer[bitmap_start..bitmap_end];
        offset += bitmap_len as usize;

        let mut bitmap_idx = 0u16;
        for bits in bitmap {
            let start = window as u16 * (std::u8::MAX as u16 + 1);
            for i in 0usize..8 {
                let bit = bits << i >> 7;
                // if bitmap_idx > 0 && bit == 1 {
                if bit == 1 {
                    let n = start + bitmap_idx;
                    kinds.push(wire::Kind(n));
                }

                bitmap_idx += 1;
            }
        }
    }

    Ok(kinds)
}

pub fn encode_type_bit_maps(input: &mut Vec<wire::Kind>, mut output: &mut [u8]) -> Result<usize, Error> {
    input.sort();

    let mut amt = 0usize;
    
    let mut window = 0u8;
    let mut bitmap_len = 0u8;
    let mut bitmap_idx = 0u8;
    for i in 2..34 {
        if let Some(mut byte) = output.get_mut(i) {
            *byte = 0;
        }
    }

    for (idx, kind) in input.iter().enumerate() {
        let [hi, lo] = kind.0.to_be_bytes();

        let is_last_kind = idx == input.len() - 1;
        let is_new_window = hi != window;

        if is_new_window {
            let len_bytes = bitmap_len + 1;
            if len_bytes == 0 || len_bytes > 32 {
                return Err(Error::Unrecognized);
            }

            output[0] = window;
            output[1] = len_bytes;
            let window_len = len_bytes as usize + 2;
            output = &mut output[window_len..];
            for i in 2..34 {
                if let Some(mut byte) = output.get_mut(i) {
                    *byte = 0;
                }
            }

            amt += window_len;

            window = hi;
            bitmap_len = 0;
            bitmap_idx = 0;
        }

        let bit_idx = lo % 8;
        let byte_idx = if bit_idx > 0 {
            lo / 8
        } else {
            lo / 8
        };
        
        bitmap_len = byte_idx;
        bitmap_idx = bit_idx;
        
        let byte_idx = byte_idx as usize + 2;
        if output.len() < byte_idx {
            return Err(Error::Truncated);
        }
        match bit_idx {
            0 => output[byte_idx] |= 0b_1000_0000,
            1 => output[byte_idx] |= 0b_0100_0000,
            2 => output[byte_idx] |= 0b_0010_0000,
            3 => output[byte_idx] |= 0b_0001_0000,
            4 => output[byte_idx] |= 0b_0000_1000,
            5 => output[byte_idx] |= 0b_0000_0100,
            6 => output[byte_idx] |= 0b_0000_0010,
            7 => output[byte_idx] |= 0b_0000_0001,
            _ => unreachable!(),
        };

        if is_last_kind {
            let len_bytes = bitmap_len + 1;
            if len_bytes == 0 || len_bytes > 32 {
                return Err(Error::Unrecognized);
            }
            
            output[0] = window;
            output[1] = len_bytes;
            let window_len = len_bytes as usize + 2;
            
            amt += window_len;
        }
    }

    Ok(amt)
}


#[test]
fn test_parse_root_zone() {
    let data = include_str!("../../data/root.zone");

    for line in data.lines() {
        assert!(line.parse::<Record>().is_ok(), line);
    }
}

#[test]
fn test_encode_type_bit_maps() {
    let bitmap: Vec<u8> = vec![0, 7, 34, 0, 0, 0, 0, 2, 144];
    assert_eq!(decode_type_bit_maps(&bitmap), Ok(vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM]));

    assert_eq!(decode_type_bit_maps(&[0u8, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 128]),
        Ok(vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::URI]));

    assert_eq!(decode_type_bit_maps(&[0, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 64]),
        Ok(vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::CAA]));

    assert_eq!(decode_type_bit_maps(&[0u8, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 192, 128, 1, 128]),
        Ok(vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::URI, Kind::CAA, Kind::TA]));
}

#[test]
fn test_decode_type_bit_maps() {
    let mut buffer = [0u8; 1024];

    let mut kinds = vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM];
    let amt = encode_type_bit_maps(&mut kinds, &mut buffer);
    assert!(amt.is_ok());
    let amt = amt.unwrap();
    let bitmap = &buffer[..amt];
    assert_eq!(bitmap, &[0u8, 7, 34, 0, 0, 0, 0, 2, 144]);


    let mut kinds = vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::URI];
    let amt = encode_type_bit_maps(&mut kinds, &mut buffer);
    assert!(amt.is_ok());
    let amt = amt.unwrap();
    let bitmap = &buffer[..amt];
    assert_eq!(bitmap, &[0u8, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 128]);


    let mut kinds = vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::CAA];
    let amt = encode_type_bit_maps(&mut kinds, &mut buffer);
    assert!(amt.is_ok());
    let amt = amt.unwrap();
    let bitmap = &buffer[..amt];
    assert_eq!(bitmap, &[0, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 64]);


    let mut kinds = vec![Kind::NS, Kind::SOA, Kind::RRSIG, Kind::DNSKEY, Kind::NSEC3PARAM, Kind::CAA, Kind::URI, Kind::TA];
    let amt = encode_type_bit_maps(&mut kinds, &mut buffer);
    assert!(amt.is_ok());
    let amt = amt.unwrap();
    let bitmap = &buffer[..amt];
    assert_eq!(bitmap, &[0u8, 7, 34, 0, 0, 0, 0, 2, 144, 1, 1, 192, 128, 1, 128]);
}
