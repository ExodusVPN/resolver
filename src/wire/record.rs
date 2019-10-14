use crate::error::Error;

use crate::wire::Kind;
use crate::wire::Class;
use crate::wire::Flags;
use crate::wire::read_name;
use crate::wire::OptionCode;
use crate::wire::AddressFamily;
use crate::wire::DNSKEYProtocol;
use crate::wire::DNSKEYFlags;
use crate::wire::Algorithm;
use crate::wire::DigestKind;
use crate::wire::AsciiStr;
use crate::wire::ExtensionFlags;


use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};



#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct ClientSubnet {
    pub address_family: AddressFamily,
    pub src_prefix_len: u8,
    pub scope_prefix_len: u8,
    pub address: IpAddr,
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum OptionValue<'a> {
    None,
    ClientSubnet(ClientSubnet),
    Raw(&'a [u8]),
}


#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct ClientSubnet2 {
    pub src_prefix_len: u8,
    pub scope_prefix_len: u8,
    pub address: IpAddr,
}

pub enum ExtensionValue {
    None,
    ClientSubnet(ClientSubnet2),
}

// OPT Resource Record
pub struct Extension {
    // kind: Kind, // OPT
    udp_size: u16,
    rcode: u8,
    version: u8,
    flags: ExtensionFlags,
    value: ExtensionValue,
}

pub struct Response {
    extension: Option<Extension>,
}

// Normal Resource Record
pub struct Record2<'a, N: AsRef<str>> {
    name: N,
    kind: Kind,
    class: Class,
    ttl: u32,
    value: Value<'a>,
}

pub struct RecordRepr<'a, N: AsRef<str>> {
    pub name: N,
    pub kind: Kind,
    pub class: Class,
    pub ttl: u32,
    pub value: Value<'a>,
}

// pub fn parse<T: AsRef<[u8]> + ?Sized>(frame: &Frame<&T>) -> Result<Repr>    [src]
// Parse an Ethernet II frame and return a high-level representation.
// pub fn buffer_len(&self) -> usize   [src]
// Return the length of a header that will be emitted from this high-level representation.
// pub fn emit<T: AsRef<[u8]> + AsMut<[u8]>>(&self, frame: &mut Frame<T>)  [src]
// Emit a high-level representation into an Ethernet II frame.

pub static HINFO_CPU: &'static str = "RFC8482";

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Value<'a> {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    String(String),
    Str(&'a str),
    // AsciiStr(AsciiStr<'a>),
    HINFO {
        cpu: String,        // The CPU field of the HINFO RDATA SHOULD be set to "RFC8482".
        os: Option<String>, // The OS field of the HINFO RDATA SHOULD be set to the null string to minimize the size of the response.
    },
    MX {
        preference: i16,
        exchange: String,
    },
    OPT {
        code: OptionCode,      // EXTENDED-RCODE
        // length: u16,
        // data: &'a [u8],
        value: OptionValue<'a>,
    },
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },
    Raw(&'a [u8]),
}

impl<'a> std::fmt::Display for Value<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            &Self::V4(addr) => std::fmt::Display::fmt(&addr, f),
            &Self::V6(addr) => std::fmt::Display::fmt(&addr, f),
            &Self::String(s) => std::fmt::Display::fmt(&s, f),
            &Self::Str(s) => std::fmt::Display::fmt(s, f),
            &Self::HINFO { ref cpu, ref os } => {
                write!(f, "cpu: {}, os:{}", cpu,
                    match os {
                        Some(ref os) => os,
                        None => "N/A"
                    })
            },
            &Self::MX { preference, exchange } => write!(f, "preference: {}, exchange: {}", preference, exchange),
            &Self::OPT { code, value } => {
                write!(f, "code={}", code)
            },
            &Self::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
                write!(f, "mname: {}, rname: {}, serial: {}, refresh: {}, retry: {}, expire: {}, minimum: {}",
                    mname, rname, serial, refresh, retry, expire, minimum)
            },
            &Self::Raw(data) => write!(f, "{:?}", data),
        }
    }
}

// 3.3. Standard RRs
// https://tools.ietf.org/html/rfc1035#section-3.3
// 
// 
// List_of_DNS_record_types
// https://en.wikipedia.org/wiki/List_of_DNS_record_types

// Apart from the new DNS server and client concepts, 
// DNSSEC introduced to the DNS the following 4 new resource records: DNSKEY, RRSIG, NSEC and DS. 

/// resource record value
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum Record<'a> {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    // DNAME Redirection in the DNS
    // https://tools.ietf.org/html/rfc6672
    DNAME(String),
    // 4.2.  Answer with a Synthesized HINFO RRset
    // https://tools.ietf.org/html/rfc8482#section-4.2
    // 
    // Note: 当客户端发起 Class=ANY 的查询时，必须要要返回该 Record.
    //       
    HINFO {
        cpu: String,        // The CPU field of the HINFO RDATA SHOULD be set to "RFC8482".
        os: Option<String>, // The OS field of the HINFO RDATA SHOULD be set to the null string to minimize the size of the response.
    },
    // https://tools.ietf.org/html/rfc1035#section-3.3.14
    // 
    // Using the Domain Name System To Store Arbitrary String Attributes
    // https://tools.ietf.org/html/rfc1464
    TXT(AsciiStr<'a>),
    // 3.3.9. MX RDATA format
    // https://tools.ietf.org/html/rfc1035#section-3.3.9
    MX {
        preference: i16,
        exchange: String,
    },
    // 3.3.11. NS RDATA format
    // https://tools.ietf.org/html/rfc1035#section-3.3.11
    NS(String),
    
    // 3.3.12. PTR RDATA format
    // https://tools.ietf.org/html/rfc1035#section-3.3.12
    PTR(String),

    // TODO:
    // https://tools.ietf.org/html/rfc4034
    DNSKEY {
        flags: DNSKEYFlags,         // 16 bits
        protocol: DNSKEYProtocol,   //  8 bits
        algorithm: Algorithm,       //  8 bits
        public_key: &'a str,
    },
    RRSIG {
        type_covered: Kind,
        algorithm: Algorithm,       //  8 bits
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: String,
        signature: &'a [u8],
    },
    // 4.  The NSEC Resource Record
    // https://tools.ietf.org/html/rfc4034#page-12
    NSEC {
        next_domain_name: String,
        type_bit_maps: &'a [u8],
    },
    // 3.  The NSEC3 Resource Record
    // https://tools.ietf.org/html/rfc5155#section-3.2
    NSEC3 {
        hash_algorithm: Algorithm,
        // https://tools.ietf.org/html/rfc5155#section-3.2
        // 
        // Flags field is a single octet, the Opt-Out flag is the least
        // significant bit, as shown below:
        // 
        // 0 1 2 3 4 5 6 7
        // +-+-+-+-+-+-+-+-+
        // |             |O|
        // +-+-+-+-+-+-+-+-+
        flags: u8,
        iterations: u16,
        salt_length: u8,
        salt: &'a [u8],
        hash_length: u8,
        // It is the unmodified binary hash value.
        next_hashed_owner_name: &'a [u8],
        // 3.2.1.  Type Bit Maps Encoding
        // https://tools.ietf.org/html/rfc5155#section-3.2.1
        type_bit_maps: &'a [u8],
    },

    // 4.2.  NSEC3PARAM RDATA Wire Format
    // https://tools.ietf.org/html/rfc5155#section-4.2
    NSEC3PARAM {
        hash_algorithm: Algorithm,
        flags: u8,
        iterations: u16,
        salt_length: u8,
        salt: &'a [u8],
    },

    // 5.1.  DS RDATA Wire Format
    // https://tools.ietf.org/html/rfc4034#section-5.1
    DS {
        key_tag: u16,
        algorithm: Algorithm,
        // A.2.  DNSSEC Digest Types
        // https://tools.ietf.org/html/rfc4034#appendix-A.2
        // 2.  Implementing the SHA-256 Algorithm for DS Record Support
        // https://tools.ietf.org/html/rfc4509#section-2
        // 
        // VALUE   Algorithm                 STATUS
        //  0      Reserved                   -
        //  1      SHA-1                   MANDATORY
        // 2-255   Unassigned                 -
        // 
        //  2      SHA-256
        // 
        // A SHA-256 bit digest value calculated by using the following
        // formula ("|" denotes concatenation).  The resulting value is not
        // truncated, and the entire 32 byte result is to be used in the
        // resulting DS record and related calculations.
        // 
        //      digest = SHA_256(DNSKEY owner name | DNSKEY RDATA)
        // 
        // where DNSKEY RDATA is defined by [RFC4034] as:
        // 
        //      DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key
        // 
        digest_type: DigestKind,
        digest: &'a [u8],
    },
        

    // DLV,
    // KEY,
    // KX,
    // CDNSKEY
    // CDS
    // 

    // 6.1.  OPT Record Definition
    // https://tools.ietf.org/html/rfc6891#section-6.1
    // 
    // DNS EDNS0 Option Codes (OPT)
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
    // 
    // https://tools.ietf.org/html/rfc3225#section-3
    OPT {
        // EXTENDED-RCODE
        // ext_rcode: u8,
        code: u16,
        length: u16,
        data: &'a [u8],
    },
    // 
    // 3.3.13. SOA RDATA format
    // https://tools.ietf.org/html/rfc1035#section-3.3.13
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: i32,
        retry: i32,
        expire: i32,
        minimum: u32,
    },

    // A DNS RR for specifying the location of services (DNS SRV)
    // https://tools.ietf.org/html/rfc2782
    // SRV,
    
    Raw(&'a [u8]),
}

impl<'a> Record<'a> {
    pub fn parse(offset: usize,
                 packet: &[u8],
                 kind: Kind,
                 _class: Class,
                 rdata: &'a [u8]) -> Result<Record<'a>, Error> {
        match kind {
            Kind::A => {
                if rdata.len() < 4 {
                    return Err(Error::Truncated);
                }

                let a = rdata[0];
                let b = rdata[1];
                let c = rdata[2];
                let d = rdata[3];

                Ok(Record::A(Ipv4Addr::new(a, b, c, d)))
            },
            Kind::AAAA => {
                if rdata.len() < 16 {
                    return Err(Error::Truncated);
                }

                let mut octets = [0u8; 16];
                &mut octets.copy_from_slice(&rdata[..16]);

                Ok(Record::AAAA(Ipv6Addr::from(octets)))
            },
            Kind::CNAME => {
                let mut cname = String::new();
                let _amt = read_name(offset, packet, &mut cname, 0)?;

                Ok(Record::CNAME(cname))
            },
            Kind::HINFO => {
                // TEST: cargo run --example dig ns3.cloudflare.com:53 cloudflare.com
                const DEFAULT_HINFO: &[u8] = &[7, 82, 70, 67, 56, 52, 56, 50, 0]; // RFC8482
                if rdata != DEFAULT_HINFO {
                    return Err(Error::InvalidHinfoRecord);
                }

                let mut cpu = String::new();
                let _amt = read_name(offset, packet, &mut cpu, 0)?;

                Ok(Record::HINFO { cpu, os: None } )
            },
            Kind::PTR => {
                let mut cname = String::new();
                let _amt = read_name(offset, packet, &mut cname, 0)?;

                Ok(Record::PTR(cname))
            },
            Kind::TXT => {
                Ok(Record::TXT(AsciiStr::new(rdata)))
            },
            Kind::NS => {
                let mut ns = String::new();
                let _amt = read_name(offset, packet, &mut ns, 0)?;
                Ok(Record::NS(ns))
            },
            Kind::MX => {
                let a = rdata[0];
                let b = rdata[1];
                let preference = i16::from_be_bytes([a, b]);

                let mut exchange = String::new();
                let _amt = read_name(offset, packet, &mut exchange, 0)?;

                Ok(Record::MX { preference, exchange })
            },
            Kind::SOA => {
                let mut mname = String::new();
                let amt = read_name(offset, packet, &mut mname, 0)?;

                let mut rname = String::new();
                let amt2 = read_name(offset + amt, packet, &mut rname, 0)?;

                let start = amt + amt2;
                let serial = u32::from_be_bytes([
                    rdata[start + 0],
                    rdata[start + 1],
                    rdata[start + 2],
                    rdata[start + 3],
                ]);

                let start = start + 4;
                let refresh = i32::from_be_bytes([
                    rdata[start + 0],
                    rdata[start + 1],
                    rdata[start + 2],
                    rdata[start + 3],
                ]);

                let start = start + 4;
                let retry = i32::from_be_bytes([
                    rdata[start + 0],
                    rdata[start + 1],
                    rdata[start + 2],
                    rdata[start + 3],
                ]);

                let start = start + 4;
                let expire = i32::from_be_bytes([
                    rdata[start + 0],
                    rdata[start + 1],
                    rdata[start + 2],
                    rdata[start + 3],
                ]);

                let start = start + 4;
                let minimum = u32::from_be_bytes([
                    rdata[start + 0],
                    rdata[start + 1],
                    rdata[start + 2],
                    rdata[start + 3],
                ]);

                Ok(Record::SOA { mname, rname, serial, refresh, retry, expire, minimum })
            },
            Kind::RRSIG => {
                if rdata.len() < 19 {
                    return Err(Error::Truncated);
                }

                let a = packet[offset];
                let b = packet[offset+1];
                let type_covered = Kind(u16::from_be_bytes([a, b]));
                let algorithm = Algorithm(packet[offset+2]);
                let labels = packet[offset+3];
                let original_ttl = u32::from_be_bytes([
                    packet[offset+4],
                    packet[offset+5],
                    packet[offset+6],
                    packet[offset+7],
                ]);
                let signature_expiration = u32::from_be_bytes([
                    packet[offset+8],
                    packet[offset+9],
                    packet[offset+10],
                    packet[offset+11],
                ]);
                let signature_inception = u32::from_be_bytes([
                    packet[offset+12],
                    packet[offset+13],
                    packet[offset+14],
                    packet[offset+15],
                ]);
                let key_tag = u16::from_be_bytes([
                    packet[offset+16],
                    packet[offset+17],
                ]);

                let mut signer_name = String::new();
                let _amt = read_name(offset+18, packet, &mut signer_name, 0)?;
                
                if rdata.len() < 19 + _amt {
                    return Err(Error::Truncated);
                }

                let signature = &rdata[18+_amt..];

                Ok(Record::RRSIG {
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
            Kind::DS => {
                if rdata.len() < 5 {
                    return Err(Error::Truncated);
                }

                let key_tag = u16::from_be_bytes([packet[offset], packet[offset+1]]);
                let algorithm = Algorithm(packet[offset+2]);
                // 1      SHA-1                   MANDATORY
                // 2      SHA-256
                let digest_type = DigestKind(packet[offset+3]);
                let digest = &rdata[4..];

                Ok(Record::DS {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                })
            },
            Kind::NSEC => {
                let mut next_domain_name = String::new();
                let _amt = read_name(offset, packet, &mut next_domain_name, 0)?;
                if rdata.len() < _amt {
                    return Err(Error::Truncated);
                }
                let type_bit_maps = &rdata[_amt..];

                Ok(Record::NSEC {
                    next_domain_name,
                    type_bit_maps,
                })
            },
            Kind::NSEC3 => {
                if rdata.len() < 6 {
                    return Err(Error::Truncated);
                }

                let hash_algorithm = Algorithm(packet[offset]);
                let flags = packet[offset+1];
                let iterations = u16::from_be_bytes([packet[offset+2], packet[offset+3]]);
                let salt_length = packet[offset+4];

                let salt_end = 5 + salt_length as usize;
                if rdata.len() < salt_end + 1 {
                    return Err(Error::Truncated);
                }
                let salt = &rdata[5..salt_end];
                
                let hash_length = rdata[salt_end];
                let hash_start = salt_end + 1;
                let hash_end = hash_start + hash_length as usize;
                if rdata.len() < hash_end + 1 {
                    return Err(Error::Truncated);
                }
                let next_hashed_owner_name = &rdata[hash_start..hash_end];
                let type_bit_maps = &rdata[hash_end+1..];

                Ok(Record::NSEC3 {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt_length,
                    salt,
                    hash_length,
                    next_hashed_owner_name,
                    type_bit_maps,
                })
            },
            Kind::NSEC3PARAM => {
                if rdata.len() < 6 {
                    return Err(Error::Truncated);
                }

                let hash_algorithm = Algorithm(packet[offset]);
                let flags = packet[offset+1];
                let iterations = u16::from_be_bytes([packet[offset+2], packet[offset+3]]);
                let salt_length = packet[offset+4];
                let salt = &rdata[5..];

                Ok(Record::NSEC3PARAM {
                    hash_algorithm,
                    flags,
                    iterations,
                    salt_length,
                    salt
                })
            },
            _ => Ok(Record::Raw(rdata)),
        }
    }
}


    
    

impl<'a> std::fmt::Display for Record<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            &Self::A(addr) => std::fmt::Display::fmt(&addr, f),
            &Self::AAAA(addr) => std::fmt::Display::fmt(&addr, f),
            &Self::CNAME(s) => std::fmt::Display::fmt(&s, f),
            &Self::DNAME(s) => std::fmt::Display::fmt(&s, f),
            &Self::TXT(s) => std::fmt::Display::fmt(s, f),
            &Self::NS(s) => std::fmt::Display::fmt(s, f),
            &Self::PTR(s) => std::fmt::Display::fmt(s, f),
            &Self::HINFO { ref cpu, ref os } => {
                write!(f, "cpu: {}, os:{}", cpu,
                    match os {
                        Some(ref os) => os,
                        None => "N/A"
                    })
            },
            &Self::MX { preference, exchange } => write!(f, "preference: {}, exchange: {}", preference, exchange),
            &Self::SOA { mname, rname, serial, refresh, retry, expire, minimum } => {
                write!(f, "mname: {}, rname: {}, serial: {}, refresh: {}, retry: {}, expire: {}, minimum: {}",
                    mname, rname, serial, refresh, retry, expire, minimum)
            },
            &Self::Raw(data) => write!(f, "{:?}", data),
            &Self::DNSKEY { flags, protocol, algorithm, public_key } => {
                write!(f, "flags: {}, protocol: {}, algorithm: {}, public_key: {}", flags, protocol, algorithm, public_key)
            },
            &Self::RRSIG { type_covered, algorithm, labels, original_ttl, signature_expiration, signature_inception, key_tag, signer_name, signature } => {
                write!(f, "type_covered: {}, algorithm: {}, labels: {}, original_ttl: {}, signature_expiration: {}, signature_inception: {}, key_tag: {}, signer_name: {}, signature: {:?}",
                    type_covered, algorithm, labels, original_ttl, signature_expiration, signature_inception, 
                    key_tag, signer_name, hexdigest(signature))
            },
            &Self::NSEC { next_domain_name, type_bit_maps } => {
                write!(f, "next_domain_name: {}, type_bit_maps: {:?}", next_domain_name, hexdigest(type_bit_maps))
            },
            &Self::NSEC3 { hash_algorithm, flags, iterations, salt_length, salt, hash_length, next_hashed_owner_name, type_bit_maps} => {
                write!(f, "hash_algorithm: {}, flags: {}, iterations: {}, salt_length: {}, salt: {:?}, hash_length: {}, next_hashed_owner_name: {:?}, type_bit_maps: {:?}",
                hash_algorithm, flags, iterations, salt_length, hexdigest(salt), hash_length,
                hexdigest(next_hashed_owner_name),
                hexdigest(type_bit_maps))
            },
            &Self::NSEC3PARAM { hash_algorithm, flags, iterations, salt_length, salt } => {
                write!(f, "hash_algorithm: {}, flags: {}, iterations: {}, salt_length: {}, salt: {:?}",
                hash_algorithm, flags, iterations, salt_length, salt)
            },
            &Self::DS { key_tag, algorithm, digest_type, digest } => {
                write!(f, "key_tag: {}, algorithm: {}, digest_type: {}, digest: {:?}",
                    key_tag, algorithm, digest_type, hexdigest(digest))
            },
            _ => write!(f, "{:?}", self)
        }
    }
}

fn hexdigest(digest: &[u8]) -> String {
    let mut s = String::from("0x");
    for n in digest.iter() {
        s.push_str(format!("{:02x}", n).as_ref());
    }
    s
}