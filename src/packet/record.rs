use crate::error::Error;

use crate::packet::Kind;
use crate::packet::Class;
use crate::packet::Flags;
use crate::packet::read_name;
use crate::packet::OptionCode;
use crate::packet::AddressFamily;
use crate::packet::DNSKEYProtocol;
use crate::packet::DNSKEYFlags;
use crate::packet::Algorithm;

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
pub enum Value<'a> {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    String(String),
    Str(&'a str),
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
    TXT(&'a str),
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
    },
    RRSIG {
        type_covered: u16,
        algorithm: Algorithm,       //  8 bits
        labels: u8,
        original_ttl: u32,
        signature_expiration: u32,
        signature_inception: u32,
        key_tag: u16,
        signer_name: &'a str,
        signature: &'a [u8],
    },
    // 4.  The NSEC Resource Record
    // https://tools.ietf.org/html/rfc4034#page-12
    // NSEC,
    // 3.  The NSEC3 Resource Record
    // https://tools.ietf.org/html/rfc5155#section-3.2
    NSEC3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt_length: u8,
        salt: u32,
        hash_length: u8,
        next_hashed_owner_name: &'a str,
        // type_bit_maps: 
    },
    // DS,
    

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
            _ => Ok(Record::Raw(rdata)),
        }
    }
}
