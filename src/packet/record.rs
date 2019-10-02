use crate::error::Error;

use crate::packet::Kind;
use crate::packet::Class;
use crate::packet::Flags;
use crate::packet::read_name;

use std::net::{Ipv4Addr, Ipv6Addr};


pub struct Question {
    pub name: String,
    pub kind: Kind,
    pub class: Class,
}

pub struct Answer<'a> {
    pub name: String,
    pub kind: Kind,
    pub class: Class,
    pub ttl: u32,
    pub value: Record<'a>
}


pub struct Request {
    pub id: u16,
    pub flags: Flags,
    pub questions: Vec<Question>,
}

pub struct Response<'a> {
    pub id: u16,
    pub flags: Flags,
    pub questions: Vec<Question>,
    pub answers: Vec<Answer<'a>>,
    pub authorities: Vec<Answer<'a>>,
    pub additionals: Vec<Answer<'a>>,
}


// 3.3. Standard RRs
// https://tools.ietf.org/html/rfc1035#section-3.3
// 
// 
// List_of_DNS_record_types
// https://en.wikipedia.org/wiki/List_of_DNS_record_types

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
    // RRSIG,
    // DNSKEY(),
    // DS,
    // NSEC,
    // NSEC3
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
