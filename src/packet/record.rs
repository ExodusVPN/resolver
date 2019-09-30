use crate::error::Error;
// use crate::packet::question::Labels;
use crate::packet::Kind;
use crate::packet::Class;

use std::net::{Ipv4Addr, Ipv6Addr};


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
    CNAME(&'a str),
    TXT(&'a str),
    // 3.3.9. MX RDATA format
    // https://tools.ietf.org/html/rfc1035#section-3.3.9
    MX {
        preference: i16,
        exchange: &'a str,
    },
    // 3.3.11. NS RDATA format
    // https://tools.ietf.org/html/rfc1035#section-3.3.11
    NS(&'a str),
    
    // TODO:
    // NSEC,
    // https://tools.ietf.org/html/rfc4034
    // DNSKEY(),
    // OPT(),
    // SOA(),
    // SRV,
    Raw {
        kind: Kind,
        class: Class,
        data: &'a [u8],
    }
}

impl<'a> Record<'a> {
    pub fn parse(kind: Kind,
                 _class: Class,
                 rdata: &'a [u8]) -> Result<Option<Record<'a>>, Error> {
        match kind {
            Kind::A => {
                if rdata.len() < 4 {
                    return Err(Error::Truncated);
                }

                let a = rdata[0];
                let b = rdata[1];
                let c = rdata[2];
                let d = rdata[3];

                Ok(Some(Record::A(Ipv4Addr::new(a, b, c, d))))
            },
            Kind::AAAA => {
                if rdata.len() < 16 {
                    return Err(Error::Truncated);
                }

                let mut octets = [0u8; 16];
                &mut octets.copy_from_slice(&rdata[..16]);

                Ok(Some(Record::AAAA(Ipv6Addr::from(octets))))
            },
            Kind::CNAME => {
                // TODO:
                //      1. check MAXIMUM_LABEL_SIZE
                //      2. check MAXIMUM_NAMES_SIZE
                //      3. check utf8
                // let labels = Labels { offset: 0, data: rdata };
                // Ok(Some(Record::CNAME(labels)))

                unimplemented!();
            },
            _ => Ok(None),
        }
    }
}
