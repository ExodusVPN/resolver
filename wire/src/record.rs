use crate::error::Error;
use crate::error::ErrorKind;
use crate::kind::Kind;
use crate::class::Class;
use crate::dnssec;
use crate::edns;
use crate::ser::Serializer;
use crate::ser::Serialize;
use crate::de::Deserializer;
use crate::de::Deserialize;

use base64;

use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;


#[derive(PartialEq, Eq, Clone)]
pub struct Digest<T: AsRef<[u8]>> {
    inner: T
}

impl<T: AsRef<[u8]>> Digest<T> {
    #[inline]
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_ref()
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.inner
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.as_bytes().len()
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Digest<T> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<T: AsRef<[u8]>> std::fmt::Debug for Digest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self.as_ref())
    }
}

impl<T: AsRef<[u8]>> crate::fmt::Base64 for Digest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let digest = self.as_ref();
        let s = base64::encode(digest);
        f.write_str(&s)
    }
}

impl<T: AsRef<[u8]>> std::fmt::LowerHex for Digest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = self.as_bytes();
        if data.len() > 0 {
            if f.alternate() {
                f.write_str("0x")?;
            }

            for n in data.iter() {
                write!(f, "{:02x}", n)?;
            }
        }
        
        Ok(())
    }
}

impl<T: AsRef<[u8]>> std::fmt::UpperHex for Digest<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let data = self.as_bytes();
        if data.len() > 0 {
            if f.alternate() {
                f.write_str("0x")?;
            }

            for n in data.iter() {
                write!(f, "{:02X}", n)?;
            }
        }

        Ok(())
    }
}


// 4.1.3. Resource record format
// https://tools.ietf.org/html/rfc1035#section-4.1.3
// 
// The answer, authority, and additional sections all share the same
// format: a variable number of resource records, where the number of
// records is specified in the corresponding count field in the header.
// Each resource record has the following format:
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                                               /
//     /                      NAME                     /
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     CLASS                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      TTL                      |
//     |                                               |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                   RDLENGTH                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
//     /                     RDATA                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 
// where:
// 
// NAME            a domain name to which this resource record pertains.
// 
// TYPE            two octets containing one of the RR type codes.  This
//                 field specifies the meaning of the data in the RDATA
//                 field.
// 
// CLASS           two octets which specify the class of the data in the
//                 RDATA field.
// 
// TTL             a 32 bit unsigned integer that specifies the time
//                 interval (in seconds) that the resource record may be
//                 cached before it should be discarded.  Zero values are
//                 interpreted to mean that the RR can only be used for the
//                 transaction in progress, and should not be cached.
// 
// RDLENGTH        an unsigned 16 bit integer that specifies the length in
//                 octets of the RDATA field.
// 
// RDATA           a variable length string of octets that describes the
//                 resource.  The format of this information varies
//                 according to the TYPE and CLASS of the resource record.
//                 For example, the if the TYPE is A and the CLASS is IN,
//                 the RDATA field is a 4 octet ARPA Internet address.

// 
// Extension Mechanisms for DNS (EDNS(0))
// 
// 6.1.  OPT Record Definition
// https://tools.ietf.org/html/rfc6891#section-6.1
// 
//    An OPT RR has a fixed part and a variable set of options expressed as
//    {attribute, value} pairs.  The fixed part holds some DNS metadata,
//    and also a small collection of basic extension elements that we
//    expect to be so popular that it would be a waste of wire space to
//    encode them as {attribute, value} pairs.
// 
//    The fixed part of an OPT RR is structured as follows:
// 
//        +------------+--------------+------------------------------+
//        | Field Name | Field Type   | Description                  |
//        +------------+--------------+------------------------------+
//        | NAME       | domain name  | MUST be 0 (root domain)      |
//        | TYPE       | u_int16_t    | OPT (41)                     |
//        | CLASS      | u_int16_t    | requestor's UDP payload size |
//        | TTL        | u_int32_t    | extended RCODE and flags     |
//        | RDLEN      | u_int16_t    | length of all RDATA          |
//        | RDATA      | octet stream | {attribute,value} pairs      |
//        +------------+--------------+------------------------------+
// 
//                                OPT RR Format
// 
// 
// 6.1.3.  OPT Record TTL Field Use
// 
//    The extended RCODE and flags, which OPT stores in the RR Time to Live
//    (TTL) field, are structured as follows:
// 
//                   +0 (MSB)                            +1 (LSB)
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//     0: |         EXTENDED-RCODE        |            VERSION            |
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//     2: | DO|                           Z                               |
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 
//    EXTENDED-RCODE
//       Forms the upper 8 bits of extended 12-bit RCODE (together with the
//       4 bits defined in [RFC1035].  Note that EXTENDED-RCODE value 0
//       indicates that an unextended RCODE is in use (values 0 through
//       15).
// 
//    VERSION
//       Indicates the implementation level of the setter.  Full
//       conformance with this specification is indicated by version '0'.
//       Requestors are encouraged to set this to the lowest implemented
//       level capable of expressing a transaction, to minimise the
//       responder and network load of discovering the greatest common
//       implementation level between requestor and responder.  A
//       requestor's version numbering strategy MAY ideally be a run-time
//       configuration option.
//       If a responder does not implement the VERSION level of the
//       request, then it MUST respond with RCODE=BADVERS.  All responses
//       MUST be limited in format to the VERSION level of the request, but
//       the VERSION of each response SHOULD be the highest implementation
//       level of the responder.  In this way, a requestor will learn the
//       implementation level of a responder as a side effect of every
//       response, including error responses and including RCODE=BADVERS.
// 
// 6.1.4.  Flags
// 
//    DO
//       DNSSEC OK bit as defined by [RFC3225].
// 
//    Z
//       Set to zero by senders and ignored by receivers, unless modified
//       in a subsequent specification.
// 

// 
//    The variable part of an OPT RR may contain zero or more options in
//    the RDATA.  Each option MUST be treated as a bit field.  Each option
//    is encoded as:
// 
//                   +0 (MSB)                            +1 (LSB)
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//     0: |                          OPTION-CODE                          |
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//     2: |                         OPTION-LENGTH                         |
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//     4: |                                                               |
//        /                          OPTION-DATA                          /
//        /                                                               /
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 
//    OPTION-CODE
//       Assigned by the Expert Review process as defined by the DNSEXT
//       working group and the IESG.
// 
//    OPTION-LENGTH
//       Size (in octets) of OPTION-DATA.
// 
//    OPTION-DATA
//       Varies per OPTION-CODE.  MUST be treated as a bit field.
// 
//    The order of appearance of option tuples is not defined.  If one
//    option modifies the behaviour of another or multiple options are
//    related to one another in some way, they have the same effect
//    regardless of ordering in the RDATA wire encoding.
// 
//    Any OPTION-CODE values not understood by a responder or requestor
//    MUST be ignored.  Specifications of such options might wish to
//    include some kind of signaled acknowledgement.  For example, an
//    option specification might say that if a responder sees and supports
//    option XYZ, it MUST include option XYZ in its response.
// 

// 
// 
// Client Subnet in DNS Queries
// 
// 6.  Option Format
// https://tools.ietf.org/html/rfc7871#section-6
// 
//                 +0 (MSB)                            +1 (LSB)
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    0: |                          OPTION-CODE                          |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    2: |                         OPTION-LENGTH                         |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    4: |                            FAMILY                             |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    6: |     SOURCE PREFIX-LENGTH      |     SCOPE PREFIX-LENGTH       |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    8: |                           ADDRESS...                          /
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 
// The format of the address part depends on the value of FAMILY.  This
// document only defines the format for FAMILY 1 (IPv4) and FAMILY 2 (IPv6).
// 

macro_rules! rr {
    ($name:ident, $($element: ident: $ty: ty),*) => {
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $name {
            pub name: String,
            pub class: Class,
            pub ttl: u32,
            $(pub $element: $ty),*  // RDATA
        }

        impl $name {
            pub const KIND: Kind = Kind::$name;

            #[inline]
            pub const fn kind(&self) -> Kind {
                Self::KIND
            }
        }
    };
}


rr! { A,
    value: Ipv4Addr
}
rr! { AAAA,
    value: Ipv6Addr
}
rr! { NS,
    value: String
}
rr! { CNAME,
    value: String
}
rr! { DNAME,
    value: String
}
rr! { TXT,
    value: String
}
rr! { MX,
    preference: i16,
    exchange: String
}
rr! {
    SOA,
    mname: String,
    rname: String,
    serial: u32,
    refresh: i32,
    retry: i32,
    expire: i32,
    minimum: u32
}

// ===== DNSSEC ======
rr! { DNSKEY,
    flags: dnssec::DNSKEYFlags,         // 16 bits
    protocol: dnssec::DNSKEYProtocol,   //  8 bits
    algorithm: dnssec::Algorithm,       //  8 bits
    public_key: Digest<Vec<u8>>
}

rr! { RRSIG,
    type_covered: Kind,
    algorithm: dnssec::Algorithm,       //  8 bits
    labels: u8,
    original_ttl: u32,
    signature_expiration: u32,
    signature_inception: u32,
    key_tag: u16,
    signer_name: String,
    signature: Digest<Vec<u8>>
}

rr! { NSEC,
    next_domain_name: String,
    type_bit_maps: Vec<Kind>
}

rr! { NSEC3,
    hash_algorithm: dnssec::Algorithm,  // 8 bits
    flags: dnssec::NSEC3Flags,          // 8 bits
    iterations: u16,
    // salt_length: u8,
    salt: Digest<Vec<u8>>,
    // hash_length: u8,
    next_hashed_owner_name: Digest<Vec<u8>>, // It is the unmodified binary hash value.
    type_bit_maps: Vec<Kind>
}

rr! { NSEC3PARAM,
    hash_algorithm: dnssec::Algorithm, // 8 bits
    flags: u8,
    iterations: u16,
    // salt_length: u8,
    salt: Digest<Vec<u8>>
}

rr! { DS,
    key_tag: u16,
    algorithm: dnssec::Algorithm,
    digest_type: dnssec::DigestKind,
    digest: Digest<Vec<u8>>
}

// 5.1.1.  Canonical Presentation Format
// https://tools.ietf.org/html/rfc6844#section-5.1.1
rr! { CAA,
    // Is an unsigned integer between 0 and 255.
    // 
    // 7.3.  Certification Authority Restriction Flags
    // https://tools.ietf.org/html/rfc6844#section-7.3
    // 
    // Flag         Meaning                            Reference
    // -----------  ---------------------------------- ---------
    // 0            Issuer Critical Flag               [RFC6844]
    // 1-7          Reserved>                          [RFC6844]
    flags: u8,
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
    tag: String,
    // Is the <character-string> encoding of the value field as specified in [RFC1035], Section 5.1.
    value: String
}


#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ClientSubnet {
    pub src_prefix_len: u8,
    pub scope_prefix_len: u8,
    pub address: IpAddr,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum OptAttr {
    ECS(ClientSubnet),
}

// ======= pseudo resource records ========
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct OPT {
    pub name: String,           // MUST be 0 (root domain)
    pub udp_size: u16,          // requestor's UDP payload size
    pub rcode: u8,              // extended RCODE，高 8 位, 低 4 位在 DNS MESSAGE HEADER 里面。
    pub version: u8,            // version
    pub flags: edns::EDNSFlags, // flags
    pub attrs: Vec<OptAttr>,    // RDATA
}

impl OPT {
    pub const KIND: Kind = Kind::OPT;

    #[inline]
    pub const fn kind(&self) -> Kind {
        Self::KIND
    }
}



#[derive(PartialEq, Eq, Clone)]
pub enum Record {
    A(A),
    AAAA(AAAA),
    NS(NS),
    CNAME(CNAME),
    DNAME(DNAME),
    TXT(TXT),
    MX(MX),
    SOA(SOA),

    DNSKEY(DNSKEY),
    RRSIG(RRSIG),
    NSEC(NSEC),
    NSEC3(NSEC3),
    NSEC3PARAM(NSEC3PARAM),
    DS(DS),

    CAA(CAA),

    OPT(OPT),
    // ALL(ALL),
    // AXFR,
    // IXFR

    // NOTE: 这些不再被使用的资源类型，支持一下也许更好？
    // PTR
    // SRV
    // SSHFP
    // SPF
    // 
}

impl Record {
    pub fn kind(&self) -> Kind {
        match self {
            Self::A(inner) => inner.kind(),
            Self::AAAA(inner) => inner.kind(),
            Self::NS(inner) => inner.kind(),
            Self::CNAME(inner) => inner.kind(),
            Self::DNAME(inner) => inner.kind(),
            Self::TXT(inner) => inner.kind(),
            Self::MX(inner) => inner.kind(),
            Self::SOA(inner) => inner.kind(),

            Self::DNSKEY(inner) => inner.kind(),
            Self::RRSIG(inner) => inner.kind(),
            Self::NSEC(inner) => inner.kind(),
            Self::NSEC3(inner) => inner.kind(),
            Self::NSEC3PARAM(inner) => inner.kind(),
            Self::DS(inner) => inner.kind(),

            Self::CAA(inner) => inner.kind(),

            Self::OPT(inner) => inner.kind(),
        }
    }

    pub fn is_pseudo_record(&self) -> bool {
        match self {
            Self::OPT(_) => true,
            _ => false,
        }
    }
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::A(inner) => std::fmt::Debug::fmt(inner, f),
            Self::AAAA(inner) => std::fmt::Debug::fmt(inner, f),
            Self::NS(inner) => std::fmt::Debug::fmt(inner, f),
            Self::CNAME(inner) => std::fmt::Debug::fmt(inner, f),
            Self::DNAME(inner) => std::fmt::Debug::fmt(inner, f),
            Self::TXT(inner) => std::fmt::Debug::fmt(inner, f),
            Self::MX(inner) => std::fmt::Debug::fmt(inner, f),
            Self::SOA(inner) => std::fmt::Debug::fmt(inner, f),

            Self::DNSKEY(inner) => std::fmt::Debug::fmt(inner, f),
            Self::RRSIG(inner) => std::fmt::Debug::fmt(inner, f),
            Self::NSEC(inner) => std::fmt::Debug::fmt(inner, f),
            Self::NSEC3(inner) => std::fmt::Debug::fmt(inner, f),
            Self::NSEC3PARAM(inner) => std::fmt::Debug::fmt(inner, f),
            Self::DS(inner) => std::fmt::Debug::fmt(inner, f),

            Self::CAA(inner) => std::fmt::Debug::fmt(inner, f),

            Self::OPT(inner) => std::fmt::Debug::fmt(inner, f),
        }
    }
}


impl Deserialize for Record {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let name = String::deserialize(deserializer)?;
        let kind = Kind(u16::deserialize(deserializer)?);

        #[inline]
        fn deserialize_normal_rr(deserializer: &mut Deserializer) -> Result<(Class, u32, u16), io::Error> {
            let class = Class(u16::deserialize(deserializer)?);
            let ttl = u32::deserialize(deserializer)?;
            let rdlen = u16::deserialize(deserializer)?;

            Ok((class, ttl, rdlen))
        }

        match kind {
            Kind::A => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let value = std::net::Ipv4Addr::deserialize(deserializer)?;

                Ok(Record::A(A { name, class, ttl, value }))
            },
            Kind::AAAA => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let value = std::net::Ipv6Addr::deserialize(deserializer)?;
                
                Ok(Record::AAAA(AAAA { name, class, ttl, value }))
            },
            Kind::NS => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let value = String::deserialize(deserializer)?;
                
                Ok(Record::NS(NS { name, class, ttl, value }))
            },
            Kind::CNAME => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let value = String::deserialize(deserializer)?;
                
                Ok(Record::CNAME(CNAME { name, class, ttl, value }))
            },
            Kind::DNAME => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let value = String::deserialize(deserializer)?;
                
                Ok(Record::DNAME(DNAME { name, class, ttl, value }))
            },
            Kind::TXT => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let buffer = deserializer.get_ref();
                let start = deserializer.position();
                let end = start + rdlen as usize;
                match buffer.get(start..end) {
                    Some(rdata) => {
                        let value = (&rdata).iter().map(|b| *b as char).collect::<String>();

                        Ok(Record::TXT(TXT { name, class, ttl, value }))
                    },
                    None => {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                    }
                }
            },
            Kind::MX => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let preference = i16::deserialize(deserializer)?;
                let exchange = String::deserialize(deserializer)?;

                Ok(Record::MX(MX { name, class, ttl, preference, exchange }))
            },
            Kind::SOA => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let mname = String::deserialize(deserializer)?;
                let rname = String::deserialize(deserializer)?;
                let serial = u32::deserialize(deserializer)?;
                let refresh = i32::deserialize(deserializer)?;
                let retry = i32::deserialize(deserializer)?;
                let expire = i32::deserialize(deserializer)?;
                let minimum = u32::deserialize(deserializer)?;

                Ok(Record::SOA(SOA { name, class, ttl, mname, rname, serial, refresh, retry, expire, minimum }))
            },
            Kind::OPT => {
                let udp_size = kind.0;

                let rcode = u8::deserialize(deserializer)?;
                let version = u8::deserialize(deserializer)?;

                if version != edns::EDNS_V0 {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid EDNS version(must be 0)."));
                }

                let flags = edns::EDNSFlags::new_unchecked(u16::deserialize(deserializer)?);
                let mut rdlen = u16::deserialize(deserializer)?;
                let mut attrs: Vec<OptAttr> = Vec::new();
                while rdlen > 4 {
                    let opt_code = edns::OptionCode(u16::deserialize(deserializer)?);
                    let opt_len = u16::deserialize(deserializer)?;

                    if opt_code == edns::OptionCode::EDNS_CLIENT_SUBNET {
                        let address_family = edns::AddressFamily(u16::deserialize(deserializer)?);
                        let src_prefix_len = u8::deserialize(deserializer)?;
                        let scope_prefix_len = u8::deserialize(deserializer)?;

                        let address = if address_family == edns::AddressFamily::IPV4 {
                            std::net::IpAddr::V4(std::net::Ipv4Addr::deserialize(deserializer)?)
                        } else if address_family == edns::AddressFamily::IPV6 {
                            std::net::IpAddr::V6(std::net::Ipv6Addr::deserialize(deserializer)?)
                        } else {
                            return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid EDNS Client Subnet AddressFamily."));
                        };

                        attrs.push(OptAttr::ECS(ClientSubnet { src_prefix_len, scope_prefix_len, address }));
                    } else {
                        debug!("EDNS Attribute is droped. OptCode={:?} OptLen={:?}", opt_code, opt_len);
                        deserializer.set_position(deserializer.position() + opt_len as usize);
                    }

                    rdlen -= opt_len;
                }

                Ok(Record::OPT(OPT { name, udp_size, rcode, version, flags, attrs }))
            },

            // ===== DNSSEC ======
            Kind::DNSKEY => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let flags = dnssec::DNSKEYFlags::new_unchecked(u16::deserialize(deserializer)?);
                let protocol = dnssec::DNSKEYProtocol(u8::deserialize(deserializer)?);
                let algorithm = dnssec::Algorithm(u8::deserialize(deserializer)?);
                
                let buf = deserializer.get_ref();
                let start = deserializer.position();
                let end = start + rdlen as usize;
                match buf.get(start..end) {
                    Some(rdata) => {
                        let public_key = Digest::new(rdata.to_vec());
                        Ok(Record::DNSKEY(DNSKEY { name, class, ttl, flags, protocol, algorithm, public_key }))
                    },
                    None => {
                        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"))
                    }
                }
            },
            Kind::RRSIG => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let type_covered = Kind(u16::deserialize(deserializer)?);
                let algorithm = dnssec::Algorithm(u8::deserialize(deserializer)?);
                let labels = u8::deserialize(deserializer)?;
                let original_ttl = u32::deserialize(deserializer)?;
                let signature_expiration = u32::deserialize(deserializer)?;
                let signature_inception = u32::deserialize(deserializer)?;
                let key_tag = u16::deserialize(deserializer)?;
                let signer_name = String::deserialize(deserializer)?;

                let buf = deserializer.get_ref();
                let start = deserializer.position();
                let end = start + rdlen as usize;
                match buf.get(start..end) {
                    Some(rdata) => {
                        let signature = Digest::new(rdata.to_vec());
                        Ok(Record::RRSIG(RRSIG {
                            name,
                            class,
                            ttl,
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
                    None => {
                        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"))
                    }
                }
            },
            Kind::NSEC => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let name_pos = deserializer.position();
                let next_domain_name = String::deserialize(deserializer)?;
                let name_amt = deserializer.position() - name_pos;
                
                match (rdlen as usize).checked_sub(name_amt) {
                    Some(len) => {
                        let type_bit_maps = crate::de::read_type_bit_maps(deserializer, len)?;

                        Ok(Record::NSEC(NSEC { name, class, ttl, next_domain_name, type_bit_maps, }))
                    },
                    None => {
                        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"))
                    },
                }
            },
            Kind::NSEC3 => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;

                let rdata_pos = deserializer.position();
                let hash_algorithm = dnssec::Algorithm(u8::deserialize(deserializer)?);
                let flags = dnssec::NSEC3Flags::new_unchecked(u8::deserialize(deserializer)?);
                let iterations = u16::deserialize(deserializer)?;

                let salt_length = u8::deserialize(deserializer)?;
                let buf = deserializer.get_ref();
                let start = deserializer.position();
                let end = start + salt_length as usize;
                let salt_data = buf.get(start..end);

                if salt_data.is_none() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                }

                let salt = Digest::new(salt_data.unwrap().to_vec());

                let hash_length = u8::deserialize(deserializer)?;
                let buf = deserializer.get_ref();
                let start = deserializer.position();
                let end = start + hash_length as usize;
                let hash_data = buf.get(start..end);
                if hash_data.is_none() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                }
                let next_hashed_owner_name = Digest::new(hash_data.unwrap().to_vec());

                let amt = deserializer.position() - rdata_pos;
                match (rdlen as usize).checked_sub(amt) {
                    Some(len) => {
                        let type_bit_maps = crate::de::read_type_bit_maps(deserializer, len)?;

                        Ok(Record::NSEC3(NSEC3 {
                            name,
                            class,
                            ttl,
                            hash_algorithm,
                            flags,
                            iterations,
                            salt,
                            next_hashed_owner_name,
                            type_bit_maps,
                        }))
                    },
                    None => {
                        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"))
                    }
                }
            },
            Kind::NSEC3PARAM => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let hash_algorithm = dnssec::Algorithm(u8::deserialize(deserializer)?);
                let flags = u8::deserialize(deserializer)?;
                let iterations = u16::deserialize(deserializer)?;
                
                let salt_length = u8::deserialize(deserializer)?;
                let buf = deserializer.get_ref();
                let start = deserializer.position();
                let end = start + salt_length as usize;
                let salt_data = buf.get(start..end);

                if salt_data.is_none() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                }

                let salt = Digest::new(salt_data.unwrap().to_vec());

                Ok(Record::NSEC3PARAM(NSEC3PARAM { name, class, ttl, hash_algorithm, flags, iterations, salt, }))
            },
            Kind::DS => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;

                let rdata_pos = deserializer.position();

                let key_tag = u16::deserialize(deserializer)?;
                let algorithm = dnssec::Algorithm(u8::deserialize(deserializer)?);
                let digest_type = dnssec::DigestKind(u8::deserialize(deserializer)?);

                let amt = deserializer.position() - rdata_pos;

                match (rdlen as usize).checked_sub(amt) {
                    Some(len) => {
                        let buf = deserializer.get_ref();
                        let start = deserializer.position();
                        let end = start + len as usize;
                        let digest_data = buf.get(start..end);

                        if digest_data.is_none() {
                            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                        }

                        let digest = Digest::new(digest_data.unwrap().to_vec());

                        Ok(Record::DS(DS {
                            name,
                            class,
                            ttl,
                            key_tag,
                            algorithm,
                            digest_type,
                            digest,
                        }))
                    },
                    None => {
                        Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"))
                    }
                }
            },
            Kind::CAA => {
                let (class, ttl, rdlen) = deserialize_normal_rr(deserializer)?;
                let flags = u8::deserialize(deserializer)?;
                let tag_len = u8::deserialize(deserializer)?;

                let buf = deserializer.get_ref();
                let start = deserializer.position();
                let end = start + tag_len as usize;
                let tag_data = buf.get(start..end);

                if tag_data.is_none() {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                }

                let tag = tag_data.unwrap().iter().map(|b| *b as char).collect::<String>();

                let buf = deserializer.get_ref();
                let start = deserializer.position();
                match (rdlen as usize).checked_sub(2 + tag_len as usize) {
                    Some(len) => {
                        let end = start + len;
                        let value_data = buf.get(start..end);

                        if value_data.is_none() {
                            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                        }
                        
                        let value = value_data.unwrap().iter().map(|b| *b as char).collect::<String>();

                        Ok(Record::CAA(CAA { name, class, ttl, flags, tag, value, }))
                    },
                    None => {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer"));
                    }
                }
            },
            _ => {
                unimplemented!()
            }
        }
    }
}


fn write_rdlen(serializer: &mut Serializer, rdlen_pos: usize) -> Result<(), io::Error> {
    let rdlen = serializer.position() - rdlen_pos - 2;
    if rdlen > std::u16::MAX as usize {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid rdlen."));
    }

    let rdlen_bytes = (rdlen as u16).to_be_bytes();
    let buffer = serializer.get_mut();

    buffer[rdlen_pos] = rdlen_bytes[0];
    buffer[rdlen_pos + 1] = rdlen_bytes[1];

    Ok(())
}

impl Serialize for Record {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {

        macro_rules! serialize_normal_rr {
            ($rr:ident, $stmt:stmt) => {
                $rr.name.serialize(serializer)?;
                $rr.kind().0.serialize(serializer)?;
                $rr.class.0.serialize(serializer)?;
                $rr.ttl.serialize(serializer)?;

                let rdlen_pos = serializer.position();
                0u16.serialize(serializer)?;           // RDLEN
                $stmt
                write_rdlen(serializer, rdlen_pos)?;
            }
        }

        match self {
            &Record::A(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.value.serialize(serializer)?;
                });
            },
            &Record::AAAA(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.value.serialize(serializer)?;
                });
            },
            &Record::NS(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.value.serialize(serializer)?;
                });
            },
            &Record::CNAME(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.value.serialize(serializer)?;
                });
            },
            &Record::DNAME(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.value.serialize(serializer)?;
                });
            },
            &Record::TXT(ref rr) => {
                serialize_normal_rr!(rr, {
                    if !rr.value.is_ascii() {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid txt string(must be ASCII)."));
                    }
                    rr.value.as_bytes().serialize(serializer)?;
                });
            },
            &Record::MX(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.preference.serialize(serializer)?;
                    rr.exchange.serialize(serializer)?;
                });
            },
            &Record::SOA(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.mname.serialize(serializer)?;
                    rr.rname.serialize(serializer)?;
                    rr.serial.serialize(serializer)?;
                    rr.refresh.serialize(serializer)?;
                    rr.retry.serialize(serializer)?;
                    rr.expire.serialize(serializer)?;
                    rr.minimum.serialize(serializer)?;
                });
            },
            &Record::OPT(ref rr) => {
                if !rr.name.is_empty() {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid DNS name(ROOT Name must be empty)."));
                }
                rr.name.serialize(serializer)?;
                rr.udp_size.serialize(serializer)?;
                rr.rcode.serialize(serializer)?;
                rr.version.serialize(serializer)?;
                rr.flags.bits().serialize(serializer)?;

                let rdlen_pos = serializer.position();
                0u16.serialize(serializer)?;           // RDLEN
                
                for attr in rr.attrs.iter() {
                    match attr {
                        OptAttr::ECS(ecs) => {
                            edns::OptionCode::EDNS_CLIENT_SUBNET.0.serialize(serializer)?; // OptCode
                            let opt_len_pos = serializer.position();
                            0u16.serialize(serializer)?;                                   // OptLen

                            match ecs.address {
                                std::net::IpAddr::V4(_) => {
                                    edns::AddressFamily::IPV4.0.serialize(serializer)?;
                                },
                                std::net::IpAddr::V6(_) => {
                                    edns::AddressFamily::IPV6.0.serialize(serializer)?;
                                },
                            }

                            ecs.src_prefix_len.serialize(serializer)?;
                            ecs.scope_prefix_len.serialize(serializer)?;
                            ecs.address.serialize(serializer)?;

                            write_rdlen(serializer, opt_len_pos)?;
                        }
                    }
                }

                write_rdlen(serializer, rdlen_pos)?;
            },

            // ===== DNSSEC ======
            &Record::DNSKEY(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.flags.bits().serialize(serializer)?;
                    rr.protocol.0.serialize(serializer)?;
                    rr.algorithm.0.serialize(serializer)?;
                    rr.public_key.as_ref().serialize(serializer)?;
                });
            },
            &Record::RRSIG(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.type_covered.0.serialize(serializer)?;
                    rr.algorithm.0.serialize(serializer)?;
                    rr.labels.serialize(serializer)?;
                    rr.original_ttl.serialize(serializer)?;
                    rr.signature_expiration.serialize(serializer)?;
                    rr.signature_inception.serialize(serializer)?;
                    rr.key_tag.serialize(serializer)?;
                    rr.signer_name.serialize(serializer)?;
                    rr.signature.as_ref().serialize(serializer)?;
                });
            },
            &Record::NSEC(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.next_domain_name.serialize(serializer)?;
                    rr.type_bit_maps.as_slice().serialize(serializer)?;
                });
            },
            &Record::NSEC3(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.hash_algorithm.0.serialize(serializer)?;
                    rr.flags.bits().serialize(serializer)?;
                    rr.iterations.serialize(serializer)?;

                    let salt_len = rr.salt.len();
                    if salt_len > std::u8::MAX as usize {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid salt length."));
                    }
                    (salt_len as u8).serialize(serializer)?;
                    rr.salt.as_ref().serialize(serializer)?;

                    let hash_len = rr.next_hashed_owner_name.len();
                    if hash_len > std::u8::MAX as usize {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid next hashed owner name length."));
                    }
                    (hash_len as u8).serialize(serializer)?;
                    rr.next_hashed_owner_name.as_ref().serialize(serializer)?;

                    rr.type_bit_maps.as_slice().serialize(serializer)?;
                });
            },
            &Record::NSEC3PARAM(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.hash_algorithm.0.serialize(serializer)?;
                    rr.flags.serialize(serializer)?;
                    rr.iterations.serialize(serializer)?;

                    let salt_len = rr.salt.len();
                    if salt_len > std::u8::MAX as usize {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid salt length."));
                    }
                    (salt_len as u8).serialize(serializer)?;
                    rr.salt.as_ref().serialize(serializer)?;
                });
            },
            &Record::DS(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.key_tag.serialize(serializer)?;
                    rr.algorithm.0.serialize(serializer)?;
                    rr.digest_type.0.serialize(serializer)?;
                    rr.digest.as_ref().serialize(serializer)?;
                });
            },
            &Record::CAA(ref rr) => {
                serialize_normal_rr!(rr, {
                    rr.flags.serialize(serializer)?;
                    
                    let tag_len = rr.tag.len();
                    if tag_len > std::u8::MAX as usize {
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid tag length."));
                    }
                    (tag_len as u8).serialize(serializer)?;

                    rr.tag.as_bytes().serialize(serializer)?;
                    rr.value.as_bytes().serialize(serializer)?;
                });
            },
            _ => {
                unimplemented!()
            },
        }

        Ok(())
    }
}
