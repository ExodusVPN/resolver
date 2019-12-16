use crate::kind::Kind;
use crate::class::Class;
use crate::opcode::OpCode;
use crate::rcode::ResponseCode;
use crate::record::Record;
use crate::record::ClientSubnet;
use crate::record::OPT;
use crate::record::OptAttr;
use crate::edns::EDNS_V0;
use crate::edns::EDNSFlags;

use crate::ser::Serializer;
use crate::ser::Serialize;
use crate::de::Deserializer;
use crate::de::Deserialize;


use std::io;


pub const HEADER_SIZE: usize = 12;

bitflags! {
    // DNS Header Flags
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-12
    pub struct HeaderFlags: u16 {
        // QR      1 bits
        const QR_REQ = 0b_0000_0000_0000_0000;
        const QR_RES = 0b_1000_0000_0000_0000;
        
        // Opcode  4 bits
        const OP_QUERY    = 0b_0000_0000_0000_0000; /// Query                            RFC1035
        const OP_IQUERY   = 0b_0000_1000_0000_0000; /// inverse query, obsoleted.        RFC1035, RFC3425
        const OP_STATUS   = 0b_0001_0000_0000_0000; /// a server status request (STATUS) RFC1035
        const OP_NOTIFY   = 0b_0010_0000_0000_0000; /// notify                           RFC1996
        const OP_UPDATE   = 0b_0010_1000_0000_0000; /// Update                           RFC2136
        const OP_DSO      = 0b_0011_0000_0000_0000; /// DNS Stateful Operations (DSO)    RFC8490
        // OpCode   7-15    Unassigned
        
        const AA          = 0b_0000_0100_0000_0000; // Authoritative Answer
        const TC          = 0b_0000_0010_0000_0000; // TrunCation
        const RD          = 0b_0000_0001_0000_0000; // Recursion Desired
        const RA          = 0b_0000_0000_1000_0000; // Recursion Available

        // https://tools.ietf.org/html/rfc3225#section-3
        // 
        // explicit notification of the ability of
        // the client to accept (if not understand) DNSSEC security RRs.
        // 
        // https://tools.ietf.org/html/rfc4035#section-4.9.1
        // 
        // A validating security-aware stub resolver MUST set the DO bit,
        // because otherwise it will not receive the DNSSEC RRs it needs to
        // perform signature validation.
        // const DO          = 0b_0000_0000_0100_0000;
        
        // https://tools.ietf.org/html/rfc3655#section-2
        // 
        // If the CD bit is set, the server will not perform checking, 
        // but SHOULD still set the AD bit if the data has already been cryptographically verified or
        // complies with local policy.  The AD bit MUST only be set if DNSSEC
        // records have been requested via the DO bit RFC3225 and relevant SIG
        // records are returned.
        // 
        // https://tools.ietf.org/html/rfc4035#section-4.9.3
        // 
        // A validating security-aware stub resolver SHOULD NOT examine the
        // setting of the AD bit in response messages, as, by definition, the
        // stub resolver performs its own signature validation regardless of the
        // setting of the AD bit.
        const AD          = 0b_0000_0000_0010_0000; // Authentic Data    RFC4035, RFC6840, RFC Errata 4924
        // https://tools.ietf.org/html/rfc4035#section-4.9.2
        // 
        // A validating security-aware stub resolver SHOULD set the CD bit
        // because otherwise the security-aware recursive name server will
        // answer the query using the name server's local policy, which may
        // prevent the stub resolver from receiving data that would be
        // acceptable to the stub resolver's local policy.
        const CD          = 0b_0000_0000_0001_0000; // Checking Disabled RFC4035, RFC6840, RFC Errata 4927

        // response code (RCODE)  4 bits
        /// No Error   RFC1035
        /// No error condition
        const RCODE_OK                  = 0b_0000_0000_0000_0000;
        /// Format Error   RFC1035
        /// Format error - The name server was unable to interpret the query.
        const RCODE_FORMAT_ERROR        = 0b_0000_0000_0000_0001;
        /// Server Failure  RFC1035
        /// Server failure - The name server was unable to 
        /// process this query due to a problem with the name server.
        const RCODE_SERVER_FAILURE      = 0b_0000_0000_0000_0010;
        /// Non-Existent Domain     RFC1035
        /// Name Error - Meaningful only for responses from 
        /// an authoritative name server, this code signifies that the
        /// domain name referenced in the query does not exist.
        const RCODE_NON_EXISTENT_DOMAIN = 0b_0000_0000_0000_0011;
        /// Not Implemented     RFC1035
        /// Not Implemented - The name server does
        /// not support the requested kind of query.
        const RCODE_NOT_IMPLEMENTED     = 0b_0000_0000_0000_0100;
        /// Query Refused   RFC1035
        /// Refused - The name server refuses to perform the specified operation for policy reasons.
        /// For example, a name server may not wish to provide the information 
        /// to the particular requester, or a name server may not wish to perform
        /// a particular operation (e.g., zone transfer) for particular data.
        const RCODE_QUERY_REFUSED       = 0b_0000_0000_0000_0101;
        /// YXDomain    Name Exists when it should not  RFC2136 RFC6672
        const RCODE_YXDOMAIN            = 0b_0000_0000_0000_0110;
        /// YXRRSet     RR Set Exists when it should not    RFC2136
        const RCODE_YXRRSET             = 0b_0000_0000_0000_0111;
        /// NXRRSet     RR Set that should exist does not   RFC2136
        const RCODE_NXRRSET             = 0b_0000_0000_0000_1000;
        /// NotAuth     Server Not Authoritative for zone   RFC2136
        /// NotAuth     Not Authorized  RFC2845
        const RCODE_NOT_AUTH            = 0b_0000_0000_0000_1001;
        /// NotZone     Name not contained in zone  RFC2136
        const RCODE_NOT_ZONE            = 0b_0000_0000_0000_1010;
        
        const REQUEST           = Self::QR_REQ.bits | Self::OP_QUERY.bits | Self::RCODE_OK.bits;
        const RECURSION_REQUEST = Self::REQUEST.bits | Self::RD.bits;
    }
}

impl HeaderFlags {
    pub fn new_unchecked(bits: u16) -> Self {
        unsafe {
            Self::from_bits_unchecked(bits)
        }
    }

    // 1 bits
    /// A one bit field that specifies whether this message is a query (0), or a response (1).
    pub fn qr(&self) -> bool {
        self.bits >> 15 == 1
    }

    // 4 bits
    /// A four bit field that specifies kind of query in this message.
    /// This value is set by the originator of a query and copied into the response.
    pub fn opcode(&self) -> OpCode {
        let bits = ((self.bits << 1) >> 12) as u8;
        OpCode::new(bits)
    }

    // 1 bits
    /// Authoritative Answer - this bit is valid in responses,
    /// and specifies that the responding name server is an 
    /// authority for the domain name in question section.
    /// Note that the contents of the answer section may have
    /// multiple owner names because of aliases.  The AA bit
    /// corresponds to the name which matches the query name, or
    /// the first owner name in the answer section.
    pub fn aa(&self) -> bool {
        (self.bits & 0b_0000_0100_0000_0000) >> 10 == 1
    }

    // 1 bits
    /// TrunCation - specifies that this message was truncated
    /// due to length greater than that permitted on the
    /// transmission channel.
    pub fn tc(&self) -> bool {
        (self.bits & 0b_0000_0010_0000_0000) >> 9 == 1
    }

    // 1 bits
    /// Recursion Desired - this bit may be set in a query and
    /// is copied into the response.  If RD is set, it directs
    /// the name server to pursue the query recursively.
    /// Recursive query support is optional.
    pub fn rd(&self) -> bool {
        (self.bits & 0b_0000_0001_0000_0000) >> 8 == 1
    }

    // 1 bits
    /// Recursion Available - this be is set or cleared in a response,
    /// and denotes whether recursive query support is available in the name server.
    pub fn ra(&self) -> bool {
        (self.bits & 0b_0000_0000_1000_0000) >> 7 == 1
    }

    // 1 bits
    pub fn z(&self) -> bool {
        (self.bits & 0b_0000_0000_0100_0000) >> 6 == 1
    }
    
    // 1 bits
    // https://tools.ietf.org/html/rfc3655#section-2
    // 
    // If the CD bit is set, the server will not perform checking, 
    // but SHOULD still set the AD bit if the data has already been cryptographically verified or
    // complies with local policy.  The AD bit MUST only be set if DNSSEC
    // records have been requested via the DO bit RFC3225 and relevant SIG
    // records are returned.
    // 
    // https://tools.ietf.org/html/rfc4035#section-4.9.3
    // 
    // A validating security-aware stub resolver SHOULD NOT examine the
    // setting of the AD bit in response messages, as, by definition, the
    // stub resolver performs its own signature validation regardless of the
    // setting of the AD bit.
    pub fn ad(&self) -> bool {
        (self.bits & 0b_0000_0000_0010_0000) >> 5 == 1
    }

    // 1 bits
    // https://tools.ietf.org/html/rfc4035#section-4.9.2
    // 
    // A validating security-aware stub resolver SHOULD set the CD bit
    // because otherwise the security-aware recursive name server will
    // answer the query using the name server's local policy, which may
    // prevent the stub resolver from receiving data that would be
    // acceptable to the stub resolver's local policy.
    pub fn cd(&self) -> bool {
        (self.bits & 0b_0000_0000_0001_0000) >> 4 == 1
    }

    // 4 bits
    /// Response code - this 4 bit field is set as part of responses.
    pub fn rcode(&self) -> ResponseCode {
        let bits = self.bits & 0b_0000_0000_0000_1111;
        ResponseCode::new(bits)
    }

    pub fn set_qr(&mut self, value: bool) {
        if value {
            self.bits |= 0b_1000_0000_0000_0000;
        } else {
            self.bits &= 0b_0111_1111_1111_1111;
        }
    }

    pub fn set_opcode(&mut self, value: OpCode) {
        let code = value.code() as u16;
        self.bits &= 0b_1000_0111_1111_1111;
        self.bits |= code << 11;
    }

    pub fn set_aa(&mut self, value: bool) {
        if value {
            self.bits |= 0b_0000_0100_0000_0000;
        } else {
            self.bits &= 0b_1111_1011_1111_1111;
        }
    }

    pub fn set_tc(&mut self, value: bool) {
        if value {
            self.bits |= 0b_0000_0010_0000_0000;
        } else {
            self.bits &= 0b_1111_1101_1111_1111;
        }
    }

    pub fn set_rd(&mut self, value: bool) {
        if value {
            self.bits |= 0b_0000_0001_0000_0000;
        } else {
            self.bits &= 0b_1111_1110_1111_1111;
        }
    }

    pub fn set_ra(&mut self, value: bool) {
        if value {
            self.bits |= 0b_0000_0000_1000_0000;
        } else {
            self.bits &= 0b_1111_1111_0111_1111;
        }
    }

    // pub fn set_do(&mut self, value: bool) {
    //     if value {
    //         self.bits |= 0b_0000_0000_0100_0000;
    //     } else {
    //         self.bits &= 0b_1111_1111_1011_1111;
    //     }
    // }

    pub fn set_ad(&mut self, value: bool) {
        if value {
            self.bits |= 0b_0000_0000_0010_0000;
        } else {
            self.bits &= 0b_1111_1111_1101_1111;
        }
    }

    pub fn set_cd(&mut self, value: bool) {
        if value {
            self.bits |= 0b_0000_0000_0001_0000;
        } else {
            self.bits &= 0b_1111_1111_1110_1111;
        }
    }

    pub fn set_rcode(&mut self, value: ResponseCode) {
        let code = value.lo() as u16;
        self.bits &= 0b_1111_1111_1111_0000;
        self.bits |= code;
    }
}


bitflags! {
    pub struct ReprFlags: u8 {
        const QR = 0b_1000_0000; // Response
        const AA = 0b_0100_0000; // Authoritative Answer
        const TC = 0b_0010_0000; // TrunCation
        const RD = 0b_0001_0000; // Recursion Desired
        const RA = 0b_0000_1000; // Recursion Available
        const DO = 0b_0000_0100; // DNSSEC OK
        const AD = 0b_0000_0010; // Authentic Data    RFC4035, RFC6840, RFC Errata 4924
        const CD = 0b_0000_0001; // Checking Disabled RFC4035, RFC6840, RFC Errata 4927
    }
}

impl ReprFlags {
    pub fn new_unchecked(bits: u8) -> Self {
        unsafe {
            Self::from_bits_unchecked(bits)
        }
    }
}

impl Default for ReprFlags {
    fn default() -> Self {
        Self::RD | Self::DO
    }
}

impl Into<HeaderFlags> for ReprFlags {
    fn into(self) -> HeaderFlags {
        let mut flags = HeaderFlags::empty();
        
        if self.contains(ReprFlags::QR) {
            flags |= HeaderFlags::QR_RES;
        }

        if self.contains(ReprFlags::AA) {
            flags |= HeaderFlags::AA;
        }

        if self.contains(ReprFlags::TC) {
            flags |= HeaderFlags::TC;
        }

        if self.contains(ReprFlags::RD) {
            flags |= HeaderFlags::RD;
        }

        if self.contains(ReprFlags::RA) {
            flags |= HeaderFlags::RA;
        }

        if self.contains(ReprFlags::AD) {
            flags |= HeaderFlags::AD;
        }

        if self.contains(ReprFlags::CD) {
            flags |= HeaderFlags::CD;
        }

        flags
    }
}

impl From<HeaderFlags> for ReprFlags {
    fn from(val: HeaderFlags) -> ReprFlags {
        let mut flags = ReprFlags::empty();
        if val.qr() {
            flags |= ReprFlags::QR;
        }
        if val.aa() {
            flags |= ReprFlags::AA;
        }
        if val.tc() {
            flags |= ReprFlags::TC;
        }
        if val.rd() {
            flags |= ReprFlags::RD;
        }
        if val.ra() {
            flags |= ReprFlags::RA;
        }
        if val.ad() {
            flags |= ReprFlags::AD;
        }
        if val.cd() {
            flags |= ReprFlags::CD;
        }

        flags
    }
}

// 4.1.2. Question section format
// https://tools.ietf.org/html/rfc1035#section-4.1.2
// 
// The question section is used to carry the "question" in most queries,
// i.e., the parameters that define what is being asked.  The section
// contains QDCOUNT (usually 1) entries, each of the following format:
// 
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                     QNAME                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     QTYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     QCLASS                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 
// where:
// QNAME           a domain name represented as a sequence of labels, where
//                 each label consists of a length octet followed by that
//                 number of octets.  The domain name terminates with the
//                 zero length octet for the null label of the root.  Note
//                 that this field may be an odd number of octets; no
//                 padding is used.
// 
// QTYPE           a two octet code which specifies the type of the query.
//                 The values for this field include all codes valid for a
//                 TYPE field, together with some more general codes which
//                 can match more than one type of RR.
// 
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Question {
    pub name: String,
    pub kind: Kind,
    pub class: Class,
}

// 4.1.1. Header section format
// https://tools.ietf.org/html/rfc1035#section-4.1.1
// 
// The header contains the following fields:
// 
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      ID                       |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    QDCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ANCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    NSCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ARCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Header {
    pub id: u16,
    pub flags: HeaderFlags,     // u8
    // pub opcode: OpCode,         // u8
    // pub rcode: ResponseCode,    // u16
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Request {
    pub id: u16,
    pub flags: ReprFlags,     // u8
    pub opcode: OpCode,       // u8
    pub client_subnet: Option<ClientSubnet>,
    pub question: Question,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Response {
    pub id: u16,
    pub flags: ReprFlags,     // u8
    pub opcode: OpCode,
    pub rcode: ResponseCode,
    pub client_subnet: Option<ClientSubnet>,
    pub question: Question,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl Deserialize for Question {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        let name = String::deserialize(deserializer)?;
        let kind = Kind(u16::deserialize(deserializer)?);
        let class = Class(u16::deserialize(deserializer)?);

        Ok(Question { name, kind, class, })
    }
}

impl Serialize for Question {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        self.name.serialize(serializer)?;
        self.kind.0.serialize(serializer)?;
        self.class.0.serialize(serializer)?;

        Ok(())
    }
}


// 4.1.1. Header section format
// https://tools.ietf.org/html/rfc1035#section-4.1.1
// 
// The header contains the following fields:
// 
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                      ID                       |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    QDCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ANCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    NSCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ARCOUNT                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 
impl Deserialize for Request {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, io::Error> {
        unimplemented!();
    }
}

impl Serialize for Request {
    fn serialize(&self, serializer: &mut Serializer) -> Result<(), io::Error> {
        let mut hdr_flags: HeaderFlags = self.flags.into();
        hdr_flags.set_opcode(self.opcode);
        hdr_flags.set_rcode(ResponseCode::OK);
        
        let is_dnssec_ok = if self.flags.contains(ReprFlags::DO) { true } else { false };
        self.id.serialize(serializer)?;
        hdr_flags.bits().serialize(serializer)?;

        let qdcount = 1u16;
        let ancount = 0u16;
        let nscount = 0u16;
        let arcount = if !is_dnssec_ok && self.client_subnet.is_none() { 0u16 } else { 1 };

        qdcount.serialize(serializer)?;
        ancount.serialize(serializer)?;
        nscount.serialize(serializer)?;
        arcount.serialize(serializer)?;

        // ===== QUESTION ======
        self.question.serialize(serializer)?;

        // ===== EDNS =====
        if arcount == 0 {
            return Ok(());
        }
        debug_assert_eq!(arcount, 1);


        let edns_flags = if is_dnssec_ok { EDNSFlags::DO } else { EDNSFlags::empty() };
        let ends_opt_attrs = 
            match &self.client_subnet {
                Some(client_subnet) => vec![ OptAttr::ECS(client_subnet.clone()) ],
                None => Vec::new(),
            };

        let root_name = String::new();
        let opt = OPT {
            name: root_name,
            udp_size: 512,
            rcode: 0,
            version: EDNS_V0,
            flags: edns_flags,
            attrs: ends_opt_attrs,
        };
        let opt_record = Record::OPT(opt);
        opt_record.serialize(serializer)?;

        Ok(())
    }
}