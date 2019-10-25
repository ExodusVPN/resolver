use crate::error::Error;
use crate::wire::OpCode;
use crate::wire::ResponseCode;


pub const HEADER_SIZE: usize = 12;

bitflags! {
    // DNS Header Flags
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-12
    pub struct Flags: u16 {
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

impl Flags {
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
/// 4.1.1. Header section format
#[derive(PartialEq, Clone)]
pub struct HeaderPacket<T: AsRef<[u8]>> {
    buffer: T
}
    
impl<T: AsRef<[u8]>> HeaderPacket<T> {
    #[inline]
    pub fn new_unchecked(buffer: T) -> HeaderPacket<T> {
        HeaderPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<HeaderPacket<T>, Error> {
        let v = Self::new_unchecked(buffer);
        v.check_len()?;

        Ok(v)
    }

    #[inline]
    pub fn check_len(&self) -> Result<(), Error> {
        let data = self.buffer.as_ref();
        if data.len() < HEADER_SIZE {
            return Err(Error::Truncated);
        }

        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// A 16 bit identifier assigned by the program that generates any kind of query.
    /// This identifier is copied the corresponding reply and can be used by the requester
    /// to match up replies to outstanding queries.
    #[inline]
    pub fn id(&self) -> u16 {
        let data = self.buffer.as_ref();
        u16::from_be_bytes([ data[0], data[1] ])
    }

    #[inline]
    pub fn flags(&self) -> Flags {
        let data = self.buffer.as_ref();
        Flags::new_unchecked(u16::from_be_bytes([ data[2], data[3] ]))
    }

    /// an unsigned 16 bit integer specifying the number of entries in the question section.
    #[inline]
    pub fn qdcount(&self) -> u16 {
        let data = self.buffer.as_ref();
        u16::from_be_bytes([ data[4], data[5] ])
    }

    /// an unsigned 16 bit integer specifying the number of resource records in the answer section.
    #[inline]
    pub fn ancount(&self) -> u16 {
        let data = self.buffer.as_ref();
        u16::from_be_bytes([ data[6], data[7] ])
    }

    /// an unsigned 16 bit integer specifying the number of name
    /// server resource records in the authority records section.
    #[inline]
    pub fn nscount(&self) -> u16 {
        let data = self.buffer.as_ref();
        u16::from_be_bytes([ data[8], data[9] ])
    }

    /// an unsigned 16 bit integer specifying the number of
    /// resource records in the additional records section.
    #[inline]
    pub fn arcount(&self) -> u16 {
        let data = self.buffer.as_ref();
        u16::from_be_bytes([ data[10], data[11] ])
    }

    #[inline]
    pub fn len(&self) -> usize {
        HEADER_SIZE
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> HeaderPacket<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[HEADER_SIZE..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> HeaderPacket<T> {
    #[inline]
    pub fn set_id(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();
        data[0] = octets[0];
        data[1] = octets[1];
    }

    #[inline]
    pub fn set_flags(&mut self, value: Flags) {
        let data = self.buffer.as_mut();
        let octets = value.bits.to_be_bytes();

        data[2] = octets[0];
        data[3] = octets[1];
    }

    #[inline]
    pub fn set_qdcount(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();
        data[4] = octets[0];
        data[5] = octets[1];
    }

    #[inline]
    pub fn set_ancount(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();
        data[6] = octets[0];
        data[7] = octets[1];
    }

    #[inline]
    pub fn set_nscount(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();
        data[8] = octets[0];
        data[9] = octets[1];
    }

    #[inline]
    pub fn set_arcount(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();
        data[10] = octets[0];
        data[11] = octets[1];
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8]{
        let data = self.buffer.as_mut();
        
        &mut data[HEADER_SIZE..]
    }
}


impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Debug for HeaderPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HeaderPacket {{ id: {:?}, flags: {:?}, opcode: {:?}, rcode: {:?}, qdcount: {:?}, ancount: {:?}, nscount: {:?}, arcount: {:?} }}",
                self.id(),
                self.flags(),
                self.flags().opcode(),
                self.flags().rcode(),
                self.qdcount(),
                self.ancount(),
                self.nscount(),
                self.arcount(),
        )
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for HeaderPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HeaderPacket {{ id: {}, flags: {:?}, opcode: {}, rcode: {:?}, qdcount: {}, ancount: {}, nscount: {}, arcount: {} }}",
                self.id(),
                self.flags(),
                self.flags().opcode(),
                self.flags().rcode(),
                self.qdcount(),
                self.ancount(),
                self.nscount(),
                self.arcount(),
        )
    }
}

#[test]
fn test_header_packet() {
    let mut buffer = [0u8; 1024];

    let mut pkt = HeaderPacket::new_unchecked(&mut buffer[..]);
    pkt.set_id(1);
    pkt.set_flags(Flags::REQUEST);
    pkt.set_qdcount(1);
    pkt.set_ancount(0);
    pkt.set_nscount(0);
    pkt.set_arcount(0);

    let buffer = pkt.into_inner();
    let pkt = HeaderPacket::new_checked(&buffer[..]);
    assert!(pkt.is_ok());
    
    let pkt = pkt.unwrap();
    assert_eq!(pkt.id(), 1);
    assert_eq!(pkt.flags(), Flags::REQUEST);
    assert_eq!(pkt.qdcount(), 1);
    assert_eq!(pkt.ancount(), 0);
    assert_eq!(pkt.nscount(), 0);
    assert_eq!(pkt.arcount(), 0);
}