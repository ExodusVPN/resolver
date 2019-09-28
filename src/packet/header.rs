use crate::error::Error;
use crate::packet::MessageType;
use crate::packet::OpCode;
use crate::packet::ResponseCode;

// DNS Header Flags
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-12
// bit 5   AA  Authoritative Answer    [RFC1035]
// bit 6   TC  Truncated Response  [RFC1035]
// bit 7   RD  Recursion Desired   [RFC1035]
// bit 8   RA  Recursion Available     [RFC1035]
// bit 9       Reserved
// bit 10  AD  Authentic Data  [RFC4035][RFC6840][RFC Errata 4924]
// bit 11  CD  Checking Disabled   [RFC4035][RFC6840][RFC Errata 4927]


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
#[derive(Debug, PartialEq, Clone)]
pub struct HeaderPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> HeaderPacket<T> {
    pub const HEADER_SIZE: usize = 12;

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
        if data.len() < Self::HEADER_SIZE {
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

    // Offset: 2

    // 1 bits
    /// A one bit field that specifies whether this message is a query (0), or a response (1).
    #[inline]
    pub fn qr(&self) -> MessageType {
        // query (0), or a response (1).
        let data = self.buffer.as_ref();
        let bit = data[2] >> 7;
        if bit == 0 {
            MessageType::Query
        } else {
            MessageType::Response
        }
    }

    // qr  1 bits
    /// A one bit field that specifies whether this message is a query (0), or a response (1).
    #[inline]
    pub fn is_query(&self) -> bool {
        let data = self.buffer.as_ref();
        let bit = data[2] >> 7;
        bit == 0
    }

    // qr  1 bits
    /// A one bit field that specifies whether this message is a query (0), or a response (1).
    #[inline]
    pub fn is_response(&self) -> bool {
        !self.is_query()
    }

    // 4 bits
    /// A four bit field that specifies kind of query in this message.
    /// This value is set by the originator of a query and copied into the response.
    #[inline]
    pub fn opcode(&self) -> OpCode {
        let data = self.buffer.as_ref();
        OpCode::new(data[2] << 1 >> 4)
    }

    // 1 bits
    /// Authoritative Answer - this bit is valid in responses,
    /// and specifies that the responding name server is an 
    /// authority for the domain name in question section.
    /// Note that the contents of the answer section may have
    /// multiple owner names because of aliases.  The AA bit
    /// corresponds to the name which matches the query name, or
    /// the first owner name in the answer section.
    #[inline]
    pub fn aa(&self) -> bool {
        let data = self.buffer.as_ref();
        data[2] << 5 >> 2 == 0
    }

    // 1 bits
    /// TrunCation - specifies that this message was truncated
    /// due to length greater than that permitted on the
    /// transmission channel.
    #[inline]
    pub fn tc(&self) -> bool {
        let data = self.buffer.as_ref();
        data[2] << 6 >> 1 == 0
    }

    // 1 bits
    /// Recursion Desired - this bit may be set in a query and
    /// is copied into the response.  If RD is set, it directs
    /// the name server to pursue the query recursively.
    /// Recursive query support is optional.
    #[inline]
    pub fn rd(&self) -> bool {
        let data = self.buffer.as_ref();
        data[2] << 7 == 0
    }

    // Offset: 3

    // 1 bits
    /// Recursion Available - this be is set or cleared in a response,
    /// and denotes whether recursive query support is available in the name server.
    #[inline]
    pub fn ra(&self) -> bool {
        let data = self.buffer.as_ref();
        data[3] >> 7 == 0
    }

    // 3 bits
    /// Reserved for future use.  Must be zero in all queries and responses.
    #[inline]
    pub fn z(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[3] << 1 >> 5
    }

    // 4 bits
    /// Response code - this 4 bit field is set as part of responses.
    #[inline]
    pub fn rcode(&self) -> ResponseCode {
        let data = self.buffer.as_ref();
        ResponseCode::new(data[3] << 4)
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
}

impl<'a, T: AsRef<[u8]> + ?Sized> HeaderPacket<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();
        &data[Self::HEADER_SIZE..]
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

    // 1 bits
    #[inline]
    pub fn set_qr(&mut self, value: MessageType) {
        let data = self.buffer.as_mut();
        let mask = match value {
            MessageType::Query    => 0b_0000_0000,
            MessageType::Response => 0b_1000_0000,
        };

        data[2] |= mask;
    }

    // 4 bits
    #[inline]
    pub fn set_opcode(&mut self, value: OpCode) {
        let data = self.buffer.as_mut();
        let code = value.code();
        
        data[2] |= code << 3;
    }

    // 1 bits
    #[inline]
    pub fn set_aa(&mut self, value: bool) {
        let data = self.buffer.as_mut();

        if value {
            data[2] |= 0b_0000_0100;
        } else {
            data[2] &= 0b_1111_1011;
        }
    }

    // 1 bits
    #[inline]
    pub fn set_tc(&mut self, value: bool) {
        let data = self.buffer.as_mut();

        if value {
            data[2] |= 0b_0000_0010;
        } else {
            data[2] &= 0b_1111_1101;
        }
    }

    // 1 bits
    #[inline]
    pub fn set_rd(&mut self, value: bool) {
        let data = self.buffer.as_mut();

        if value {
            data[2] |= 0b_0000_0001;
        } else {
            data[2] &= 0b_1111_1110;
        }
    }
    

    // 1 bits
    #[inline]
    pub fn set_ra(&mut self, value: bool) {
        let data = self.buffer.as_mut();

        if value {
            data[3] |= 0b_1000_0000;
        } else {
            data[3] &= 0b_0111_1111;
        }
    }

    // 3 bits
    #[inline]
    pub fn set_z(&mut self, value: u8) {
        assert_eq!(value, 0);

        let data = self.buffer.as_mut();

        data[3] &= 0b_1000_1111;
    }

    // 4 bits
    #[inline]
    pub fn set_rcode(&mut self, value: ResponseCode) {
        let data = self.buffer.as_mut();
        let code = value.code();

        data[3] |= code << 4;
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
        
        &mut data[Self::HEADER_SIZE..]
    }
}


impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for HeaderPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "HeaderPacket {{ id: {:?}, qr: {:?}, opcode: {:?}, aa: {:?}, tc: {}, rd: {}, ra: {}, z: {}, rcode: {:?}, qdcount: {}, ancount: {}, nscount: {}, arcount: {} }}",
                self.id(),
                self.qr(),
                self.opcode(),
                self.aa(),
                self.tc(),
                self.rd(),
                self.ra(),
                self.z(),
                self.rcode(),
                self.qdcount(),
                self.ancount(),
                self.nscount(),
                self.arcount(),
        )
    }
}