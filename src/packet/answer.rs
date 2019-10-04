use crate::error::Error;
use crate::packet::Kind;
use crate::packet::Class;


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

/// 4.1.3. Resource record format
/// The answer, authority, and additional sections all share the same format.
#[derive(PartialEq, Clone)]
pub struct AnswerPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> AnswerPacket<T> {

    #[inline]
    pub fn new_unchecked(buffer: T) -> AnswerPacket<T> {
        AnswerPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<AnswerPacket<T>, Error> {
        let v = Self::new_unchecked(buffer);
        v.check_len()?;

        Ok(v)
    }

    #[inline]
    pub fn check_len(&self) -> Result<(), Error> {
        let data = self.buffer.as_ref();
        let min_size = self.header_len();
        
        if data.len() < min_size {
            return Err(Error::Truncated);
        }

        if data.len() < self.total_len() {
            return Err(Error::Truncated);
        }

        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// two octets containing one of the RR type codes.
    /// This field specifies the meaning of the data in the RDATA field.
    #[inline]
    pub fn kind(&self) -> Kind {
        let data = self.buffer.as_ref();

        Kind(u16::from_be_bytes([ data[0], data[1] ]))
    }

    /// two octets which specify the class of the data in the RDATA field.
    #[inline]
    pub fn class(&self) -> Class {
        let data = self.buffer.as_ref();
        let num = u16::from_be_bytes([ data[2], data[3] ]);

        Class(num)
    }

    /// a 32 bit unsigned integer that specifies the time interval (in seconds) 
    /// that the resource record may be cached before it should be discarded.
    /// Zero values are interpreted to mean that the RR can only be used for the
    /// transaction in progress, and should not be cached.
    #[inline]
    pub fn ttl(&self) -> u32 {
        let data = self.buffer.as_ref();
        let num = u32::from_be_bytes([
            data[4], data[5],
            data[6], data[7],
        ]);

        num
    }

    /// an unsigned 16 bit integer that specifies the length in octets of the RDATA field.
    #[inline]
    pub fn rdlen(&self) -> u16 {
        let data = self.buffer.as_ref();

        u16::from_be_bytes([ data[8], data[9] ])
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        10
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        10 + self.rdlen() as usize
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> AnswerPacket<&'a T> {
    /// Additional RR-specific data
    #[inline]
    pub fn rdata(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();

        &data[self.header_len()..self.total_len()]
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let offset = self.total_len();
        let data = self.buffer.as_ref();

        &data[offset..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> AnswerPacket<T> {
    #[inline]
    pub fn set_kind(&mut self, value: Kind) {
        let data = self.buffer.as_mut();
        let octets = value.0.to_be_bytes();

        data[0] = octets[0];
        data[1] = octets[1];
    }

    #[inline]
    pub fn set_class(&mut self, value: Class) {
        let data = self.buffer.as_mut();
        let octets = value.0.to_be_bytes();

        data[2] = octets[0];
        data[3] = octets[1];
    }


    #[inline]
    pub fn set_ttl(&mut self, value: u32) {
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();

        data[4] = octets[0];
        data[5] = octets[1];
        data[6] = octets[2];
        data[7] = octets[3];
    }

    #[inline]
    pub fn set_rdlen(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();

        data[8] = octets[0];
        data[9] = octets[1];
    }

    #[inline]
    pub fn rdata_mut(&mut self) -> &mut [u8] {
        let start = self.header_len();
        let end = self.total_len();

        let data = self.buffer.as_mut();

        &mut data[start..end]
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8]{
        let total_len = self.total_len();
        let data = self.buffer.as_mut();
        
        &mut data[total_len..]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Debug for AnswerPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnswerPacket {{ kind: {:?}, class: {:?}, ttl: {:?}, rdlen: {:?}, rdata: {:?} }}",
                self.kind(),
                self.class(),
                self.ttl(),
                self.rdlen(),
                self.rdata(),
        )
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for AnswerPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AnswerPacket {{ kind: {}, class: {}, ttl: {}, rdlen: {}, rdata: {:?} }}",
                self.kind(),
                self.class(),
                self.ttl(),
                self.rdlen(),
                self.rdata(),
        )
    }
}
