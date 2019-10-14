use crate::error::Error;
use crate::wire::Kind;
use crate::wire::Class;


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
/// 4.1.2. Question section format
#[derive(PartialEq, Clone)]
pub struct QuestionPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> QuestionPacket<T> {
    pub const SIZE: usize = 4;

    #[inline]
    pub fn new_unchecked(buffer: T) -> QuestionPacket<T> {
        QuestionPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<QuestionPacket<T>, Error> {
        let v = Self::new_unchecked(buffer);
        v.check_len()?;

        Ok(v)
    }

    #[inline]
    pub fn check_len(&self) -> Result<(), Error> {
        let data = self.buffer.as_ref();
        if data.len() < 4 {
            return Err(Error::Truncated);
        }

        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    #[inline]
    pub fn kind(&self) -> Kind {
        let data = self.buffer.as_ref();

        Kind(u16::from_be_bytes([ data[0], data[1] ]))
    }

    #[inline]
    pub fn class(&self) -> Class {
        let data = self.buffer.as_ref();

        Class(u16::from_be_bytes([ data[2], data[3] ]))
    }

    #[inline]
    pub fn len(&self) -> usize {
        Self::SIZE
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> QuestionPacket<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();

        &data[4..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> QuestionPacket<T> {
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
    pub fn payload_mut(&mut self) -> &mut [u8]{
        let data = self.buffer.as_mut();
        
        &mut data[4..]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Debug for QuestionPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QuestionPacket {{ kind: {:?}, class: {:?} }}",
                self.kind(),
                self.class(),
        )
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for QuestionPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QuestionPacket {{ kind: {}, class: {} }}",
                self.kind(),
                self.class(),
        )
    }
}


#[test]
fn test_question_packet() {
    let mut buffer = [0u8; 1024];

    let mut pkt = QuestionPacket::new_unchecked(&mut buffer[..]);
    pkt.set_kind(Kind(111));
    pkt.set_class(Class(222));

    let buffer = pkt.into_inner();
    let pkt = QuestionPacket::new_checked(&buffer[..]);
    assert!(pkt.is_ok());

    let pkt = pkt.unwrap();
    assert_eq!(pkt.kind(), Kind(111));
    assert_eq!(pkt.class(), Class(222));
}

