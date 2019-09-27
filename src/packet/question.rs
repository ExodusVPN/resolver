use crate::error::Error;
use crate::MAXIMUM_LABEL_SIZE;
use crate::MAXIMUM_NAMES_SIZE;



// 16 Bits
/// two octets containing one of the RR TYPE codes. 
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct QuestionType(pub u16);

impl QuestionType {
    /// a host address
    pub const A: Self     = Self(1);
    /// an authoritative name server
    pub const NS: Self    = Self(2);
    /// a mail destination (Obsolete - use MX)
    pub const MD: Self    = Self(3);
    /// a mail forwarder (Obsolete - use MX)
    pub const MF: Self    = Self(4);
    /// the canonical name for an alias
    pub const CNAME: Self = Self(5);
    /// marks the start of a zone of authority
    pub const SOA: Self   = Self(6);
    /// a mailbox domain name (EXPERIMENTAL)
    pub const MB: Self    = Self(7);
    /// a mail group member (EXPERIMENTAL)
    pub const MG: Self    = Self(8);
    /// a mail rename domain name (EXPERIMENTAL)
    pub const MR: Self    = Self(9);
    /// a null RR (EXPERIMENTAL)
    pub const NULL: Self  = Self(10);
    /// a well known service description
    pub const WKS: Self   = Self(11);
    /// a domain name pointer
    pub const PTR: Self   = Self(12);
    /// host information
    pub const HINFO: Self = Self(13);
    /// mailbox or mail list information
    pub const MINFO: Self = Self(14);
    /// mail exchange
    pub const MX: Self    = Self(15);
    /// text strings
    pub const TXT: Self   = Self(16);

    // QTYPE values
    /// A request for a transfer of an entire zone
    pub const AXFR: Self  = Self(252);
    /// A request for mailbox-related records (MB, MG or MR)
    pub const MAILB: Self = Self(253);
    /// A request for mail agent RRs (Obsolete - see MX)
    pub const MAILA: Self = Self(254);
    /// A request for all records
    pub const ALL: Self   = Self(255);

    #[inline]
    pub fn is_unspecified(&self) -> bool {
        self.0 == 0 || (self.0 > Self::TXT.0 && self.0 < Self::AXFR.0)
    }
}

impl std::fmt::Display for QuestionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &QuestionType::A => write!(f, "A"),
            &QuestionType::NS => write!(f, "NS"),
            &QuestionType::MD => write!(f, "MD"),
            &QuestionType::MF => write!(f, "MF"),
            &QuestionType::CNAME => write!(f, "CNAME"),
            &QuestionType::SOA => write!(f, "SOA"),
            &QuestionType::MB => write!(f, "MB"),
            &QuestionType::MG => write!(f, "MG"),
            &QuestionType::MR => write!(f, "MR"),
            &QuestionType::NULL => write!(f, "NULL"),
            &QuestionType::WKS => write!(f, "WKS"),
            &QuestionType::PTR => write!(f, "PTR"),
            &QuestionType::HINFO => write!(f, "HINFO"),
            &QuestionType::MINFO => write!(f, "MINFO"),
            &QuestionType::MX => write!(f, "MX"),
            &QuestionType::TXT => write!(f, "TXT"),

            &QuestionType::AXFR => write!(f, "AXFR"),
            &QuestionType::MAILB => write!(f, "MAILB"),
            &QuestionType::MAILA => write!(f, "MAILA"),
            &QuestionType::ALL => write!(f, "ALL"),

            _ => write!(f, "UnspecifiedQuestionType({})", self.0),
        }
    }
}


// 16 Bits
/// two octets containing one of the RR CLASS codes.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct QuestionClass(pub u16);

impl QuestionClass {
    /// the Internet
    pub const IN: Self = Self(1);
    // the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    pub const CS: Self = Self(2);
    /// the CHAOS class
    pub const CH: Self = Self(3);
    /// Hesiod [Dyer 87]
    pub const HS: Self = Self(4);
    
    // QCLASS values
    /// any class
    pub const ANY: Self = Self(255);

    #[inline]
    pub fn is_unspecified(&self) -> bool {
        self.0 == 0 || (self.0 > Self::HS.0 && self.0 < Self::ANY.0)
    }
}

impl std::fmt::Display for QuestionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &QuestionClass::IN => write!(f, "IN"),
            &QuestionClass::CS => write!(f, "CS"),
            &QuestionClass::CH => write!(f, "CH"),
            &QuestionClass::HS => write!(f, "HS"),

            &QuestionClass::ANY => write!(f, "ANY"),

            _ => write!(f, "UnspecifiedQuestionClass({})", self.0),
        }
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
#[derive(PartialEq, Clone)]
pub struct QuestionPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> QuestionPacket<T> {

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
        let min_size = self.last_label_offset()? + 1 + 2 + 2;
        
        if data.len() < min_size {
            return Err(Error::Truncated);
        }

        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    fn last_label_offset(&self) -> Result<usize, Error> {
        let data = self.buffer.as_ref();

        let mut names_length = 0;
        let mut labels_count = 0;
        let mut idx = 0usize;
        loop {
            if idx >= data.len() {
                return Err(Error::Truncated);
            }

            let len = data[idx] as usize;
            if len == 0 {
                break;
            }

            if len > MAXIMUM_LABEL_SIZE {
                return Err(Error::LabelSizeLimitExceeded);
            }

            let start = idx + 1;

            idx += len + 1;
            labels_count += 1;
            names_length += len;

            let end = idx;
            match &data.get(start..end) {
                Some(s) => {
                    if let Err(_) = std::str::from_utf8(s) {
                        return Err(Error::InvalidUtf8Sequence);
                    }
                },
                None => return Err(Error::Truncated),
            }
        }

        if names_length + labels_count - 1 > MAXIMUM_NAMES_SIZE {
            return Err(Error::NamesSizeLimitExceeded);
        }

        Ok(idx)
    }

    #[inline]
    pub fn qtype(&self) -> QuestionType {
        let data = self.buffer.as_ref();

        let offset = self.last_label_offset().unwrap() + 1;
        QuestionType(u16::from_be_bytes([ data[offset + 0], data[offset + 1] ]))
    }

    #[inline]
    pub fn qclass(&self) -> QuestionClass {
        let data = self.buffer.as_ref();

        let offset = self.last_label_offset().unwrap() + 1 + 2;
        QuestionClass(u16::from_be_bytes([ data[offset + 0], data[offset + 1] ]))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> QuestionPacket<&'a T> {
    #[inline]
    pub fn labels(&self) -> Labels<'a> {
        let offset = self.last_label_offset().unwrap() + 1;
        let data = self.buffer.as_ref();
        Labels {
            offset: 0,
            data: &data[..offset],
        }
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2;

        let data = self.buffer.as_ref();
        &data[offset..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> QuestionPacket<T> {
    #[inline]
    pub fn set_names(&mut self, value: &str) {
        assert!(value.len() <= MAXIMUM_NAMES_SIZE);
        let data = self.buffer.as_mut();

        let mut offset = 0usize;
        for label in value.split('.') {
            assert!(label.len() <= MAXIMUM_LABEL_SIZE);

            data[offset] = label.len() as u8;
            let start = offset + 1;
            let end = start + label.len();

            &mut data[start..end].copy_from_slice(label.as_bytes());
            offset += 1 + label.len();
        }

        if data[offset] != 0 {
            data[offset] = 0;
        }
    }

    #[inline]
    pub fn set_qtype(&mut self, value: QuestionType) {
        let offset = self.last_label_offset().unwrap() + 1;
        let data = self.buffer.as_mut();
        let octets = value.0.to_be_bytes();

        // NOTE: 确保名字先存储了！
        assert_eq!(data[offset-1], 0);

        data[offset + 0] = octets[0];
        data[offset + 1] = octets[1];
    }

    #[inline]
    pub fn set_qclass(&mut self, value: QuestionClass) {
        let offset = self.last_label_offset().unwrap() + 1 + 2;
        let data = self.buffer.as_mut();
        let octets = value.0.to_be_bytes();

        // NOTE: 确保名字先存储了！
        assert_eq!(data[offset-3], 0);

        data[offset + 0] = octets[0];
        data[offset + 1] = octets[1];
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8]{
        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2;

        let data = self.buffer.as_mut();
        
        &mut data[offset..]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Debug for QuestionPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QuestionPacket {{ labels: {:?}, qtype: {:?}, qclass: {:?} }}",
                self.labels().collect::<Vec<&str>>(),
                self.qtype(),
                self.qclass(),
        )
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for QuestionPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QuestionPacket {{ labels: {:?}, qtype: {}, qclass: {} }}",
                self.labels().collect::<Vec<&str>>(),
                self.qtype(),
                self.qclass(),
        )
    }
}


pub struct Labels<'a> {
    pub(crate) offset: usize,
    pub(crate) data: &'a [u8],
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data[self.offset] == 0 {
            return None;
        }

        let len = self.data[self.offset] as usize;
        let start = self.offset + 1;
        let end = start + len;

        self.offset += 1 + len;
        let s = &self.data[start..end];

        Some(unsafe { std::str::from_utf8_unchecked(s) })
    }
}



#[test]
fn test_question_packet() {
    let mut buffer = [0u8; 1024];

    let mut pkt = QuestionPacket::new_unchecked(&mut buffer[..]);
    pkt.set_names("www.example.com");
    pkt.set_qtype(111);
    pkt.set_qclass(222);

    let buffer = pkt.into_inner();
    let pkt = QuestionPacket::new_checked(&buffer[..]);
    assert!(pkt.is_ok());

    let pkt = pkt.unwrap();
    assert_eq!(pkt.labels().collect::<Vec<&str>>().join("."), "www.example.com");
    assert_eq!(pkt.qtype(), 111);
    assert_eq!(pkt.qclass(), 222);
}

