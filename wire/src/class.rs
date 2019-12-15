use crate::error::Error;
use crate::error::ErrorKind;

// 0        0x0000  Reserved    [RFC6895]
// 1        0x0001  Internet (IN)   [RFC1035]
// 2        0x0002  Unassigned  
// 3        0x0003  Chaos (CH)  [D. Moon, "Chaosnet", A.I. Memo 628, Massachusetts Institute of Technology Artificial Intelligence Laboratory, June 1981.]
// 4        0x0004  Hesiod (HS)     [Dyer, S., and F. Hsu, "Hesiod", Project Athena Technical Plan - Name Service, April 1987.]
// 5-253    0x0005-0x00FD   Unassigned  
// 254      0x00FE  QCLASS NONE     [RFC2136]
// 255      0x00FF  QCLASS * (ANY)  [RFC1035]
// 256-65279        0x0100-0xFEFF   Unassigned  
// 65280-65534      0xFF00-0xFFFE   Reserved for Private Use    [RFC6895]
// 65535            0xFFFF  Reserved    [RFC6895]
// 
// 16 Bits
/// two octets containing one of the RR CLASS codes.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct Class(pub u16);

impl Class {
    /// the Internet
    pub const IN: Self = Self(1);
    /// the CSNET class (Obsolete - used only for examples in some obsolete RFCs)
    pub const CS: Self = Self(2);
    /// the CHAOS class
    pub const CH: Self = Self(3);
    /// Hesiod [Dyer 87]
    pub const HS: Self = Self(4);
    
    // QCLASS values

    /// QCLASS NONE     RFC2136
    pub const NONE: Self = Self(254);
    // QCLASS ANY
    /// any class (*)
    pub const ANY: Self  = Self(255);

    #[inline]
    pub fn is_unassigned(&self) -> bool {
        // 2            0x0002          Unassigned  (NOTE: assigned in RFC1035)
        // 5-253        0x0005-0x00FD   Unassigned
        // 256-65279    0x0100-0xFEFF   Unassigned
        match self.0 {
            5 ..= 253 | 256 ..= 65279 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_private_use(&self) -> bool {
        // 65280-65534      0xFF00-0xFFFE   Reserved for Private Use    RFC6895
        match self.0 {
            65280 ..= 65534 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_reserved(&self) -> bool {
        // 0                0x0000          Reserved    [RFC6895]
        // 65280-65534      0xFF00-0xFFFE   Reserved for Private Use    [RFC6895]
        // 65535            0xFFFF          Reserved    [RFC6895]
        match self.0 {
            0 | 65535 | 65280 ..= 65534 => true,
            _ => false,
        }
    }

    /// 5.4.  Questions Requesting Unicast Responses
    /// https://tools.ietf.org/html/rfc6762#section-5.4
    /// 
    /// To avoid large floods of potentially unnecessary responses in these
    /// cases, Multicast DNS defines the top bit in the class field of a DNS
    /// question as the unicast-response bit.  When this bit is set in a
    /// question, it indicates that the querier is willing to accept unicast
    /// replies in response to this specific query, as well as the usual
    /// multicast responses.  These questions requesting unicast responses
    /// are referred to as "QU" questions, to distinguish them from the more
    /// usual questions requesting multicast responses ("QM" questions).  A
    /// Multicast DNS querier sending its initial batch of questions
    /// immediately on wake from sleep or interface activation SHOULD set the
    /// unicast-response bit in those questions.
    #[inline]
    pub fn is_unicast(&self) -> bool {
        self.0 >> 15 == 1
    }

    #[inline]
    pub fn set_unicast(&mut self) {
        unimplemented!()
    }
    
    #[inline]
    pub fn class(&self) -> Self {
        if self.is_unicast() {
            Self(self.0 << 1 >> 1)
        } else {
            *self
        }
    }
}

impl std::fmt::Debug for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let class = if self.is_unicast() { self.class() } else { *self };

        match &class {
            &Self::IN => write!(f, "IN"),
            &Self::CS => write!(f, "CS"),
            &Self::CH => write!(f, "CH"),
            &Self::HS => write!(f, "HS"),
            &Self::NONE => write!(f, "NONE"),
            &Self::ANY => write!(f, "ANY"),
            _ => {
                if class.is_unassigned() {
                    write!(f, "Unassigned({})", class.0)
                } else if class.is_private_use() {
                    write!(f, "PrivateUse({})", class.0)
                } else if class.is_reserved() {
                    write!(f, "Reserved({})", class.0)
                } else {
                    write!(f, "Unknow({})", class.0)
                }
            },
        }
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::str::FromStr for Class {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "IN"   => Ok(Self::IN),
            "CS"   => Ok(Self::CS),
            "CH"   => Ok(Self::CH),
            "HS"   => Ok(Self::HS),
            "NONE" => Ok(Self::NONE),
            "ANY"  => Ok(Self::ANY),
            _      => Err(Error::from(ErrorKind::FormatError)),
        }
    }
}