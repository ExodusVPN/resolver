// 0   NoError     No Error    [RFC1035]
// 1   FormErr     Format Error    [RFC1035]
// 2   ServFail    Server Failure  [RFC1035]
// 3   NXDomain    Non-Existent Domain     [RFC1035]
// 4   NotImp      Not Implemented     [RFC1035]
// 5   Refused     Query Refused   [RFC1035]
// 6   YXDomain    Name Exists when it should not  [RFC2136][RFC6672]
// 7   YXRRSet     RR Set Exists when it should not    [RFC2136]
// 8   NXRRSet     RR Set that should exist does not   [RFC2136]
// 9   NotAuth     Server Not Authoritative for zone   [RFC2136]
// 9   NotAuth     Not Authorized  [RFC2845]
// 10  NotZone     Name not contained in zone  [RFC2136]
// 11  DSOTYPENI   DSO-TYPE Not Implemented    [RFC8490]
// 12-15   Unassigned      
// 16  BADVERS     Bad OPT Version     [RFC6891]
// 16  BADSIG  TSIG Signature Failure  [RFC2845]
// 17  BADKEY  Key not recognized  [RFC2845]
// 18  BADTIME     Signature out of time window    [RFC2845]
// 19  BADMODE     Bad TKEY Mode   [RFC2930]
// 20  BADNAME     Duplicate key name  [RFC2930]
// 21  BADALG  Algorithm not supported     [RFC2930]
// 22  BADTRUNC    Bad Truncation  [RFC4635]
// 23  BADCOOKIE   Bad/missing Server Cookie   [RFC7873]
// 24-3840     Unassigned      
// 3841-4095   Reserved for Private Use        [RFC6895]
// 4096-65534  Unassigned      
// 65535   Reserved, can be allocated by Standards Action      [RFC6895]
// 

// 8 Bits + 4 Bits
/// Response code - this 4 bit field is set as part of responses.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct ResponseCode(u16);

impl ResponseCode {
    /// No Error   RFC1035
    /// No error condition
    pub const OK: Self              = Self(0);
    /// Format Error   RFC1035
    /// Format error - The name server was unable to interpret the query.
    pub const FORMAT_ERROR: Self    = Self(1);
    /// Server Failure  RFC1035
    /// Server failure - The name server was unable to 
    /// process this query due to a problem with the name server.
    pub const SERVER_FAILURE: Self  = Self(2);
    /// Non-Existent Domain     RFC1035
    /// Name Error - Meaningful only for responses from 
    /// an authoritative name server, this code signifies that the
    /// domain name referenced in the query does not exist.
    pub const NON_EXISTENT_DOMAIN: Self = Self(3);
    /// Not Implemented     RFC1035
    /// Not Implemented - The name server does
    /// not support the requested kind of query.
    pub const NOT_IMPLEMENTED: Self     = Self(4);
    /// Query Refused   RFC1035
    /// Refused - The name server refuses to perform the specified operation for policy reasons.
    /// For example, a name server may not wish to provide the information 
    /// to the particular requester, or a name server may not wish to perform
    /// a particular operation (e.g., zone transfer) for particular data.
    pub const QUERY_REFUSED: Self       = Self(5);

    /// YXDomain    Name Exists when it should not  RFC2136 RFC6672
    pub const YXDOMAIN: Self = Self(6);
    /// YXRRSet     RR Set Exists when it should not    RFC2136
    pub const YXRRSET: Self  = Self(7);
    /// NXRRSet     RR Set that should exist does not   RFC2136
    pub const NXRRSET: Self  = Self(8);
    /// NotAuth     Server Not Authoritative for zone   RFC2136
    /// NotAuth     Not Authorized  RFC2845
    pub const NOT_AUTH: Self = Self(9); 
    /// NotZone     Name not contained in zone  RFC2136
    pub const NOT_ZONE: Self = Self(10);

    // ExtResponseCode
    // https://tools.ietf.org/html/rfc6891#section-6.1.3
    /// DSOTYPENI   DSO-TYPE Not Implemented    RFC8490
    pub const DSOTYPENI: Self= Self(11);
    
    /// 16 BADVERS     Bad OPT Version     RFC6891
    /// 16 BADSIG      TSIG Signature Failure  RFC2845
    pub const BADVERS: Self = Self(16);
    /// BADKEY      Key not recognized  RFC2845
    pub const BADKEY: Self  = Self(17);
    /// BADTIME     Signature out of time window    RFC2845
    pub const BADTIME: Self = Self(18);
    /// BADMODE     Bad TKEY Mode   RFC2930
    pub const BADMODE: Self = Self(19);
    /// BADNAME     Duplicate key name  RFC2930
    pub const BADNAME: Self = Self(20);
    /// BADALG      Algorithm not supported     RFC2930
    pub const BADALG: Self  = Self(21);
    /// BADTRUNC    Bad Truncation  RFC4635
    pub const BADTRUNC: Self  = Self(22);
    /// BADCOOKIE   Bad/missing Server Cookie   RFC7873
    pub const BADCOOKIE: Self = Self(23);


    #[inline]
    pub fn new(code: u16) -> Self {
        assert!(code < 4095); // 2**12 - 1
        Self(code)
    }

    #[inline]
    pub fn code(&self) -> u16 {
        self.0
    }

    #[inline]
    pub fn hi(&self) -> u8 {
        // 8 bits
        ((self.0 >> 4) & 0b_0000_0000_1111_1111) as u8
    }

    #[inline]
    pub fn lo(&self) -> u8 {
        // 4 bits
        (self.0 & 0b_0000_0000_0000_1111) as u8
    }

    #[inline]
    pub fn extend_hi(&mut self, hi: u8) {
        self.0 |= (hi as u16) << 4
    }

    #[inline]
    pub fn is_ok(&self) -> bool {
        *self == Self::OK
    }

    #[inline]
    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }

    #[inline]
    pub fn is_unassigned(&self) -> bool {
        // 12-15        Unassigned
        // 24-3840      Unassigned
        // 4096-65534   Unassigned
        match self.0 {
            12 ..= 15 | 24 ..= 3840 | 4096 ..= 65534 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_reserved(&self) -> bool {
        // 3841-4095   Reserved for Private Use        RFC6895
        // 65535       Reserved, can be allocated by Standards Action     RFC6895
        match self.0 {
            3841 ..= 4095 | 65535 => true,
            _ => false,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            &Self::OK => "No Error [RFC1035]",
            &Self::FORMAT_ERROR => "Format Error [RFC1035]",
            &Self::SERVER_FAILURE => "Server Failure [RFC1035]",
            &Self::NON_EXISTENT_DOMAIN => "Non-Existent Domain [RFC1035]",
            &Self::NOT_IMPLEMENTED => "Not Implemented [RFC1035]",
            &Self::QUERY_REFUSED  => "Query Refused [RFC1035]",
            &Self::YXDOMAIN  => "Name Exists when it should not [RFC2136] [RFC6672]",
            &Self::YXRRSET  => "RR Set Exists when it should not [RFC2136]",
            &Self::NXRRSET  => "RR Set that should exist does not [RFC2136]",
            &Self::NOT_AUTH  => "Server Not Authoritative for zone [RFC2136]",
            &Self::NOT_ZONE  => "Name not contained in zone [RFC2136]",
            &Self::DSOTYPENI  => "DSO-TYPE Not Implemented RFC8490",
            &Self::BADVERS  => "Bad OPT Version RFC6891",
            &Self::BADKEY  => "Key not recognized  RFC2845",
            &Self::BADTIME  => "Signature out of time window RFC2845",
            &Self::BADMODE  => "Bad TKEY Mode RFC2930",
            &Self::BADNAME  => "Duplicate key name RFC2930",
            &Self::BADALG  => "Algorithm not supported RFC2930",
            &Self::BADTRUNC  => "Bad Truncation RFC4635",
            &Self::BADCOOKIE  => "Bad/missing Server Cookie RFC7873",
            _ => {
                if self.is_unassigned() {
                    "Unassigned"
                } else {
                    "Unknow"
                }
            },
        }
    }
}

impl std::fmt::Debug for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::OK => write!(f, "OK"),
            &Self::FORMAT_ERROR => write!(f, "FORMAT_ERROR"),
            &Self::SERVER_FAILURE => write!(f, "SERVER_FAILURE"),
            &Self::NON_EXISTENT_DOMAIN => write!(f, "NON_EXISTENT_DOMAIN"),
            &Self::NOT_IMPLEMENTED => write!(f, "NOT_IMPLEMENTED"),
            &Self::QUERY_REFUSED  => write!(f, "QUERY_REFUSED"),
            &Self::YXDOMAIN  => write!(f, "YXDOMAIN"),
            &Self::YXRRSET  => write!(f, "YXRRSET"),
            &Self::NXRRSET  => write!(f, "NXRRSET"),
            &Self::NOT_AUTH  => write!(f, "NOT_AUTH"),
            &Self::NOT_ZONE  => write!(f, "NOT_ZONE"),
            &Self::DSOTYPENI  => write!(f, "DSOTYPENI"),
            &Self::BADVERS  => write!(f, "BADVERS"),
            &Self::BADKEY  => write!(f, "BADKEY"),
            &Self::BADTIME  => write!(f, "BADTIME"),
            &Self::BADMODE  => write!(f, "BADMODE"),
            &Self::BADNAME  => write!(f, "BADNAME"),
            &Self::BADALG  => write!(f, "BADALG"),
            &Self::BADTRUNC  => write!(f, "BADTRUNC"),
            &Self::BADCOOKIE  => write!(f, "BADCOOKIE"),
            _ => {
                if self.is_unassigned() {
                    write!(f, "Unassigned({})", self.0)
                } else {
                    write!(f, "Unknow({})", self.0)
                }
            },
        }
    }
}

impl std::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}