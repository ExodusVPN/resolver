
mod header;
mod question;
mod answer;
mod record;

pub use self::header::*;
pub use self::question::*;
pub use self::answer::*;
pub use self::record::*;


pub fn query_packet_min_size(name: &str) -> usize {
    // Header Size + NAMES Size + QueryType Size + QueryClass Size
    //    12       name.len() + 1       2                2
    12 + name.len() + 1 + 1 + 2 + 2
}

// 4. MESSAGES
// 4.1. Format
// https://tools.ietf.org/html/rfc1035#section-4
// 
// All communications inside of the domain protocol are carried in a single
// format called a message.  The top level format of message is divided
// into 5 sections (some of which are empty in certain cases) shown below:
// 
//     +---------------------+
//     |        Header       |
//     +---------------------+
//     |       Question      | the question for the name server
//     +---------------------+
//     |        Answer       | RRs answering the question
//     +---------------------+
//     |      Authority      | RRs pointing toward an authority
//     +---------------------+
//     |      Additional     | RRs holding additional information
//     +---------------------+
// 
// 


// 1 Bits
/// A one bit field that specifies whether this message is a
/// query (0), or a response (1).
#[repr(u8)]
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum MessageType {
    Query    = 0u8,
    Response = 1u8,
}


// 4 Bits
/// A four bit field that specifies kind of query in this message.
/// This value is set by the originator of a query and copied into the response.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct OpCode(u8);

impl OpCode {
    // 0   Query   [RFC1035]
    // 1   IQuery (Inverse Query, OBSOLETE)    [RFC3425]
    // 2   Status  [RFC1035]
    // 3   Unassigned  
    // 4   Notify  [RFC1996]
    // 5   Update  [RFC2136]
    // 6   DNS Stateful Operations (DSO)   [RFC8490]
    // 7-15    Unassigned  

    /// a standard query (QUERY)
    pub const QUERY: Self  = Self(0);
    /// an inverse query (IQUERY)
    pub const IQUERY: Self = Self(1);
    /// a server status request (STATUS)
    pub const STATUS: Self = Self(2);

    /// Notify RFC1996
    pub const NOTIFY: Self = Self(4);
    /// Update RFC2136
    pub const UPDATE: Self = Self(5);
    /// DNS Stateful Operations (DSO)   RFC8490
    pub const DNS_STATEFUL_OPERATIONS: Self = Self(6);

    pub const MAX: Self    = Self(15);

    pub fn new(code: u8) -> Self {
        assert!(code < 16);
        Self(code)
    }

    #[inline]
    pub fn code(&self) -> u8 {
        self.0
    }

    #[inline]
    pub fn is_unassigned(&self) -> bool {
        // 3       Unassigned
        // 7-15    Unassigned
        match self.0 {
            3 | 7 ..= 15 => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &OpCode::QUERY => write!(f, "QUERY"),
            &OpCode::IQUERY => write!(f, "IQUERY"),
            &OpCode::STATUS => write!(f, "STATUS"),
            &OpCode::NOTIFY => write!(f, "NOTIFY"),
            
            &OpCode::UPDATE => write!(f, "UPDATE"),
            &OpCode::DNS_STATEFUL_OPERATIONS => write!(f, "DNS_STATEFUL_OPERATIONS"),

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

// 4 Bits
/// Response code - this 4 bit field is set as part of responses.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct ResponseCode(u8);

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

    // NOTE: 大于 10 的代码参见 ErrorCode 部分。
    //       https://tools.ietf.org/html/rfc6895#section-2.3

    pub const MAX: Self       = Self(15);

    pub fn new(code: u8) -> Self {
        assert!(code < 16);
        Self(code)
    }

    #[inline]
    pub fn code(&self) -> u8 {
        self.0
    }

    #[inline]
    pub fn is_unassigned(&self) -> bool {
        match self.0 {
            10 ..= 15 => true,
            _ => false,
        }
    }
}

impl std::fmt::Debug for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &ResponseCode::OK => write!(f, "OK"),
            &ResponseCode::FORMAT_ERROR => write!(f, "FORMAT_ERROR"),
            &ResponseCode::SERVER_FAILURE => write!(f, "SERVER_FAILURE"),
            &ResponseCode::NON_EXISTENT_DOMAIN => write!(f, "NON_EXISTENT_DOMAIN"),
            &ResponseCode::NOT_IMPLEMENTED => write!(f, "NOT_IMPLEMENTED"),
            &ResponseCode::QUERY_REFUSED  => write!(f, "QUERY_REFUSED"),
            &ResponseCode::YXDOMAIN  => write!(f, "YXDOMAIN"),
            &ResponseCode::YXRRSET  => write!(f, "YXRRSET"),
            &ResponseCode::NXRRSET  => write!(f, "NXRRSET"),
            &ResponseCode::NOT_AUTH  => write!(f, "NOT_AUTH"),
            &ResponseCode::NOT_ZONE  => write!(f, "NOT_ZONE"),

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
        match self {
            &ResponseCode::OK => write!(f, "No Error [RFC1035]"),
            &ResponseCode::FORMAT_ERROR => write!(f, "Format Error [RFC1035]"),
            &ResponseCode::SERVER_FAILURE => write!(f, "Server Failure [RFC1035]"),
            &ResponseCode::NON_EXISTENT_DOMAIN => write!(f, "Non-Existent Domain [RFC1035]"),
            &ResponseCode::NOT_IMPLEMENTED => write!(f, "Not Implemented [RFC1035]"),
            &ResponseCode::QUERY_REFUSED  => write!(f, "Query Refused [RFC1035]"),
            &ResponseCode::YXDOMAIN  => write!(f, "Name Exists when it should not [RFC2136] [RFC6672]"),
            &ResponseCode::YXRRSET  => write!(f, "RR Set Exists when it should not [RFC2136]"),
            &ResponseCode::NXRRSET  => write!(f, "RR Set that should exist does not [RFC2136]"),
            &ResponseCode::NOT_AUTH  => write!(f, "Server Not Authoritative for zone [RFC2136]"),
            &ResponseCode::NOT_ZONE  => write!(f, "Name not contained in zone [RFC2136]"),

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

// DNS RCODEs
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
// 2.3.  RCODE Assignment
// https://tools.ietf.org/html/rfc6895#section-2.3
// 
// It would appear from the DNS header above that only four bits of
// RCODE, or response/error code, are available.  However, RCODEs can
// appear not only at the top level of a DNS response but also inside
// TSIG RRs [RFC2845], TKEY RRs [RFC2930], and extended by OPT RRs
// [RFC6891].  The OPT RR provides an 8-bit extension to the 4 header
// bits, resulting in a 12-bit RCODE field, and the TSIG and TKEY RRs
// have a 16-bit field designated in their RFCs as the "Error" field.
// 
// Error codes appearing in the DNS header and in these other RR types
// all refer to the same error code space with the exception of error
// code 16, which has a different meaning in the OPT RR than in the TSIG
// RR, and error code 9, whose variations are described after the table
// below.  The duplicate assignment of 16 was accidental.  To the extent
// that any prior RFCs imply any sort of different error number space
// for the OPT, TSIG, or TKEY RRs, they are superseded by this unified
// 
// DNS error number space.  (This paragraph is the reason this document
// updates [RFC2845] and [RFC2930].)  With the existing exceptions of
// error numbers 9 and 16, the same error number must not be assigned
// for different errors even if they would only occur in different RR
// types.  See table below.
// 
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct ErrorCode(u16);

impl ErrorCode {
    /// No Error    RFC1035
    /// No error condition
    pub const OK: Self              = Self(0);
    /// Format Error    RFC1035
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
    pub fn code(&self) -> u16 {
        self.0
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
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &ErrorCode::OK => write!(f, "No Error [RFC1035]"),
            &ErrorCode::FORMAT_ERROR => write!(f, "Format Error [RFC1035]"),
            &ErrorCode::SERVER_FAILURE => write!(f, "Server Failure [RFC1035]"),
            &ErrorCode::NON_EXISTENT_DOMAIN => write!(f, "Non-Existent Domain [RFC1035]"),
            &ErrorCode::NOT_IMPLEMENTED => write!(f, "Not Implemented [RFC1035]"),
            &ErrorCode::QUERY_REFUSED  => write!(f, "Query Refused [RFC1035]"),
            &ErrorCode::YXDOMAIN  => write!(f, "Name Exists when it should not [RFC2136] [RFC6672]"),
            &ErrorCode::YXRRSET  => write!(f, "RR Set Exists when it should not [RFC2136]"),
            &ErrorCode::NXRRSET  => write!(f, "RR Set that should exist does not [RFC2136]"),
            &ErrorCode::NOT_AUTH  => write!(f, "Server Not Authoritative for zone [RFC2136]"),
            &ErrorCode::NOT_ZONE  => write!(f, "Name not contained in zone [RFC2136]"),
            &ErrorCode::DSOTYPENI  => write!(f, "DSO-TYPE Not Implemented [RFC8490]"),
            &ErrorCode::BADVERS  => write!(f, "Bad OPT Version [RFC6891]"),
            &ErrorCode::BADKEY  => write!(f, "Key not recognized [RFC2845]"),
            &ErrorCode::BADTIME  => write!(f, "Signature out of time window [RFC2845]"),
            &ErrorCode::BADMODE  => write!(f, "Bad TKEY Mode [RFC2930]"),
            &ErrorCode::BADNAME  => write!(f, "Duplicate key name [RFC2930]"),
            &ErrorCode::BADALG  => write!(f, "Algorithm not supported [RFC2930]"),
            &ErrorCode::BADTRUNC  => write!(f, "Bad Truncation [RFC4635]"),
            &ErrorCode::BADCOOKIE  => write!(f, "Bad/missing Server Cookie [RFC7873]"),

            _ => {
                if self.is_unassigned() {
                    write!(f, "Unassigned({})", self.0)
                } else if self.is_reserved() {
                    write!(f, "Reserved({})", self.0)
                } else {
                    write!(f, "Unknow({})", self.0)
                }
            },
        }
    }
}