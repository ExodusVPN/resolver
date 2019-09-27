
pub mod header;
pub mod question;
pub mod answer;
pub mod record;

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
pub enum MessageKind {
    Query    = 0u8,
    Response = 1u8,
}


// 4 Bits
/// A four bit field that specifies kind of query in this message.
/// This value is set by the originator of a query and copied into the response.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct OpCode(u8);

impl OpCode {
    /// a standard query (QUERY)
    pub const QUERY: Self  = Self(0);
    /// an inverse query (IQUERY)
    pub const IQUERY: Self = Self(1);
    /// a server status request (STATUS)
    pub const STATUS: Self = Self(2);

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
    pub fn is_reserved(&self) -> bool {
        // 3-15            reserved for future use
        self.0 > Self::STATUS.0
    }
}

// 4 Bits
/// Response code - this 4 bit field is set as part of responses.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct ResponseCode(u8);

impl ResponseCode {
    /// No error condition
    pub const OK: Self              = Self(0);
    /// Format error - The name server was unable to interpret the query.
    pub const FORMAT_ERROR: Self    = Self(1);
    /// Server failure - The name server was unable to 
    /// process this query due to a problem with the name server.
    pub const SERVER_FAILURE: Self  = Self(2);
    /// Name Error - Meaningful only for responses from 
    /// an authoritative name server, this code signifies that the
    /// domain name referenced in the query does not exist.
    pub const NAME_ERROR: Self      = Self(3);
    /// Not Implemented - The name server does
    /// not support the requested kind of query.
    pub const NOT_IMPLEMENTED: Self = Self(4);
    /// Refused - The name server refuses to perform the specified operation for policy reasons.
    /// For example, a name server may not wish to provide the information 
    /// to the particular requester, or a name server may not wish to perform
    /// a particular operation (e.g., zone transfer) for particular data.
    pub const REFUSED: Self         = Self(5);

    pub const MAX: Self             = Self(15);

    pub fn new(code: u8) -> Self {
        assert!(code < 16);
        Self(code)
    }

    #[inline]
    pub fn code(&self) -> u8 {
        self.0
    }

    #[inline]
    pub fn is_reserved(&self) -> bool {
        // 6-15            Reserved for future use.
        self.0 > Self::REFUSED.0
    }
}
