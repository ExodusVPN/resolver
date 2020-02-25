
// 4 Bits
/// A four bit field that specifies kind of query in this message.
/// This value is set by the originator of a query and copied into the response.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
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
    /// an inverse query (IQUERY), obsoleted
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

    #[inline]
    pub fn new(code: u8) -> Self {
        if code >= 16 {
            debug!("invalid OpCode.");
        }
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

impl std::fmt::Debug for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::QUERY => write!(f, "QUERY"),
            &Self::IQUERY => write!(f, "IQUERY"),
            &Self::STATUS => write!(f, "STATUS"),
            &Self::NOTIFY => write!(f, "NOTIFY"),
            &Self::UPDATE => write!(f, "UPDATE"),
            &Self::DNS_STATEFUL_OPERATIONS => write!(f, "DNS_STATEFUL_OPERATIONS"),
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

impl std::fmt::Display for OpCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}