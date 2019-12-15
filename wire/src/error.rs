use std::io;
use std::fmt;
use std::error;


pub struct Error {
    repr: Repr,
}

#[derive(Debug)]
struct Custom {
    kind: ErrorKind,
    cause: Box<dyn error::Error + Send + Sync>,
}

#[derive(Debug)]
enum Repr {
    IO(io::Error),
    Simple(ErrorKind),
    Custom(Box<Custom>),
}


#[derive(Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Clone, Copy)]
pub enum ErrorKind {
    /// An operation cannot proceed because a buffer is empty or full.
    Exhausted,
    /// An incoming packet could not be parsed because some of its fields were out of bounds of the received data.
    Truncated,
    /// An incoming packet could not be recognized and was dropped.
    Unrecognized,
    /// An incoming packet was recognized but was self-contradictory.
    Malformed,
    /// An operation is not permitted in the current state.
    Illegal,
    
    // Response Code

    /// The name server was unable to interpret the query.
    FormatError,
    /// The name server was unable to process this query due to a problem with the name server.
    ServerFailure,
    /// Meaningful only for responses from an authoritative name server,
    /// this code signifies that the domain name referenced in the query does not exist.
    NonExistentDomain,
    /// The name server does not support the requested kind of query
    NotImplemented,
    /// The name server refuses to perform the specified operation for policy reasons.
    QueryRefused,
    /// Name Exists when it should not  RFC2136 RFC6672
    YXDomain,
    /// RR Set Exists when it should not RFC2136
    YXRRSet,
    /// RR Set that should exist does not RFC2136
    NXRRSet,
    /// Not Authorized  RFC2845
    NotAuthorized,
    /// Name not contained in zone  RFC2136
    NotZone,
    /// DSO-TYPE Not Implemented    RFC8490
    DsoTypeNotImplemented,
    /// Bad OPT Version RFC6891
    BadOptVersion,
    /// Key not recognized  RFC2845
    BadKey,
    /// Signature out of time window RFC2845
    BadTime,
    /// Bad TKEY Mode   RFC2930
    BadMode,
    /// Duplicate key name  RFC2930
    BadName,
    /// Algorithm not supported  RFC2930
    BadAlgorithm,
    /// Bad Truncation  RFC4635
    BadTruncation,
    /// Bad/missing Server Cookie  RFC7873
    BadCookie,
}



impl Error {
    pub fn new<E: Into<Box<dyn error::Error + Send + Sync>>>(kind: ErrorKind, cause: E) -> Error {
        let c = Box::new(Custom { kind, cause: cause.into() });
        Self { repr: Repr::Custom(c) }
    }

    pub fn kind(&self) -> ErrorKind {
        match self.repr {
            Repr::IO(_) => ErrorKind::FormatError,
            Repr::Simple(kind) => kind,
            Repr::Custom(ref c) => c.kind,
        }
    }
    
    pub fn cause(&self) -> Option<&(dyn error::Error + Send + Sync + 'static)> {
        match self.repr {
            Repr::IO(_) => None,
            Repr::Simple(_) => None,
            Repr::Custom(ref c) => Some(&*c.cause),
        }
    }

    pub fn io_error(&self) -> Option<&io::Error> {
        match self.repr {
            Repr::IO(ref i) => Some(i),
            Repr::Custom(..) => None,
            Repr::Simple(..) => None,
        }
    }


    pub fn get_ref(&self) -> Option<&(dyn error::Error + Send + Sync + 'static)> {
        match self.repr {
            Repr::IO(..) => None,
            Repr::Simple(..) => None,
            Repr::Custom(ref c) => Some(&*c.cause),
        }
    }


    pub fn get_mut(&mut self) -> Option<&mut (dyn error::Error + Send + Sync + 'static)> {
        match self.repr {
            Repr::IO(..) => None,
            Repr::Simple(..) => None,
            Repr::Custom(ref mut c) => Some(&mut *c.cause),
        }
    }

    pub fn into_inner(self) -> Option<Box<dyn error::Error + Send + Sync>> {
        match self.repr {
            Repr::IO(..) => None,
            Repr::Simple(..) => None,
            Repr::Custom(c) => Some(c.cause),
        }
    }


}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.repr {
            Repr::IO(ref e) => e.fmt(f),
            Repr::Simple(kind) => f.debug_tuple("Kind").field(&kind).finish(),
            Repr::Custom(ref c) => c.fmt(f),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.repr {
            Repr::IO(ref e) => e.fmt(f),
            Repr::Simple(kind) => write!(f, "{:?}", &kind),
            Repr::Custom(ref c) => c.cause.fmt(f),
        }
    }
}


impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self.repr {
            Repr::IO(..) => None,
            Repr::Simple(..) => None,
            Repr::Custom(ref c) => c.cause.source(),
        }
    }
}


impl From<ErrorKind> for Error {
    #[inline]
    fn from(kind: ErrorKind) -> Error {
        Error { repr: Repr::Simple(kind) }
    }
}

impl From<io::Error> for Error {
    #[inline]
    fn from(e: io::Error) -> Error {
        Error { repr: Repr::IO(e) }
    }
}
