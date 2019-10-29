use crate::wire::ResponseCode;


#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Error {
    // 63 octets or less
    LabelSizeLimitExceeded,
    // 255 octets or less
    NamesSizeLimitExceeded,
    // 512 octets or less
    UdpMessagesSizeLimitExceeded,
    InvalidDomainName,
    InvalidDomainNameLabel,
    InvalidUtf8Sequence,
    InvalidLabelKind,
    InvalidExtLabelKind,
    InvalidHinfoRecord,
    InvalidAlgorithm,
    /// An incoming packet could not be parsed because some of its fields were out of bounds of the received data.
    Truncated,
    /// An incoming packet could not be recognized and was dropped.
    Unrecognized,

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

impl Into<ResponseCode> for Error {
    fn into(self) -> ResponseCode {
        match self {
            Error::LabelSizeLimitExceeded => ResponseCode::FORMAT_ERROR,
            Error::NamesSizeLimitExceeded => ResponseCode::FORMAT_ERROR,
            Error::UdpMessagesSizeLimitExceeded => ResponseCode::FORMAT_ERROR,
            Error::InvalidDomainName => ResponseCode::FORMAT_ERROR,
            Error::InvalidDomainNameLabel => ResponseCode::FORMAT_ERROR,
            Error::InvalidUtf8Sequence => ResponseCode::FORMAT_ERROR,
            Error::InvalidLabelKind => ResponseCode::FORMAT_ERROR,
            Error::InvalidExtLabelKind => ResponseCode::FORMAT_ERROR,
            Error::InvalidHinfoRecord => ResponseCode::FORMAT_ERROR,
            Error::InvalidAlgorithm => ResponseCode::BADALG,
            Error::Truncated => ResponseCode::FORMAT_ERROR,
            Error::Unrecognized => ResponseCode::FORMAT_ERROR,

            Error::FormatError => ResponseCode::FORMAT_ERROR,
            Error::ServerFailure => ResponseCode::SERVER_FAILURE,
            Error::NonExistentDomain => ResponseCode::NON_EXISTENT_DOMAIN,
            Error::NotImplemented => ResponseCode::NOT_IMPLEMENTED,
            Error::QueryRefused => ResponseCode::QUERY_REFUSED,
            Error::YXDomain => ResponseCode::YXDOMAIN,
            Error::YXRRSet => ResponseCode::YXRRSET,
            Error::NXRRSet => ResponseCode::NXRRSET,
            Error::NotAuthorized => ResponseCode::NOT_AUTH,
            Error::NotZone => ResponseCode::NOT_ZONE,
            Error::DsoTypeNotImplemented => ResponseCode::DSOTYPENI,
            Error::BadOptVersion => ResponseCode::BADVERS,
            Error::BadKey => ResponseCode::BADKEY,
            Error::BadTime => ResponseCode::BADTIME,
            Error::BadMode => ResponseCode::BADMODE,
            Error::BadName => ResponseCode::BADNAME,
            Error::BadAlgorithm => ResponseCode::BADALG,
            Error::BadTruncation => ResponseCode::BADTRUNC,
            Error::BadCookie => ResponseCode::BADCOOKIE,
        }
    }
}

impl std::convert::TryFrom<ResponseCode> for Error {
    type Error = Error;

    fn try_from(value: ResponseCode) -> Result<Self, Self::Error> {
        match value {
            ResponseCode::OK           => Err(Error::ServerFailure),
            ResponseCode::FORMAT_ERROR => Ok(Error::FormatError),
            ResponseCode::SERVER_FAILURE => Ok(Error::ServerFailure),
            ResponseCode::NON_EXISTENT_DOMAIN => Ok(Error::NonExistentDomain),
            ResponseCode::NOT_IMPLEMENTED => Ok(Error::NotImplemented),
            ResponseCode::QUERY_REFUSED => Ok(Error::QueryRefused),
            ResponseCode::YXDOMAIN => Ok(Error::YXDomain),
            ResponseCode::YXRRSET => Ok(Error::YXRRSet),
            ResponseCode::NXRRSET => Ok(Error::NXRRSet),
            ResponseCode::NOT_AUTH => Ok(Error::NotAuthorized),
            ResponseCode::NOT_ZONE => Ok(Error::NotZone),
            ResponseCode::DSOTYPENI => Ok(Error::DsoTypeNotImplemented),
            ResponseCode::BADVERS => Ok(Error::BadOptVersion),
            ResponseCode::BADKEY => Ok(Error::BadKey),
            ResponseCode::BADTIME => Ok(Error::BadTime),
            ResponseCode::BADMODE => Ok(Error::BadMode),
            ResponseCode::BADNAME => Ok(Error::BadName),
            ResponseCode::BADALG => Ok(Error::BadAlgorithm),
            ResponseCode::BADTRUNC => Ok(Error::BadTruncation),
            ResponseCode::BADCOOKIE => Ok(Error::BadCookie),

            _ => Ok(Error::ServerFailure),
        }
    }
}