
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
    /// An incoming packet could not be parsed because some of its fields were out of bounds of the received data.
    Truncated,
    /// An incoming packet could not be recognized and was dropped.
    Unrecognized,
}

