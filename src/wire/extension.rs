use crate::error::Error;
use crate::wire::Kind;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};



// RFC4035 RFC3225 RFC6840
/// EDNS Version Number
pub const EXT_HEADER_V0: u8 = 0; // EDNS(0)


bitflags! {
    /// EDNS Header Flags (16 bits)
    /// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-13
    pub struct ExtensionFlags: u16 {
        // DO    1 bits
        /// DNSSEC OK
        const DO = 0b_1000_0000_0000_0000;
    }
}

impl ExtensionFlags {
    pub fn new_unchecked(bits: u16) -> Self {
        unsafe {
            Self::from_bits_unchecked(bits)
        }
    }

    // 1 bits
    /// DNSSEC OK
    pub fn do_(&self) -> bool {
        self.bits >> 15 == 1
    }

    pub fn set_do(&mut self, value: bool) {
        if value {
            self.bits |= Self::DO.bits;
        } else {
            self.bits &= 0b_0111_1111_1111_1111;
        }
    }
}


/// DNS EDNS0 Option Codes (OPT)
/// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct OptionCode(pub u16);

impl OptionCode {
    // [RFC6891] [RFC Errata 3604]
    // 
    // Value        Name                Status      Reference 
    // 
    // 0            Reserved                        [RFC6891]
    // 1            LLQ                 Optional    [RFC-sekar-dns-llq-06]
    // 2            UL                  On-hold     [http://files.dns-sd.org/draft-sekar-dns-ul.txt]
    // 3            NSID                Standard    [RFC5001]
    // 4            Reserved                        [draft-cheshire-edns0-owner-option]
    // 5            DAU                 Standard    [RFC6975]
    // 6            DHU                 Standard    [RFC6975]
    // 7            N3U                 Standard    [RFC6975]
    // 8            edns-client-subnet  Optional    [RFC7871]
    // 9            EDNS EXPIRE         Optional    [RFC7314]
    // 10           COOKIE              Standard    [RFC7873]
    // 11           edns-tcp-keepalive  Standard    [RFC7828]
    // 12           Padding             Standard    [RFC7830]
    // 13           CHAIN               Standard    [RFC7901]
    // 14           edns-key-tag        Optional    [RFC8145]
    // 15           Unassigned
    // 16           EDNS-Client-Tag     Optional    [draft-bellis-dnsop-edns-tags]
    // 17           EDNS-Server-Tag     Optional    [draft-bellis-dnsop-edns-tags]
    // 18-26945     Unassigned
    // 26946        DeviceID            Optional    [https://docs.umbrella.com/developer/networkdevices-api/identifying-dns-traffic2][Brian_Hartvigsen]
    // 26947-65000  Unassigned
    // 65001-65534  Reserved for Local/Experimental Use         [RFC6891]
    // 65535        Reserved for future expansion               [RFC6891]

    pub const LLQ: Self                = Self(1);
    pub const UL: Self                 = Self(2);
    pub const NSID: Self               = Self(3);

    pub const DAU: Self                = Self(5);
    pub const DHU: Self                = Self(6);
    pub const N3U: Self                = Self(7);
    /// EDNS Client Subnet   RFC7871
    pub const EDNS_CLIENT_SUBNET: Self = Self(8);
    pub const EDNS_EXPIRE: Self        = Self(9);
    pub const COOKIE: Self             = Self(10);
    pub const EDNS_TCP_KEEPALIVE: Self = Self(11);
    pub const PADDING: Self            = Self(12);
    pub const CHAIN: Self              = Self(13);
    pub const EDNS_KEY_TAG: Self       = Self(14);

    pub const EDNS_CLIENT_TAG: Self    = Self(16);
    pub const EDNS_SERVER_TAG: Self    = Self(17);

    pub const DEVICE_ID: Self          = Self(26946);

    #[inline]
    pub const fn new(code: u16) -> Self {
        Self(code)
    }

    #[inline]
    pub fn code(&self) -> u16 {
        self.0
    }

    #[inline]
    pub fn is_unassigned(&self) -> bool {
        // 15           Unassigned
        // 18-26945     Unassigned
        // 26947-65000  Unassigned
        match self.0 {
            15 | 18 ..= 26945 | 26947 ..= 65000 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_reserved(&self) -> bool {
        // 0            Reserved                        [RFC6891]
        // 4            Reserved                        [draft-cheshire-edns0-owner-option]
        // 65001-65534  Reserved for Local/Experimental Use         [RFC6891]
        // 65535        Reserved for future expansion               [RFC6891]
        match self.0 {
            0 | 4 | 65001 ..= 65534 | 65535 => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for OptionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &OptionCode::LLQ => write!(f, "LLQ"),
            &OptionCode::UL => write!(f, "UL"),
            &OptionCode::NSID => write!(f, "NSID"),
            &OptionCode::DAU => write!(f, "DAU"),
            &OptionCode::DHU => write!(f, "DHU"),
            &OptionCode::N3U => write!(f, "N3U"),
            &OptionCode::EDNS_CLIENT_SUBNET => write!(f, "EDNS_CLIENT_SUBNET"),
            &OptionCode::EDNS_EXPIRE => write!(f, "EDNS_EXPIRE"),
            &OptionCode::COOKIE => write!(f, "COOKIE"),
            &OptionCode::EDNS_TCP_KEEPALIVE => write!(f, "EDNS_TCP_KEEPALIVE"),
            &OptionCode::PADDING => write!(f, "PADDING"),
            &OptionCode::CHAIN => write!(f, "CHAIN"),
            &OptionCode::EDNS_KEY_TAG => write!(f, "EDNS_KEY_TAG"),
            &OptionCode::EDNS_CLIENT_TAG => write!(f, "EDNS_CLIENT_TAG"),
            &OptionCode::EDNS_SERVER_TAG => write!(f, "EDNS_SERVER_TAG"),
            &OptionCode::DEVICE_ID => write!(f, "DEVICE_ID"),
            _ => {
                if self.is_unassigned() {
                    write!(f, "Unassigned({})", self.0)
                } else if self.is_reserved() {
                    write!(f, "Reserved({})", self.0)
                } else {
                    unreachable!()
                }
            },
        }
    }
}

/// Address Family Numbers
/// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct AddressFamily(pub u16);

impl AddressFamily {
    pub const IPV4: Self = Self(1);
    pub const IPV6: Self = Self(2);
    /// DNS (Domain Name System)
    pub const DOMAIN_NAME: Self = Self(16);
    /// AS Number   Charles_Lynn
    pub const AS: Self          = Self(18);
    /// 48-bit MAC  RFC7042   2013-05-06
    pub const MAC48: Self       = Self(16389);
    /// 64-bit MAC  RFC7042   2013-05-06
    pub const MAC64: Self       = Self(16390);

    pub fn is_ipv4(&self) -> bool {
        match self {
            &Self::IPV4 => true,
            _ => false,
        }
    }

    pub fn is_ipv6(&self) -> bool {
        match self {
            &Self::IPV6 => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &AddressFamily::IPV4 => write!(f, "IPV4"),
            &AddressFamily::IPV6 => write!(f, "IPV6"),
            &AddressFamily::DOMAIN_NAME => write!(f, "DOMAIN_NAME"),
            &AddressFamily::AS => write!(f, "AS"),
            &AddressFamily::MAC48 => write!(f, "MAC48"),
            &AddressFamily::MAC64 => write!(f, "MAC64"),
            _ => {
                write!(f, "Unknow({})", self.0)
            },
        }
    }
}

// Extension Mechanisms for DNS (EDNS(0))
// 
// 6.1.  OPT Record Definition
// https://tools.ietf.org/html/rfc6891#section-6.1
// 
//    An OPT RR has a fixed part and a variable set of options expressed as
//    {attribute, value} pairs.  The fixed part holds some DNS metadata,
//    and also a small collection of basic extension elements that we
//    expect to be so popular that it would be a waste of wire space to
//    encode them as {attribute, value} pairs.
// 
//    The fixed part of an OPT RR is structured as follows:
// 
//        +------------+--------------+------------------------------+
//        | Field Name | Field Type   | Description                  |
//        +------------+--------------+------------------------------+
//        | NAME       | domain name  | MUST be 0 (root domain)      |
//        | TYPE       | u_int16_t    | OPT (41)                     |
//        | CLASS      | u_int16_t    | requestor's UDP payload size |
//        | TTL        | u_int32_t    | extended RCODE and flags     |
//        | RDLEN      | u_int16_t    | length of all RDATA          |
//        | RDATA      | octet stream | {attribute,value} pairs      |
//        +------------+--------------+------------------------------+
// 
//                                OPT RR Format
// 
// 
// 6.1.3.  OPT Record TTL Field Use
// 
//    The extended RCODE and flags, which OPT stores in the RR Time to Live
//    (TTL) field, are structured as follows:
// 
//                   +0 (MSB)                            +1 (LSB)
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//     0: |         EXTENDED-RCODE        |            VERSION            |
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//     2: | DO|                           Z                               |
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 
//    EXTENDED-RCODE
//       Forms the upper 8 bits of extended 12-bit RCODE (together with the
//       4 bits defined in [RFC1035].  Note that EXTENDED-RCODE value 0
//       indicates that an unextended RCODE is in use (values 0 through
//       15).
// 
//    VERSION
//       Indicates the implementation level of the setter.  Full
//       conformance with this specification is indicated by version '0'.
//       Requestors are encouraged to set this to the lowest implemented
//       level capable of expressing a transaction, to minimise the
//       responder and network load of discovering the greatest common
//       implementation level between requestor and responder.  A
//       requestor's version numbering strategy MAY ideally be a run-time
//       configuration option.
//       If a responder does not implement the VERSION level of the
//       request, then it MUST respond with RCODE=BADVERS.  All responses
//       MUST be limited in format to the VERSION level of the request, but
//       the VERSION of each response SHOULD be the highest implementation
//       level of the responder.  In this way, a requestor will learn the
//       implementation level of a responder as a side effect of every
//       response, including error responses and including RCODE=BADVERS.
// 
// 6.1.4.  Flags
// 
//    DO
//       DNSSEC OK bit as defined by [RFC3225].
// 
//    Z
//       Set to zero by senders and ignored by receivers, unless modified
//       in a subsequent specification.
// 
/// OPT Resource Record
#[derive(PartialEq, Clone)]
pub struct ExtensionPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> ExtensionPacket<T> {

    #[inline]
    pub fn new_unchecked(buffer: T) -> ExtensionPacket<T> {
        ExtensionPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<ExtensionPacket<T>, Error> {
        let v = Self::new_unchecked(buffer);
        v.check_len()?;

        Ok(v)
    }

    #[inline]
    pub fn check_len(&self) -> Result<(), Error> {
        let data = self.buffer.as_ref();
        let min_size = self.header_len();
        
        if data.len() < min_size {
            return Err(Error::Truncated);
        }

        if data.len() < self.total_len() {
            return Err(Error::Truncated);
        }

        // Check Extension Version
        if self.version() != EXT_HEADER_V0 {
            return Err(Error::Unrecognized);
        }

        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    // 16 bits
    #[inline]
    pub fn kind(&self) -> Kind {
        let data = self.buffer.as_ref();

        Kind(u16::from_be_bytes([ data[0], data[1] ]))
    }

    // 16 bits
    #[inline]
    pub fn udp_size(&self) -> u16 {
        let data = self.buffer.as_ref();

        u16::from_be_bytes([ data[2], data[3] ])
    }

    // 8 bits
    #[inline]
    pub fn rcode(&self) -> u8 {
        let data = self.buffer.as_ref();

        data[4]
    }

    // 8 bits
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();

        data[5]
    }

    // 16 bits
    #[inline]
    pub fn flags(&self) -> ExtensionFlags {
        let data = self.buffer.as_ref();

        ExtensionFlags::new_unchecked(u16::from_be_bytes([ data[6], data[7] ]))
    }

    // 16 bits
    #[inline]
    pub fn rdlen(&self) -> u16 {
        let data = self.buffer.as_ref();

        u16::from_be_bytes([ data[8], data[9] ])
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        10
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        10 + self.rdlen() as usize
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> ExtensionPacket<&'a T> {
    /// Additional RR-specific data
    #[inline]
    pub fn rdata(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();

        &data[self.header_len()..self.total_len()]
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();

        &data[self.total_len()..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ExtensionPacket<T> {
    #[inline]
    pub fn set_kind(&mut self, value: Kind) {
        assert_eq!(value, Kind::OPT);

        let data = self.buffer.as_mut();
        let octets = value.0.to_be_bytes();

        data[0] = octets[0];
        data[1] = octets[1];
    }

    #[inline]
    pub fn set_udp_size(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();
        
        data[2] = octets[0];
        data[3] = octets[1];
    }

    #[inline]
    pub fn set_rcode(&mut self, value: u8) {
        let data = self.buffer.as_mut();

        data[4] = value;
    }

    #[inline]
    pub fn set_version(&mut self, value: u8) {
        assert_eq!(value, EXT_HEADER_V0);

        let data = self.buffer.as_mut();

        data[5] = value;
    }

    #[inline]
    pub fn set_flags(&mut self, value: ExtensionFlags) {
        let data = self.buffer.as_mut();
        let octets = value.bits().to_be_bytes();
        
        data[6] = octets[0];
        data[7] = octets[1];
    }

    #[inline]
    pub fn set_rdlen(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();
        
        data[8] = octets[0];
        data[9] = octets[1];
    }

    #[inline]
    pub fn rdata_mut(&mut self) -> &mut [u8] {
        let start = self.header_len();
        let end = self.total_len();
        let data = self.buffer.as_mut();

        &mut data[start..end]
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8]{
        let start = self.header_len();
        let data = self.buffer.as_mut();
        
        &mut data[start..]
    }
}




//    The variable part of an OPT RR may contain zero or more options in
//    the RDATA.  Each option MUST be treated as a bit field.  Each option
//    is encoded as:
// 
//                   +0 (MSB)                            +1 (LSB)
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//     0: |                          OPTION-CODE                          |
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//     2: |                         OPTION-LENGTH                         |
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//     4: |                                                               |
//        /                          OPTION-DATA                          /
//        /                                                               /
//        +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 
//    OPTION-CODE
//       Assigned by the Expert Review process as defined by the DNSEXT
//       working group and the IESG.
// 
//    OPTION-LENGTH
//       Size (in octets) of OPTION-DATA.
// 
//    OPTION-DATA
//       Varies per OPTION-CODE.  MUST be treated as a bit field.
// 
//    The order of appearance of option tuples is not defined.  If one
//    option modifies the behaviour of another or multiple options are
//    related to one another in some way, they have the same effect
//    regardless of ordering in the RDATA wire encoding.
// 
//    Any OPTION-CODE values not understood by a responder or requestor
//    MUST be ignored.  Specifications of such options might wish to
//    include some kind of signaled acknowledgement.  For example, an
//    option specification might say that if a responder sees and supports
//    option XYZ, it MUST include option XYZ in its response.
// 
#[derive(PartialEq, Clone)]
pub struct ExtensionDataPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> ExtensionDataPacket<T> {

    #[inline]
    pub fn new_unchecked(buffer: T) -> ExtensionDataPacket<T> {
        ExtensionDataPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<ExtensionDataPacket<T>, Error> {
        let v = Self::new_unchecked(buffer);
        v.check_len()?;

        Ok(v)
    }

    #[inline]
    pub fn check_len(&self) -> Result<(), Error> {
        let data = self.buffer.as_ref();
        let min_size = self.header_len();
        
        if data.len() < min_size {
            return Err(Error::Truncated);
        }

        if data.len() < self.total_len() {
            return Err(Error::Truncated);
        }

        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    // 16 bits
    #[inline]
    pub fn option_code(&self) -> OptionCode {
        let data = self.buffer.as_ref();

        OptionCode(u16::from_be_bytes([ data[0], data[1] ]))
    }

    // 16 bits
    #[inline]
    pub fn option_length(&self) -> u16 {
        let data = self.buffer.as_ref();

        u16::from_be_bytes([ data[2], data[3] ])
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        4
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        self.header_len() + self.option_length() as usize
    }
}


impl<'a, T: AsRef<[u8]> + ?Sized> ExtensionDataPacket<&'a T> {
    #[inline]
    pub fn option_data(&self) -> &'a [u8] {
        let data = self.buffer.as_ref();

        &data[4..4 + self.option_length() as usize]
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let offset = 4 + self.option_length() as usize;
        let data = self.buffer.as_ref();

        &data[offset..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ExtensionDataPacket<T> {
    #[inline]
    pub fn set_option_code(&mut self, value: OptionCode) {
        let data = self.buffer.as_mut();
        let octets = value.0.to_be_bytes();
        
        data[0] = octets[0];
        data[1] = octets[1];
    }

    // 16 bits
    #[inline]
    pub fn set_option_length(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let octets = value.to_be_bytes();
        
        data[2] = octets[0];
        data[3] = octets[1];
    }

    #[inline]
    pub fn option_data_mut(&mut self) -> &mut [u8] {
        let offset = self.total_len();
        let data = self.buffer.as_mut();

        &mut data[4..offset]
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8]{
        let offset = self.total_len();
        let data = self.buffer.as_mut();
        
        &mut data[offset..]
    }
}




// 
// Client Subnet in DNS Queries
// 
// 6.  Option Format
// https://tools.ietf.org/html/rfc7871#section-6
// 
//                 +0 (MSB)                            +1 (LSB)
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    0: |                          OPTION-CODE                          |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    2: |                         OPTION-LENGTH                         |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    4: |                            FAMILY                             |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    6: |     SOURCE PREFIX-LENGTH      |     SCOPE PREFIX-LENGTH       |
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
//    8: |                           ADDRESS...                          /
//       +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
// 
// The format of the address part depends on the value of FAMILY.  This
// document only defines the format for FAMILY 1 (IPv4) and FAMILY 2 (IPv6).
// 
#[derive(PartialEq, Clone)]
pub struct ClientSubnetPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> ClientSubnetPacket<T> {

    #[inline]
    pub fn new_unchecked(buffer: T) -> ClientSubnetPacket<T> {
        ClientSubnetPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<ClientSubnetPacket<T>, Error> {
        let v = Self::new_unchecked(buffer);
        v.check_len()?;

        Ok(v)
    }

    #[inline]
    pub fn check_len(&self) -> Result<(), Error> {
        let data = self.buffer.as_ref();
        let min_size = self.header_len();
        
        if data.len() < min_size {
            return Err(Error::Truncated);
        }

        if data.len() < self.total_len() {
            return Err(Error::Truncated);
        }

        // Check Address family
        let addr_family = self.family();
        if !addr_family.is_ipv4() && !addr_family.is_ipv6() {
            return Err(Error::Unrecognized);
        }
        
        // Check prefix len
        match addr_family {
            AddressFamily::IPV4 => {
                if self.src_prefixlen() > 32 || self.scope_prefixlen() > 32 {
                    return Err(Error::Unrecognized);
                }
            },
            AddressFamily::IPV6 => {
                if self.src_prefixlen() > 128 || self.scope_prefixlen() > 128 {
                    return Err(Error::Unrecognized);
                }
            },
            _ => return Err(Error::Unrecognized),
        }
        
        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    // 16 bits
    #[inline]
    pub fn family(&self) -> AddressFamily {
        let data = self.buffer.as_ref();

        AddressFamily(u16::from_be_bytes([ data[0], data[1] ]))
    }

    // 8 bits
    #[inline]
    pub fn src_prefixlen(&self) -> u8 {
        // SOURCE PREFIX-LENGTH
        let data = self.buffer.as_ref();
        data[2]
    }

    // 8 bits
    #[inline]
    pub fn scope_prefixlen(&self) -> u8 {
        // SCOPE PREFIX-LENGTH
        let data = self.buffer.as_ref();
        data[3]
    }

    #[inline]
    pub fn address(&self) -> IpAddr {
        let data = self.buffer.as_ref();

        match self.family() {
            AddressFamily::IPV4 => {
                let a = data[4];
                let b = data[5];
                let c = data[6];
                let d = data[7];

                IpAddr::V4(Ipv4Addr::new(a, b, c, d))
            },
            AddressFamily::IPV6 => {
                let mut octets = [0u8; 16];
                &mut octets.copy_from_slice(&data[4.. 4 + 16]);

                IpAddr::V6(Ipv6Addr::from(octets))
            },
            _ => unreachable!(),
        }
    }

    #[inline]
    pub fn header_len(&self) -> usize {
        4
    }

    #[inline]
    pub fn total_len(&self) -> usize {
        match self.family() {
            AddressFamily::IPV4 => self.header_len() + 4,
            AddressFamily::IPV6 => self.header_len() + 16,
            _ => unreachable!(),
        }
    }
}


impl<'a, T: AsRef<[u8]> + ?Sized> ClientSubnetPacket<&'a T> {
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let offset = self.total_len();
        let data = self.buffer.as_ref();

        &data[offset..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> ClientSubnetPacket<T> {

    #[inline]
    pub fn set_family(&mut self, value: AddressFamily) {
        let data = self.buffer.as_mut();
        let octets = value.0.to_be_bytes();
        
        data[0] = octets[0];
        data[1] = octets[1];
    }

    #[inline]
    pub fn set_src_prefixlen(&mut self, value: u8) {
        let data = self.buffer.as_mut();

        data[2] = value;
    }

    #[inline]
    pub fn set_scope_prefixlen(&mut self, value: u8) {
        let data = self.buffer.as_mut();

        data[3] = value;
    }

    #[inline]
    pub fn set_address(&mut self, value: IpAddr) {
        let family = self.family();
        let data = self.buffer.as_mut();
        match value {
            IpAddr::V4(v4_addr) => {
                assert_eq!(family, AddressFamily::IPV4);
                let octets = v4_addr.octets();
                
                data[4] = octets[0];
                data[5] = octets[1];
                data[6] = octets[2];
                data[7] = octets[3];
            },
            IpAddr::V6(v6_addr) => {
                assert_eq!(family, AddressFamily::IPV6);
                let octets = v6_addr.octets();

                &mut data[4..4+16].copy_from_slice(&octets);
            }
        }
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8]{
        let offset = self.total_len();
        let data = self.buffer.as_mut();
        
        &mut data[offset..]
    }
}



impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Debug for ExtensionPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExtensionPacket {{ kind: {:?}, udp_size: {:?}, rcode: {:?}, version: {:?}, flags: {:?}, rdlen: {:?}, rdata: {:?} }}",
                self.kind(),
                self.udp_size(),
                self.rcode(),
                self.version(),
                self.flags(),
                self.rdlen(),
                self.rdata(),
        )
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for ExtensionPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExtensionPacket {{ kind: {}, udp_size: {:?}, rcode: {:?}, version: {:?}, flags: {:?}, rdlen: {:?}, rdata: {:?} }}",
                self.kind(),
                self.udp_size(),
                self.rcode(),
                self.version(),
                self.flags(),
                self.rdlen(),
                self.rdata(),
        )
    }
}


impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Debug for ExtensionDataPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExtensionDataPacket {{ option_code: {:?}, option_length: {:?}, option_data: {:?} }}",
                self.option_code(),
                self.option_length(),
                self.option_data(),
        )
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for ExtensionDataPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExtensionDataPacket {{ option_code: {}, option_length: {:?}, option_data: {:?} }}",
                self.option_code(),
                self.option_length(),
                self.option_data(),
        )
    }
}


impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Debug for ClientSubnetPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientSubnetPacket {{ family: {:?}, src_prefixlen: {:?}, scope_prefixlen: {:?}, address: {:?} }}",
                self.family(),
                self.src_prefixlen(),
                self.scope_prefixlen(),
                self.address(),
        )
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for ClientSubnetPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ClientSubnetPacket {{ family: {}, src_prefixlen: {:?}, scope_prefixlen: {:?}, address: {} }}",
                self.family(),
                self.src_prefixlen(),
                self.scope_prefixlen(),
                self.address(),
        )
    }
}