
// RFC4035 RFC3225 RFC6840
/// EDNS Version Number
pub const EDNS_V0: u8 = 0; // EDNS(0)


bitflags! {
    /// EDNS Header Flags (16 bits)
    /// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-13
    pub struct EDNSFlags: u16 {
        // DO    1 bits
        /// DNSSEC OK
        const DO = 0b_1000_0000_0000_0000;
    }
}

impl EDNSFlags {
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
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
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

impl std::fmt::Debug for OptionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::LLQ => write!(f, "LLQ"),
            &Self::UL => write!(f, "UL"),
            &Self::NSID => write!(f, "NSID"),
            &Self::DAU => write!(f, "DAU"),
            &Self::DHU => write!(f, "DHU"),
            &Self::N3U => write!(f, "N3U"),
            &Self::EDNS_CLIENT_SUBNET => write!(f, "EDNS_CLIENT_SUBNET"),
            &Self::EDNS_EXPIRE => write!(f, "EDNS_EXPIRE"),
            &Self::COOKIE => write!(f, "COOKIE"),
            &Self::EDNS_TCP_KEEPALIVE => write!(f, "EDNS_TCP_KEEPALIVE"),
            &Self::PADDING => write!(f, "PADDING"),
            &Self::CHAIN => write!(f, "CHAIN"),
            &Self::EDNS_KEY_TAG => write!(f, "EDNS_KEY_TAG"),
            &Self::EDNS_CLIENT_TAG => write!(f, "EDNS_CLIENT_TAG"),
            &Self::EDNS_SERVER_TAG => write!(f, "EDNS_SERVER_TAG"),
            &Self::DEVICE_ID => write!(f, "DEVICE_ID"),
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

impl std::fmt::Display for OptionCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// Address Family Numbers
/// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
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

impl std::fmt::Debug for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::IPV4 => write!(f, "IPV4"),
            &Self::IPV6 => write!(f, "IPV6"),
            &Self::DOMAIN_NAME => write!(f, "DOMAIN_NAME"),
            &Self::AS => write!(f, "AS"),
            &Self::MAC48 => write!(f, "MAC48"),
            &Self::MAC64 => write!(f, "MAC64"),
            _ => {
                write!(f, "Unknow({})", self.0)
            },
        }
    }
}

impl std::fmt::Display for AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}