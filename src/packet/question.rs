use crate::error::Error;
use crate::MAXIMUM_LABEL_SIZE;
use crate::MAXIMUM_NAMES_SIZE;



// 16 Bits
/// two octets containing one of the RR TYPE codes. 
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct QuestionType(pub u16);

impl QuestionType {
    // Note
    // 0   0x0000  RRTYPE zero is used as a special indicator for the SIG RR [RFC2931], RFC4034  and in other circumstances and must never be allocated for ordinary use.

    /// a host address (IPv4 Address)
    pub const A: Self     = Self(1);
    /// an authoritative name server
    pub const NS: Self    = Self(2);
    /// a mail destination (Obsolete - use MX)
    pub const MD: Self    = Self(3);
    /// a mail forwarder (Obsolete - use MX)
    pub const MF: Self    = Self(4);
    /// the canonical name for an alias
    pub const CNAME: Self = Self(5);
    /// marks the start of a zone of authority
    pub const SOA: Self   = Self(6);
    /// a mailbox domain name (EXPERIMENTAL)
    pub const MB: Self    = Self(7);
    /// a mail group member (EXPERIMENTAL)
    pub const MG: Self    = Self(8);
    /// a mail rename domain name (EXPERIMENTAL)
    pub const MR: Self    = Self(9);
    /// a null RR (EXPERIMENTAL)
    pub const NULL: Self  = Self(10);
    /// a well known service description
    pub const WKS: Self   = Self(11);
    /// a domain name pointer
    pub const PTR: Self   = Self(12);
    /// host information
    pub const HINFO: Self = Self(13);
    /// mailbox or mail list information
    pub const MINFO: Self = Self(14);
    /// mail exchange
    pub const MX: Self    = Self(15);
    /// text strings
    pub const TXT: Self   = Self(16);

    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4

    /// for Responsible Person  RFC1183
    pub const RP: Self       = Self(17);
    /// for AFS Data Base location  RFC1183 RFC5864
    pub const AFSDB: Self    = Self(18);
    /// for X.25 PSDN address   RFC1183
    pub const X25: Self      = Self(19);
    /// for ISDN address    RFC1183
    pub const ISDN: Self     = Self(20);
    /// for Route Through   RFC1183
    pub const RT: Self       = Self(21);
    /// for NSAP address, NSAP style A record    RFC1706
    pub const NSAP: Self     = Self(22);
    /// for domain name pointer, NSAP style     RFC1348 RFC1637 RFC1706
    pub const NSAP_PTR: Self = Self(23);
    /// for security signature  RFC4034 RFC3755 RFC2535  RFC2536  RFC2537 RFC2931 RFC3110 RFC3008
    pub const SIG: Self  = Self(24);
    /// for security key    RFC4034 RFC3755 RFC2535 RFC2536 RFC2537 RFC2539 RFC3008 RFC3110
    pub const KEY: Self  = Self(25);
    /// X.400 mail mapping information RFC2163
    pub const PX: Self   = Self(26);
    /// Geographical Position  RFC1712
    pub const GPOS: Self = Self(27);
    /// IPv6 Address, RFC3596
    pub const AAAA: Self = Self(28);
    /// Location Information   RFC1876
    pub const LOC: Self  = Self(29);
    /// Next Domain (OBSOLETE)  RFC3755 RFC2535
    pub const NXT: Self  = Self(30);
    /// Endpoint Identifier     [Michael_Patton][http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]      1995-06
    pub const EID: Self  = Self(31);
    /// Nimrod Locator  (Michael_Patton)[http://ana-3.lcs.mit.edu/~jnc/nimrod/dns.txt]       1995-06
    pub const NIMLOC: Self = Self(32);
    /// Server Selection    RFC2782
    pub const SRV: Self    = Self(33);
    /// ATM Address     [ ATM Forum Technical Committee, "ATM Name System, V2.0", Doc ID: AF-DANS-0152.000, July 2000. Available from and held in escrow by IANA.]
    pub const ATMA: Self   = Self(34);
    /// Naming Authority Pointer    RFC2915 RFC2168 RFC3403
    pub const NAPTR: Self  = Self(35);
    /// Key Exchanger   RFC2230
    pub const KX: Self     = Self(36);
    /// DNAME   RFC6672
    pub const DNAME: Self  = Self(39);
    /// SINK    (Donald_E_Eastlake)[http://tools.ietf.org/html/draft-eastlake-kitchen-sink]         1997-11
    pub const SINK: Self  = Self(40);
    /// OPT     RFC6891 RFC3225
    pub const OPT: Self    = Self(41);
    /// APL     RFC3123
    pub const APL: Self    = Self(42);
    /// Delegation Signer   RFC4034 RFC3658
    pub const DS: Self     = Self(43);
    /// SSH Key Fingerprint     RFC4255
    pub const SSHFP: Self  = Self(44);
    /// IPSECKEY    RFC4025
    pub const IPSECKEY: Self = Self(45);
    /// RRSIG   RFC4034 RFC3755 
    pub const RRSIG: Self    = Self(46);
    /// NSEC    RFC4034 RFC3755 
    pub const NSEC: Self     = Self(47);
    /// DNSKEY  RFC4034 RFC3755 
    pub const DNSKEY: Self   = Self(48);
    /// DHCID   RFC4701
    pub const DHCID: Self    = Self(49);
    /// NSEC3   RFC5155
    pub const NSEC3: Self    = Self(50);
    /// NSEC3PARAM  RFC5155
    pub const NSEC3PARAM: Self = Self(51);
    /// TLSA    RFC6698
    pub const TLSA: Self       = Self(52);
    /// S/MIME cert association     RFC8162
    pub const SMIMEA: Self     = Self(53);

    /// Host Identity Protocol  RFC8005
    pub const HIP: Self        = Self(55);
    /// NINFO   (Jim_Reid)  NINFO/ninfo-completed-template  2008-01-21
    pub const NINFO: Self      = Self(56);

    /// RKEY    (Jim_Reid)  RKEY/rkey-completed-template    2008-01-21
    pub const RKEY: Self       = Self(57);
    /// Trust Anchor LINK   (Wouter_Wijngaards)     TALINK/talink-completed-template    2010-02-17
    pub const TALINK: Self     = Self(58);

    /// Child DS    RFC7344   CDS/cds-completed-template  2011-06-06
    pub const CDS: Self        = Self(59);
    /// DNSKEY(s) the Child wants reflected in DS   RFC7344       2014-06-16
    pub const CDNSKEY: Self    = Self(60);
    /// OpenPGP Key     RFC7929   OPENPGPKEY/openpgpkey-completed-template    2014-08-12
    pub const OPENPGPKEY: Self = Self(61);
    /// Child-To-Parent Synchronization     RFC7477       2015-01-27
    pub const CSYNC: Self      = Self(62);
    /// message digest for DNS zone     (draft-wessels-dns-zone-digest)     ZONEMD/zonemd-completed-template    2018-12-12
    pub const ZONEMD: Self     = Self(63);

    /// RFC7208
    pub const SPF: Self     = Self(99);
    /// [IANA-Reserved]
    pub const UINFO: Self   = Self(100);
    /// [IANA-Reserved]
    pub const UID: Self     = Self(101);
    /// [IANA-Reserved]
    pub const GID: Self     = Self(102);
    /// [IANA-Reserved]
    pub const UNSPEC: Self  = Self(103);
    /// RFC6742   ILNP/nid-completed-template
    pub const NID: Self     = Self(104);
    /// RFC6742   ILNP/l32-completed-template
    pub const L32: Self     = Self(105);
    /// RFC6742   ILNP/l64-completed-template
    pub const L64: Self     = Self(106);
    /// RFC6742   ILNP/lp-completed-template
    pub const LP: Self      = Self(107);
    /// an EUI-48 address   RFC7043   EUI48/eui48-completed-template  2013-03-27
    pub const EUI48: Self   = Self(108);
    /// an EUI-64 address   RFC7043   EUI64/eui64-completed-template  2013-03-27
    pub const EUI64: Self   = Self(109);


    /// Transaction Key     RFC2930
    pub const TKEY: Self  = Self(249);
    /// Transaction Signature   RFC2845
    pub const TSIG: Self  = Self(250);
    /// incremental transfer    RFC1995
    pub const IXFR: Self  = Self(251);

    // QTYPE values
    /// A request for a transfer of an entire zone
    pub const AXFR: Self  = Self(252);
    /// A request for mailbox-related records (MB, MG or MR)
    pub const MAILB: Self = Self(253);
    /// A request for mail agent RRs (Obsolete - see MX)
    pub const MAILA: Self = Self(254);
    /// A request for all records (*)
    pub const ALL: Self   = Self(255);
    /// URI     RFC7553   URI/uri-completed-template  2011-02-22
    pub const URI: Self   = Self(256);
    /// Certification Authority Restriction     [RFC-ietf-lamps-rfc6844bis-07]  CAA/caa-completed-template  2011-04-07
    pub const CAA: Self      = Self(257);
    /// Application Visibility and Control  (Wolfgang_Riedel)   AVC/avc-completed-template  2016-02-26
    pub const AVC: Self      = Self(258);
    /// Digital Object Architecture     [draft-durand-doa-over-dns]     DOA/doa-completed-template  2017-08-30
    pub const DOA: Self      = Self(259);
    /// Automatic Multicast Tunneling Relay     [draft-ietf-mboned-driad-amt-discovery]     AMTRELAY/amtrelay-completed-template    2019-02-06
    pub const AMTRELAY: Self = Self(260);

    /// DNSSEC Trust Authorities    (Sam_Weiler)[http://cameo.library.cmu.edu/][ Deploying DNSSEC Without a Signed Root. Technical Report 1999-19, Information Networking Institute, Carnegie Mellon University, April 2004.]       2005-12-13
    pub const TA: Self    = Self(32768);
    /// DNSSEC Lookaside Validation     RFC4431
    pub const DLV: Self   = Self(32769);


    #[inline]
    pub fn is_unassigned(&self) -> bool {
        // Unassigned   54
        // Unassigned   64-98
        // Unassigned   110-248
        // Unassigned   261-32767
        // Unassigned  32770-65279
        match self.0 {
            54 | 64 ..= 98 | 110 ..= 248 | 261 ..= 32767 | 32770 ..= 65279 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_private_use(&self) -> bool {
        // Private use     65280-65534
        match self.0 {
            65280 ..= 65534 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_reserved(&self) -> bool {
        // Reserved    65535
        match self.0 {
            65535 => true,
            _ => false,
        }
    }
}

impl std::fmt::Display for QuestionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &QuestionType::A => write!(f, "A"),
            &QuestionType::NS => write!(f, "NS"),
            &QuestionType::MD => write!(f, "MD"),
            &QuestionType::MF => write!(f, "MF"),
            &QuestionType::CNAME => write!(f, "CNAME"),
            &QuestionType::SOA => write!(f, "SOA"),
            &QuestionType::MB => write!(f, "MB"),
            &QuestionType::MG => write!(f, "MG"),
            &QuestionType::MR => write!(f, "MR"),
            &QuestionType::NULL => write!(f, "NULL"),
            &QuestionType::WKS => write!(f, "WKS"),
            &QuestionType::PTR => write!(f, "PTR"),
            &QuestionType::HINFO => write!(f, "HINFO"),
            &QuestionType::MINFO => write!(f, "MINFO"),
            &QuestionType::MX => write!(f, "MX"),
            &QuestionType::TXT => write!(f, "TXT"),

            &QuestionType::RP => write!(f, "RP"),
            &QuestionType::AFSDB => write!(f, "AFSDB"),
            &QuestionType::X25 => write!(f, "X25"),
            &QuestionType::ISDN => write!(f, "ISDN"),
            &QuestionType::RT => write!(f, "RT"),
            &QuestionType::NSAP => write!(f, "NSAP"),
            &QuestionType::NSAP_PTR => write!(f, "NSAP-PTR"),
            &QuestionType::SIG => write!(f, "SIG"),
            &QuestionType::KEY => write!(f, "KEY"),
            &QuestionType::PX => write!(f, "PX"),
            &QuestionType::GPOS => write!(f, "GPOS"),
            &QuestionType::AAAA => write!(f, "AAAA"),
            &QuestionType::LOC => write!(f, "LOC"),
            &QuestionType::NXT => write!(f, "NXT"),
            &QuestionType::EID => write!(f, "EID"),
            &QuestionType::NIMLOC => write!(f, "NIMLOC"),
            &QuestionType::SRV => write!(f, "SRV"),
            &QuestionType::ATMA => write!(f, "ATMA"),
            &QuestionType::NAPTR => write!(f, "NAPTR"),
            &QuestionType::KX => write!(f, "KX"),
            &QuestionType::DNAME => write!(f, "DNAME"),
            &QuestionType::SINK => write!(f, "SINK"),
            &QuestionType::OPT => write!(f, "OPT"),
            &QuestionType::APL => write!(f, "APL"),
            &QuestionType::DS => write!(f, "DS"),
            &QuestionType::SSHFP => write!(f, "SSHFP"),
            &QuestionType::IPSECKEY => write!(f, "IPSECKEY"),
            &QuestionType::RRSIG => write!(f, "RRSIG"),
            &QuestionType::NSEC => write!(f, "NSEC"),
            &QuestionType::DNSKEY => write!(f, "DNSKEY"),
            &QuestionType::DHCID => write!(f, "DHCID"),
            &QuestionType::NSEC3 => write!(f, "NSEC3"),
            &QuestionType::NSEC3PARAM => write!(f, "NSEC3PARAM"),
            &QuestionType::TLSA => write!(f, "TLSA"),
            &QuestionType::SMIMEA => write!(f, "SMIMEA"),
            &QuestionType::HIP => write!(f, "HIP"),
            &QuestionType::NINFO => write!(f, "NINFO"),
            &QuestionType::RKEY => write!(f, "RKEY"),
            &QuestionType::TALINK => write!(f, "TALINK"),
            &QuestionType::CDS => write!(f, "CDS"),
            &QuestionType::CDNSKEY => write!(f, "CDNSKEY"),
            &QuestionType::OPENPGPKEY => write!(f, "OPENPGPKEY"),
            &QuestionType::CSYNC => write!(f, "CSYNC"),
            &QuestionType::ZONEMD => write!(f, "ZONEMD"),

            &QuestionType::SPF => write!(f, "SPF"),
            &QuestionType::UINFO => write!(f, "UINFO"),
            &QuestionType::UID => write!(f, "UID"),
            &QuestionType::GID => write!(f, "GID"),
            &QuestionType::UNSPEC => write!(f, "UNSPEC"),
            &QuestionType::NID => write!(f, "NID"),
            &QuestionType::L32 => write!(f, "L32"),
            &QuestionType::L64 => write!(f, "L64"),
            &QuestionType::LP => write!(f, "LP"),
            &QuestionType::EUI48 => write!(f, "EUI48"),
            &QuestionType::EUI64 => write!(f, "EUI64"),

            &QuestionType::TKEY => write!(f, "TKEY"),
            &QuestionType::TSIG => write!(f, "TSIG"),
            &QuestionType::IXFR => write!(f, "IXFR"),
            
            &QuestionType::AXFR => write!(f, "AXFR"),
            &QuestionType::MAILB => write!(f, "MAILB"),
            &QuestionType::MAILA => write!(f, "MAILA"),
            &QuestionType::ALL => write!(f, "ALL"),
            &QuestionType::URI => write!(f, "URI"),
            &QuestionType::CAA => write!(f, "CAA"),
            &QuestionType::AVC => write!(f, "AVC"),
            &QuestionType::DOA => write!(f, "DOA"),
            &QuestionType::AMTRELAY => write!(f, "AMTRELAY"),
            &QuestionType::TA => write!(f, "TA"),
            &QuestionType::DLV => write!(f, "DLV"),

            _ => {
                if self.is_unassigned() {
                    write!(f, "Unassigned({})", self.0)
                } else if self.is_private_use() {
                    write!(f, "PrivateUse({})", self.0)
                } else if self.is_reserved() {
                    write!(f, "Reserved({})", self.0)
                } else {
                    write!(f, "Unknow({})", self.0)
                }
            },
        }
    }
}


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
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct QuestionClass(pub u16);

impl QuestionClass {
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
}

impl std::fmt::Display for QuestionClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &QuestionClass::IN => write!(f, "IN"),
            &QuestionClass::CS => write!(f, "CS"),
            &QuestionClass::CH => write!(f, "CH"),
            &QuestionClass::HS => write!(f, "HS"),
            
            &QuestionClass::NONE => write!(f, "NONE"),
            &QuestionClass::ANY => write!(f, "ANY"),

            _ => {
                if self.is_unassigned() {
                    write!(f, "Unassigned({})", self.0)
                } else if self.is_private_use() {
                    write!(f, "PrivateUse({})", self.0)
                } else if self.is_reserved() {
                    write!(f, "Reserved({})", self.0)
                } else {
                    write!(f, "Unknow({})", self.0)
                }
            },
        }
    }
}



// 4.1.2. Question section format
// https://tools.ietf.org/html/rfc1035#section-4.1.2
// 
// The question section is used to carry the "question" in most queries,
// i.e., the parameters that define what is being asked.  The section
// contains QDCOUNT (usually 1) entries, each of the following format:
// 
//                                     1  1  1  1  1  1
//       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                                               |
//     /                     QNAME                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     QTYPE                     |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                     QCLASS                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 
// where:
// QNAME           a domain name represented as a sequence of labels, where
//                 each label consists of a length octet followed by that
//                 number of octets.  The domain name terminates with the
//                 zero length octet for the null label of the root.  Note
//                 that this field may be an odd number of octets; no
//                 padding is used.
// 
// QTYPE           a two octet code which specifies the type of the query.
//                 The values for this field include all codes valid for a
//                 TYPE field, together with some more general codes which
//                 can match more than one type of RR.
// 
/// 4.1.2. Question section format
#[derive(PartialEq, Clone)]
pub struct QuestionPacket<T: AsRef<[u8]>> {
    buffer: T
}

impl<T: AsRef<[u8]>> QuestionPacket<T> {

    #[inline]
    pub fn new_unchecked(buffer: T) -> QuestionPacket<T> {
        QuestionPacket { buffer }
    }

    #[inline]
    pub fn new_checked(buffer: T) -> Result<QuestionPacket<T>, Error> {
        let v = Self::new_unchecked(buffer);
        v.check_len()?;

        Ok(v)
    }

    #[inline]
    pub fn check_len(&self) -> Result<(), Error> {
        let data = self.buffer.as_ref();
        let min_size = self.last_label_offset()? + 1 + 2 + 2;
        
        if data.len() < min_size {
            return Err(Error::Truncated);
        }

        Ok(())
    }

    #[inline]
    pub fn into_inner(self) -> T {
        self.buffer
    }

    fn last_label_offset(&self) -> Result<usize, Error> {
        let data = self.buffer.as_ref();

        let mut names_length = 0;
        let mut labels_count = 0;
        let mut idx = 0usize;
        loop {
            if idx >= data.len() {
                return Err(Error::Truncated);
            }

            let len = data[idx] as usize;
            if len == 0 {
                break;
            }

            if len > MAXIMUM_LABEL_SIZE {
                return Err(Error::LabelSizeLimitExceeded);
            }

            let start = idx + 1;

            idx += len + 1;
            labels_count += 1;
            names_length += len;

            let end = idx;
            match &data.get(start..end) {
                Some(s) => {
                    if let Err(_) = std::str::from_utf8(s) {
                        return Err(Error::InvalidUtf8Sequence);
                    }
                },
                None => return Err(Error::Truncated),
            }
        }

        if names_length + labels_count - 1 > MAXIMUM_NAMES_SIZE {
            return Err(Error::NamesSizeLimitExceeded);
        }

        Ok(idx)
    }

    #[inline]
    pub fn qtype(&self) -> QuestionType {
        let data = self.buffer.as_ref();

        let offset = self.last_label_offset().unwrap() + 1;
        QuestionType(u16::from_be_bytes([ data[offset + 0], data[offset + 1] ]))
    }

    #[inline]
    pub fn qclass(&self) -> QuestionClass {
        let data = self.buffer.as_ref();

        let offset = self.last_label_offset().unwrap() + 1 + 2;
        QuestionClass(u16::from_be_bytes([ data[offset + 0], data[offset + 1] ]))
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> QuestionPacket<&'a T> {
    #[inline]
    pub fn labels(&self) -> Labels<'a> {
        let offset = self.last_label_offset().unwrap() + 1;
        let data = self.buffer.as_ref();
        Labels {
            offset: 0,
            data: &data[..offset],
        }
    }

    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2;

        let data = self.buffer.as_ref();
        &data[offset..]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> QuestionPacket<T> {
    #[inline]
    pub fn set_names(&mut self, value: &str) {
        assert!(value.len() <= MAXIMUM_NAMES_SIZE);
        let data = self.buffer.as_mut();

        let mut offset = 0usize;
        for label in value.split('.') {
            assert!(label.len() <= MAXIMUM_LABEL_SIZE);

            data[offset] = label.len() as u8;
            let start = offset + 1;
            let end = start + label.len();

            &mut data[start..end].copy_from_slice(label.as_bytes());
            offset += 1 + label.len();
        }

        if data[offset] != 0 {
            data[offset] = 0;
        }
    }

    #[inline]
    pub fn set_qtype(&mut self, value: QuestionType) {
        let offset = self.last_label_offset().unwrap() + 1;
        let data = self.buffer.as_mut();
        let octets = value.0.to_be_bytes();

        // NOTE: 确保名字先存储了！
        assert_eq!(data[offset-1], 0);

        data[offset + 0] = octets[0];
        data[offset + 1] = octets[1];
    }

    #[inline]
    pub fn set_qclass(&mut self, value: QuestionClass) {
        let offset = self.last_label_offset().unwrap() + 1 + 2;
        let data = self.buffer.as_mut();
        let octets = value.0.to_be_bytes();

        // NOTE: 确保名字先存储了！
        assert_eq!(data[offset-3], 0);

        data[offset + 0] = octets[0];
        data[offset + 1] = octets[1];
    }

    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8]{
        let offset = self.last_label_offset().unwrap() + 1 + 2 + 2;

        let data = self.buffer.as_mut();
        
        &mut data[offset..]
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Debug for QuestionPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QuestionPacket {{ labels: {:?}, qtype: {:?}, qclass: {:?} }}",
                self.labels().collect::<Vec<&str>>(),
                self.qtype(),
                self.qclass(),
        )
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> std::fmt::Display for QuestionPacket<&'a T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "QuestionPacket {{ labels: {:?}, qtype: {}, qclass: {} }}",
                self.labels().collect::<Vec<&str>>(),
                self.qtype(),
                self.qclass(),
        )
    }
}


#[derive(Debug, Eq, Hash, Clone, Copy)]
pub struct Labels<'a> {
    pub(crate) offset: usize,
    pub(crate) data: &'a [u8],
}

impl<'a> PartialEq for Labels<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<'a> Iterator for Labels<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data[self.offset] == 0 {
            return None;
        }

        let len = self.data[self.offset] as usize;
        let start = self.offset + 1;
        let end = start + len;

        self.offset += 1 + len;
        let s = &self.data[start..end];

        Some(unsafe { std::str::from_utf8_unchecked(s) })
    }
}



#[test]
fn test_question_packet() {
    let mut buffer = [0u8; 1024];

    let mut pkt = QuestionPacket::new_unchecked(&mut buffer[..]);
    pkt.set_names("www.example.com");
    pkt.set_qtype(QuestionType(111));
    pkt.set_qclass(QuestionClass(222));

    let buffer = pkt.into_inner();
    let pkt = QuestionPacket::new_checked(&buffer[..]);
    assert!(pkt.is_ok());

    let pkt = pkt.unwrap();
    assert_eq!(pkt.labels().collect::<Vec<&str>>().join("."), "www.example.com");
    assert_eq!(pkt.qtype(), QuestionType(111));
    assert_eq!(pkt.qclass(), QuestionClass(222));
}

