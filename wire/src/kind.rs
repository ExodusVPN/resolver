use crate::error::Error;
use crate::error::ErrorKind;


// 16 Bits
/// two octets containing one of the RR TYPE codes. 
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct Kind(pub u16);

impl Kind {
    // Note
    // 0   0x0000  RRTYPE zero is used as a special indicator for the SIG RR RFC2931, 
    //             RFC4034 and in other circumstances and must never be allocated for ordinary use.

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
    pub fn is_pseudo_record_kind(&self) -> bool {
        // Other types and pseudo resource records
        // https://en.wikipedia.org/wiki/List_of_DNS_record_types#Other_types_and_pseudo_resource_records
        // 
        // *        255     RFC 1035[1]     All cached records 
        // AXFR     252     RFC 1035[1]     Authoritative Zone Transfer 
        // IXFR     251     RFC 1996        Incremental Zone Transfer
        // OPT      41      RFC 6891        Option 
        match *self {
            Self::ALL | Self::AXFR | Self::IXFR | Self::OPT => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_unassigned(&self) -> bool {
        // Unassigned   54
        // Unassigned   64-98
        // Unassigned   110-248
        // Unassigned   261-32767
        // Unassigned   32770-65279
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

impl std::fmt::Debug for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Kind::A => write!(f, "A"),
            &Kind::NS => write!(f, "NS"),
            &Kind::MD => write!(f, "MD"),
            &Kind::MF => write!(f, "MF"),
            &Kind::CNAME => write!(f, "CNAME"),
            &Kind::SOA => write!(f, "SOA"),
            &Kind::MB => write!(f, "MB"),
            &Kind::MG => write!(f, "MG"),
            &Kind::MR => write!(f, "MR"),
            &Kind::NULL => write!(f, "NULL"),
            &Kind::WKS => write!(f, "WKS"),
            &Kind::PTR => write!(f, "PTR"),
            &Kind::HINFO => write!(f, "HINFO"),
            &Kind::MINFO => write!(f, "MINFO"),
            &Kind::MX => write!(f, "MX"),
            &Kind::TXT => write!(f, "TXT"),
            &Kind::RP => write!(f, "RP"),
            &Kind::AFSDB => write!(f, "AFSDB"),
            &Kind::X25 => write!(f, "X25"),
            &Kind::ISDN => write!(f, "ISDN"),
            &Kind::RT => write!(f, "RT"),
            &Kind::NSAP => write!(f, "NSAP"),
            &Kind::NSAP_PTR => write!(f, "NSAP-PTR"),
            &Kind::SIG => write!(f, "SIG"),
            &Kind::KEY => write!(f, "KEY"),
            &Kind::PX => write!(f, "PX"),
            &Kind::GPOS => write!(f, "GPOS"),
            &Kind::AAAA => write!(f, "AAAA"),
            &Kind::LOC => write!(f, "LOC"),
            &Kind::NXT => write!(f, "NXT"),
            &Kind::EID => write!(f, "EID"),
            &Kind::NIMLOC => write!(f, "NIMLOC"),
            &Kind::SRV => write!(f, "SRV"),
            &Kind::ATMA => write!(f, "ATMA"),
            &Kind::NAPTR => write!(f, "NAPTR"),
            &Kind::KX => write!(f, "KX"),
            &Kind::DNAME => write!(f, "DNAME"),
            &Kind::SINK => write!(f, "SINK"),
            &Kind::OPT => write!(f, "OPT"),
            &Kind::APL => write!(f, "APL"),
            &Kind::DS => write!(f, "DS"),
            &Kind::SSHFP => write!(f, "SSHFP"),
            &Kind::IPSECKEY => write!(f, "IPSECKEY"),
            &Kind::RRSIG => write!(f, "RRSIG"),
            &Kind::NSEC => write!(f, "NSEC"),
            &Kind::DNSKEY => write!(f, "DNSKEY"),
            &Kind::DHCID => write!(f, "DHCID"),
            &Kind::NSEC3 => write!(f, "NSEC3"),
            &Kind::NSEC3PARAM => write!(f, "NSEC3PARAM"),
            &Kind::TLSA => write!(f, "TLSA"),
            &Kind::SMIMEA => write!(f, "SMIMEA"),
            &Kind::HIP => write!(f, "HIP"),
            &Kind::NINFO => write!(f, "NINFO"),
            &Kind::RKEY => write!(f, "RKEY"),
            &Kind::TALINK => write!(f, "TALINK"),
            &Kind::CDS => write!(f, "CDS"),
            &Kind::CDNSKEY => write!(f, "CDNSKEY"),
            &Kind::OPENPGPKEY => write!(f, "OPENPGPKEY"),
            &Kind::CSYNC => write!(f, "CSYNC"),
            &Kind::ZONEMD => write!(f, "ZONEMD"),
            &Kind::SPF => write!(f, "SPF"),
            &Kind::UINFO => write!(f, "UINFO"),
            &Kind::UID => write!(f, "UID"),
            &Kind::GID => write!(f, "GID"),
            &Kind::UNSPEC => write!(f, "UNSPEC"),
            &Kind::NID => write!(f, "NID"),
            &Kind::L32 => write!(f, "L32"),
            &Kind::L64 => write!(f, "L64"),
            &Kind::LP => write!(f, "LP"),
            &Kind::EUI48 => write!(f, "EUI48"),
            &Kind::EUI64 => write!(f, "EUI64"),
            &Kind::TKEY => write!(f, "TKEY"),
            &Kind::TSIG => write!(f, "TSIG"),
            &Kind::IXFR => write!(f, "IXFR"),
            &Kind::AXFR => write!(f, "AXFR"),
            &Kind::MAILB => write!(f, "MAILB"),
            &Kind::MAILA => write!(f, "MAILA"),
            &Kind::ALL => write!(f, "ALL"),
            &Kind::URI => write!(f, "URI"),
            &Kind::CAA => write!(f, "CAA"),
            &Kind::AVC => write!(f, "AVC"),
            &Kind::DOA => write!(f, "DOA"),
            &Kind::AMTRELAY => write!(f, "AMTRELAY"),
            &Kind::TA => write!(f, "TA"),
            &Kind::DLV => write!(f, "DLV"),

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

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::str::FromStr for Kind {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "A" => Ok(Kind::A),
            "NS" => Ok(Kind::NS),
            "MD" => Ok(Kind::MD),
            "MF" => Ok(Kind::MF),
            "CNAME" => Ok(Kind::CNAME),
            "SOA" => Ok(Kind::SOA),
            "MB" => Ok(Kind::MB),
            "MG" => Ok(Kind::MG),
            "MR" => Ok(Kind::MR),
            "NULL" => Ok(Kind::NULL),
            "WKS" => Ok(Kind::WKS),
            "PTR" => Ok(Kind::PTR),
            "HINFO" => Ok(Kind::HINFO),
            "MINFO" => Ok(Kind::MINFO),
            "MX" => Ok(Kind::MX),
            "TXT" => Ok(Kind::TXT),
            "RP" => Ok(Kind::RP),
            "AFSDB" => Ok(Kind::AFSDB),
            "X25" => Ok(Kind::X25),
            "ISDN" => Ok(Kind::ISDN),
            "RT" => Ok(Kind::RT),
            "NSAP" => Ok(Kind::NSAP),
            "NSAP-PTR" => Ok(Kind::NSAP_PTR),
            "SIG" => Ok(Kind::SIG),
            "KEY" => Ok(Kind::KEY),
            "PX" => Ok(Kind::PX),
            "GPOS" => Ok(Kind::GPOS),
            "AAAA" => Ok(Kind::AAAA),
            "LOC" => Ok(Kind::LOC),
            "NXT" => Ok(Kind::NXT),
            "EID" => Ok(Kind::EID),
            "NIMLOC" => Ok(Kind::NIMLOC),
            "SRV" => Ok(Kind::SRV),
            "ATMA" => Ok(Kind::ATMA),
            "NAPTR" => Ok(Kind::NAPTR),
            "KX" => Ok(Kind::KX),
            "DNAME" => Ok(Kind::DNAME),
            "SINK" => Ok(Kind::SINK),
            "OPT" => Ok(Kind::OPT),
            "APL" => Ok(Kind::APL),
            "DS" => Ok(Kind::DS),
            "SSHFP" => Ok(Kind::SSHFP),
            "IPSECKEY" => Ok(Kind::IPSECKEY),
            "RRSIG" => Ok(Kind::RRSIG),
            "NSEC" => Ok(Kind::NSEC),
            "DNSKEY" => Ok(Kind::DNSKEY),
            "DHCID" => Ok(Kind::DHCID),
            "NSEC3" => Ok(Kind::NSEC3),
            "NSEC3PARAM" => Ok(Kind::NSEC3PARAM),
            "TLSA" => Ok(Kind::TLSA),
            "SMIMEA" => Ok(Kind::SMIMEA),
            "HIP" => Ok(Kind::HIP),
            "NINFO" => Ok(Kind::NINFO),
            "RKEY" => Ok(Kind::RKEY),
            "TALINK" => Ok(Kind::TALINK),
            "CDS" => Ok(Kind::CDS),
            "CDNSKEY" => Ok(Kind::CDNSKEY),
            "OPENPGPKEY" => Ok(Kind::OPENPGPKEY),
            "CSYNC" => Ok(Kind::CSYNC),
            "ZONEMD" => Ok(Kind::ZONEMD),
            "SPF" => Ok(Kind::SPF),
            "UINFO" => Ok(Kind::UINFO),
            "UID" => Ok(Kind::UID),
            "GID" => Ok(Kind::GID),
            "UNSPEC" => Ok(Kind::UNSPEC),
            "NID" => Ok(Kind::NID),
            "L32" => Ok(Kind::L32),
            "L64" => Ok(Kind::L64),
            "LP" => Ok(Kind::LP),
            "EUI48" => Ok(Kind::EUI48),
            "EUI64" => Ok(Kind::EUI64),
            "TKEY" => Ok(Kind::TKEY),
            "TSIG" => Ok(Kind::TSIG),
            "IXFR" => Ok(Kind::IXFR),
            "AXFR" => Ok(Kind::AXFR),
            "MAILB" => Ok(Kind::MAILB),
            "MAILA" => Ok(Kind::MAILA),
            "ALL" => Ok(Kind::ALL),
            "URI" => Ok(Kind::URI),
            "CAA" => Ok(Kind::CAA),
            "AVC" => Ok(Kind::AVC),
            "DOA" => Ok(Kind::DOA),
            "AMTRELAY" => Ok(Kind::AMTRELAY),
            "TA" => Ok(Kind::TA),
            "DLV" => Ok(Kind::DLV),
            _ => Err(Error::from(ErrorKind::FormatError)),
        }
    }
}