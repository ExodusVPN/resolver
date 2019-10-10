use crate::error::Error;

mod name;
mod header;
mod question;
mod answer;
mod record;
mod extension;
mod dnssec;
mod pretty_print;

pub use self::name::*;
pub use self::header::*;
pub use self::question::*;
pub use self::answer::*;
pub use self::record::*;
pub use self::extension::*;
pub use self::dnssec::*;
pub use self::pretty_print::*;

use std::net::IpAddr;
use std::collections::HashMap;


pub const BUFFER_SIZE: usize = 1024 * 64 - 1; // 64K


#[inline]
pub fn alloc() -> [u8; BUFFER_SIZE] {
    [0u8; BUFFER_SIZE]
}

pub fn write_dnssec_and_ecs(offset: usize, buffer: &mut [u8], addr: IpAddr, prefix_len: u8) -> Result<usize, Error> {
    let (rdlen, opt_len) = match addr {
        IpAddr::V4(v4_addr) => {
            assert!(prefix_len <= 32);
            (2 + 2 + 2 + 1 + 1 + 4, 2 + 1 + 1 + 4)
        },
        IpAddr::V6(_) => {
            assert!(prefix_len <= 128);
            (2 + 2 + 2 + 1 + 1 + 16, 2 + 1 + 1 + 16)
        },
    };

    // DNSSEC
    buffer[offset] = 0; // Name: . (ROOT)
    let mut pkt = ExtensionPacket::new_unchecked(&mut buffer[offset + 1..]);
    pkt.set_kind(Kind::OPT);
    pkt.set_udp_size(BUFFER_SIZE as u16);
    pkt.set_rcode(0);
    pkt.set_version(EXT_HEADER_V0);
    pkt.set_flags(ExtensionFlags::DO);
    pkt.set_rdlen(rdlen);

    let mut opt = ExtensionDataPacket::new_unchecked(pkt.rdata_mut());
    opt.set_option_code(OptionCode::EDNS_CLIENT_SUBNET);
    opt.set_option_length(opt_len);

    // ECS
    let mut ecs = ClientSubnetPacket::new_unchecked(opt.option_data_mut());
    ecs.set_family(AddressFamily::IPV4);
    ecs.set_src_prefixlen(prefix_len);
    ecs.set_scope_prefixlen(0);
    ecs.set_address(addr);

    let amt = pkt.header_len() + rdlen as usize + 1;

    Ok(amt)
}

pub fn write_dnssec(offset: usize, buffer: &mut [u8]) -> Result<usize, Error> {
    let rdlen = 4usize;

    // DNSSEC
    buffer[offset] = 0; // Name: . (ROOT)
    let mut pkt = ExtensionPacket::new_unchecked(&mut buffer[offset + 1..]);
    pkt.set_kind(Kind::OPT);
    pkt.set_udp_size(BUFFER_SIZE as u16);
    pkt.set_rcode(0);
    pkt.set_version(EXT_HEADER_V0);
    pkt.set_flags(ExtensionFlags::DO);
    pkt.set_rdlen(rdlen as u16);

    let mut opt = ExtensionDataPacket::new_unchecked(pkt.rdata_mut());
    opt.set_option_code(OptionCode::new(0));
    opt.set_option_length(0);

    let amt = pkt.header_len() + rdlen as usize + 1;

    Ok(amt)
}


pub struct QueryBuilder<T: AsRef<[u8]> + AsMut<[u8]>> {
    buffer: T,
    qdcount: u16,
    name_dict: HashMap<u64, u16>,
    len: usize,
    opt_rr_exists: bool,
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> QueryBuilder<T> {
    pub fn new(buffer: T) -> Self {
        let mut builder = Self {
            buffer,
            qdcount: 0,
            name_dict: HashMap::new(),
            len: HEADER_SIZE,
            opt_rr_exists: false,
        };

        let mut hdr_pkt = builder
            .set_id(0)
            .set_flags(Flags::RECURSION_REQUEST)
            .header_pkt();
        hdr_pkt.set_qdcount(0);
        hdr_pkt.set_ancount(0);
        hdr_pkt.set_nscount(0);
        hdr_pkt.set_arcount(0);

        builder
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn set_id(&mut self, id: u16) -> &mut Self {
        let mut pkt = self.header_pkt();
        pkt.set_id(id);
        
        self
    }

    pub fn set_flags(&mut self, flags: Flags) -> &mut Self {
        let mut pkt = self.header_pkt();
        pkt.set_flags(flags);
        
        self
    }
    
    fn header_pkt(&mut self) -> HeaderPacket<&mut [u8]> {
        let data = self.buffer.as_mut();
        HeaderPacket::new_unchecked(data)
    }

    pub fn add_question<N: AsRef<str>>(&mut self, qname: N, qkind: Kind, qclass: Class) -> Result<&mut Self, Error> {
        assert_eq!(self.opt_rr_exists, false);

        let mut data = self.buffer.as_mut();

        let amt = write_name(qname.as_ref(), self.len, &mut data, &mut self.name_dict)?;

        let mut pkt = QuestionPacket::new_unchecked(&mut data[self.len + amt..]);
        pkt.set_kind(qkind);
        pkt.set_class(qclass);

        self.len += amt + pkt.len();
        self.qdcount += 1;

        Ok(self)
    }

    pub fn add_opt_record(&mut self, client_cidr: Option<(IpAddr, u8)>) -> Result<&mut Self, Error> {
        assert_eq!(self.opt_rr_exists, false);
        let data = self.buffer.as_mut();

        match client_cidr {
            Some((client_ip, prefix_len)) => {
                let amt = write_dnssec_and_ecs(self.len, data, client_ip, prefix_len)?;
                self.len += amt;
            },
            None => {
                let amt = write_dnssec(self.len, data)?;
                self.len += amt;
            },
        }
        
        self.opt_rr_exists = true;

        Ok(self)
    }

    pub fn build(&mut self) -> &[u8] {
        let qdcount = self.qdcount;
        let opt_rr_exists = self.opt_rr_exists;

        let mut hdr_pkt = self.header_pkt();
        hdr_pkt.set_qdcount(qdcount);
        hdr_pkt.set_ancount(0);
        hdr_pkt.set_nscount(0);
        if opt_rr_exists {
            hdr_pkt.set_arcount(1);
        }
        
        let data = self.buffer.as_ref();

        &data[..self.len]
    }
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

// 16 Bits
/// two octets containing one of the RR TYPE codes. 
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
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

impl std::fmt::Display for Kind {
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
pub struct Class(pub u16);

impl Class {
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

    /// 5.4.  Questions Requesting Unicast Responses
    /// https://tools.ietf.org/html/rfc6762#section-5.4
    /// 
    /// To avoid large floods of potentially unnecessary responses in these
    /// cases, Multicast DNS defines the top bit in the class field of a DNS
    /// question as the unicast-response bit.  When this bit is set in a
    /// question, it indicates that the querier is willing to accept unicast
    /// replies in response to this specific query, as well as the usual
    /// multicast responses.  These questions requesting unicast responses
    /// are referred to as "QU" questions, to distinguish them from the more
    /// usual questions requesting multicast responses ("QM" questions).  A
    /// Multicast DNS querier sending its initial batch of questions
    /// immediately on wake from sleep or interface activation SHOULD set the
    /// unicast-response bit in those questions.
    #[inline]
    pub fn is_unicast(&self) -> bool {
        self.0 >> 15 == 1
    }

    #[inline]
    pub fn set_unicast(&self) -> bool {
        self.0 >> 15 == 1
    }

    #[inline]
    pub fn class(&self) -> Self {
        if self.is_unicast() {
            Self(self.0 << 1 >> 1)
        } else {
            *self
        }
    }
}

impl std::fmt::Display for Class {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let class = if self.is_unicast() { self.class() } else { *self };

        match &class {
            &Self::IN => write!(f, "IN"),
            &Self::CS => write!(f, "CS"),
            &Self::CH => write!(f, "CH"),
            &Self::HS => write!(f, "HS"),
            &Self::NONE => write!(f, "NONE"),
            &Self::ANY => write!(f, "ANY"),
            _ => {
                if class.is_unassigned() {
                    write!(f, "Unassigned({})", class.0)
                } else if class.is_private_use() {
                    write!(f, "PrivateUse({})", class.0)
                } else if class.is_reserved() {
                    write!(f, "Reserved({})", class.0)
                } else {
                    write!(f, "Unknow({})", class.0)
                }
            },
        }
    }
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

// 8 Bits + 4 Bits
/// Response code - this 4 bit field is set as part of responses.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct ResponseCode(u16);

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

    // ExtResponseCode
    // https://tools.ietf.org/html/rfc6891#section-6.1.3
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
    pub fn new(code: u16) -> Self {
        assert!(code < 4095); // 2**12 - 1
        Self(code)
    }

    #[inline]
    pub fn code(&self) -> u16 {
        self.0
    }

    #[inline]
    pub fn is_ok(&self) -> bool {
        *self == Self::OK
    }

    #[inline]
    pub fn is_err(&self) -> bool {
        !self.is_ok()
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

    pub fn description(&self) -> &'static str {
        match self {
            &Self::OK => "No Error [RFC1035]",
            &Self::FORMAT_ERROR => "Format Error [RFC1035]",
            &Self::SERVER_FAILURE => "Server Failure [RFC1035]",
            &Self::NON_EXISTENT_DOMAIN => "Non-Existent Domain [RFC1035]",
            &Self::NOT_IMPLEMENTED => "Not Implemented [RFC1035]",
            &Self::QUERY_REFUSED  => "Query Refused [RFC1035]",
            &Self::YXDOMAIN  => "Name Exists when it should not [RFC2136] [RFC6672]",
            &Self::YXRRSET  => "RR Set Exists when it should not [RFC2136]",
            &Self::NXRRSET  => "RR Set that should exist does not [RFC2136]",
            &Self::NOT_AUTH  => "Server Not Authoritative for zone [RFC2136]",
            &Self::NOT_ZONE  => "Name not contained in zone [RFC2136]",
            &Self::DSOTYPENI  => "DSO-TYPE Not Implemented RFC8490",
            &Self::BADVERS  => "Bad OPT Version RFC6891",
            &Self::BADKEY  => "Key not recognized  RFC2845",
            &Self::BADTIME  => "Signature out of time window RFC2845",
            &Self::BADMODE  => "Bad TKEY Mode RFC2930",
            &Self::BADNAME  => "Duplicate key name RFC2930",
            &Self::BADALG  => "Algorithm not supported RFC2930",
            &Self::BADTRUNC  => "Bad Truncation RFC4635",
            &Self::BADCOOKIE  => "Bad/missing Server Cookie RFC7873",
            _ => {
                if self.is_unassigned() {
                    "Unassigned"
                } else {
                    "Unknow"
                }
            },
        }
    }
}

impl std::fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            &Self::OK => write!(f, "OK"),
            &Self::FORMAT_ERROR => write!(f, "FORMAT_ERROR"),
            &Self::SERVER_FAILURE => write!(f, "SERVER_FAILURE"),
            &Self::NON_EXISTENT_DOMAIN => write!(f, "NON_EXISTENT_DOMAIN"),
            &Self::NOT_IMPLEMENTED => write!(f, "NOT_IMPLEMENTED"),
            &Self::QUERY_REFUSED  => write!(f, "QUERY_REFUSED"),
            &Self::YXDOMAIN  => write!(f, "YXDOMAIN"),
            &Self::YXRRSET  => write!(f, "YXRRSET"),
            &Self::NXRRSET  => write!(f, "NXRRSET"),
            &Self::NOT_AUTH  => write!(f, "NOT_AUTH"),
            &Self::NOT_ZONE  => write!(f, "NOT_ZONE"),
            &Self::DSOTYPENI  => write!(f, "DSOTYPENI"),
            &Self::BADVERS  => write!(f, "BADVERS"),
            &Self::BADKEY  => write!(f, "BADKEY"),
            &Self::BADTIME  => write!(f, "BADTIME"),
            &Self::BADMODE  => write!(f, "BADMODE"),
            &Self::BADNAME  => write!(f, "BADNAME"),
            &Self::BADALG  => write!(f, "BADALG"),
            &Self::BADTRUNC  => write!(f, "BADTRUNC"),
            &Self::BADCOOKIE  => write!(f, "BADCOOKIE"),
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
