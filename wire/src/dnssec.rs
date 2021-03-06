// Resource Records for the DNS Security Extensions
// 
// defines the public key (DNSKEY), delegation signer (DS), resource record digital
// signature (RRSIG), and authenticated denial of existence (NSEC) resource records.
// 
// 2.1.  DNSKEY RDATA Wire Format
// https://tools.ietf.org/html/rfc4034#section-2.1
// 
//    The RDATA for a DNSKEY RR consists of a 2 octet Flags Field, a 1
//    octet Protocol Field, a 1 octet Algorithm Field, and the Public Key
//    Field.
// 
//                         1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
//     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    |              Flags            |    Protocol   |   Algorithm   |
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//    /                                                               /
//    /                            Public Key                         /
//    /                                                               /
//    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// 


// Domain Name System Security (DNSSEC) Algorithm Numbers
// https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml
// 
// Last Updated: 2017-03-10
// 

bitflags! {
    pub struct DNSKEYFlags: u16 {
        // 2.1.1.  The Flags Field
        // https://tools.ietf.org/html/rfc4034#section-2.1.1
        // 
        // if set, the DNSKEY record holds a DNS zone key, and the DNSKEY RR's
        // owner name MUST be the name of a zone.
        // if not set, the DNSKEY record holds some other type of DNS public key and MUST
        // NOT be used to verify RRSIGs that cover RRsets.
        /// Zone Key flag
        const ZONE_KEY = 0b_0000_0001_0000_0000;
        // 2.  The Secure Entry Point (SEP) Flag
        // https://tools.ietf.org/html/rfc3757#section-2
        // 
        // if set, the DNSKEY record holds a key intended for use as a secure entry point.
        // This flag is only intended to be a hint to zone signing or debugging software as to the
        // intended use of this DNSKEY record; validators MUST NOT alter their
        // behavior during the signature validation process in any way based on
        // the setting of this bit.  This also means that a DNSKEY RR with the
        // SEP bit set would also need the Zone Key flag set in order to be able
        // to generate signatures legally.  A DNSKEY RR with the SEP set and the
        // Zone Key flag not set MUST NOT be used to verify RRSIGs that cover
        // RRsets.
        /// The Secure Entry Point (SEP) Flag  RFC3757
        const SEP      = 0b_0000_0000_0000_0001;

        // Bits 0-6 and 8-14 are reserved:
        
        // Automated Updates of DNS Security (DNSSEC) Trust Anchors
        // 
        // 2.1.  Revocation
        // https://tools.ietf.org/html/rfc5011#section-2.1
        const REVOKE   = 0b_0000_0000_1000_0000;
    }
}

impl DNSKEYFlags {
    pub fn new_unchecked(bits: u16) -> Self {
        unsafe {
            Self::from_bits_unchecked(bits)
        }
    }
}

impl std::fmt::Display for DNSKEYFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// https://tools.ietf.org/html/rfc5155#section-3.2
// 
// Flags field is a single octet, the Opt-Out flag is the least
// significant bit, as shown below:
// 
// 0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |             |O|
// +-+-+-+-+-+-+-+-+
bitflags! {
    pub struct NSEC3Flags: u8 {
        const OPT_OUT = 0b_0000_0001;
    }
}

impl NSEC3Flags {
    pub fn new_unchecked(bits: u8) -> Self {
        unsafe {
            Self::from_bits_unchecked(bits)
        }
    }
}

impl std::fmt::Display for NSEC3Flags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}


/// The Protocol Field MUST have value 3, and the DNSKEY RR MUST be
/// treated as invalid during signature verification if it is found to be
/// some value other than 3.
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct DNSKEYProtocol(pub u8);

impl DNSKEYProtocol {
    pub const V3: Self = Self(3);
}

impl std::fmt::Debug for DNSKEYProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::V3 => write!(f, "V3"),
            _ => write!(f, "Unknow({})", self.0),
        }
    }
}

impl std::fmt::Display for DNSKEYProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC
// https://tools.ietf.org/html/rfc6605
// 
// The KEY, SIG, DNSKEY, RRSIG, DS, and CERT RRs use an 8-bit number used
// to identify the security algorithm being used.
// 
// All algorithm numbers in this registry may be used in CERT RRs. Zone
// signing (DNSSEC) and transaction security mechanisms (SIG(0) and TSIG)
// make use of particular subsets of these algorithms. Only algorithms
// usable for zone signing may appear in DNSKEY, RRSIG, and DS RRs.
// Only those usable for SIG(0) and TSIG may appear in SIG and KEY RRs.
// 
// * There has been no determination of standardization of the use of this
// algorithm with Transaction Security.
// 
// sha1            --> sha1::Sha1
// sha256          --> sha2::Sha256
// sha512          --> sha2::Sha512
// 
// https://csrc.nist.gov/csrc/media/publications/fips/186/3/archive/2009-06-25/documents/fips_186-3.pdf
// 
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct Algorithm(pub u8);

impl Algorithm {
    // DNS Security Algorithm Numbers
    // https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1
    // 
    // [RFC4034] [RFC3755] [RFC6014] [RFC6944]
    // Number   Description                     Mnemonic            ZoneSigning  Trans.Sec.    Reference 
    // 0        Delete DS                       DELETE              N               N          [RFC4034] [RFC4398] [RFC8078]
    // 1        RSA/MD5 (deprecated, see 5)     RSAMD5              N               Y          [RFC3110] [RFC4034]
    // 2        Diffie-Hellman                  DH                  N               Y          [RFC2539] [proposed standard]
    // 3        DSA/SHA1                        DSA                 Y               Y          [RFC3755] [proposed standard]
    //                                                                                         [RFC2536] [proposed standard]
    //                                                Federal Information Processing Standards Publication (FIPS PUB) 186, 
    //                                                Digital Signature Standard, 18 May 1994.
    //                                                Federal Information Processing Standards Publication (FIPS PUB) 180-1,
    //                                                Secure Hash Standard, 17 April 1995. 
    //                                                (Supersedes FIPS PUB 180 dated 11 May 1993.)
    // 4        Reserved                                                                       [RFC6725]
    // 5        RSA/SHA-1                       RSASHA1             Y               Y          [RFC3110] [RFC4034]
    // 6        DSA-NSEC3-SHA1                  DSA-NSEC3-SHA1      Y               Y          [RFC5155] [proposed standard]
    // 7        RSASHA1-NSEC3-SHA1              RSASHA1-NSEC3-SHA1  Y               Y          [RFC5155] [proposed standard]
    // 8        RSA/SHA-256                     RSASHA256           Y               *          [RFC5702] [proposed standard]
    // 9        Reserved                                                                       [RFC6725]
    // 10       RSA/SHA-512                     RSASHA512           Y               *          [RFC5702] [proposed standard]
    // 11       Reserved                                                                       [RFC6725]
    // 12       GOST R 34.10-2001               ECC-GOST            Y               *          [RFC5933] [standards track]
    // 13       ECDSA Curve P-256 with SHA-256  ECDSAP256SHA256     Y               *          [RFC6605] [standards track]
    // 14       ECDSA Curve P-384 with SHA-384  ECDSAP384SHA384     Y               *          [RFC6605] [standards track]
    // 15       Ed25519                         ED25519             Y               *          [RFC8080] [standards track]
    // 16       Ed448                           ED448               Y               *          [RFC8080] [standards track]
    // 17-122   Unassigned
    // 123-251  Reserved                                                                       [RFC4034] [RFC6014]
    // 252      Reserved for Indirect Keys      INDIRECT            N               N          [RFC4034] [proposed standard]
    // 253      private algorithm               PRIVATEDNS          Y               Y          [RFC4034]
    // 254      private algorithm OID           PRIVATEOID          Y               Y          [RFC4034]
    // 255      Reserved                                                                       [RFC4034] [proposed standard]
    // 
    // +--------+--------------------+-----------------+-------------------+
    // | Number | Mnemonics          | DNSSEC Signing  | DNSSEC Validation |
    // +--------+--------------------+-----------------+-------------------+
    // | 1      | RSAMD5             | MUST NOT        | MUST NOT          |
    // | 3      | DSA                | MUST NOT        | MUST NOT          |
    // | 5      | RSASHA1            | NOT RECOMMENDED | MUST              |
    // | 6      | DSA-NSEC3-SHA1     | MUST NOT        | MUST NOT          |
    // | 7      | RSASHA1-NSEC3-SHA1 | NOT RECOMMENDED | MUST              |
    // | 8      | RSASHA256          | MUST            | MUST              |
    // | 10     | RSASHA512          | NOT RECOMMENDED | MUST              |
    // | 12     | ECC-GOST           | MUST NOT        | MAY               |
    // | 13     | ECDSAP256SHA256    | MUST            | MUST              |
    // | 14     | ECDSAP384SHA384    | MAY             | RECOMMENDED       |
    // | 15     | ED25519            | RECOMMENDED     | RECOMMENDED       |
    // | 16     | ED448              | MAY             | RECOMMENDED       |
    // +--------+--------------------+-----------------+-------------------+
    // 
    pub const RSAMD5: Self             = Self(1);   // deprecated
    pub const DSA: Self                = Self(3);   // deprecated
    pub const RSASHA1: Self            = Self(5);   // MUST, 因为部署广泛, 需兼容
    // DSA-NSEC3-SHA1
    pub const DSA_NSEC3_SHA1: Self     = Self(6);   // deprecated
    // RSASHA1-NSEC3-SHA1
    pub const RSASHA1_NSEC3_SHA1: Self = Self(7);   // NOT RECOMMENDED, 因为部署广泛, 需兼容
    pub const RSASHA256: Self          = Self(8);   // MUST
    pub const RSASHA512: Self          = Self(10);  // NOT RECOMMENDED
    // ECC-GOST
    pub const ECC_GOST: Self           = Self(12);  // deprecated
    pub const ECDSAP256SHA256: Self    = Self(13);  // MUST
    pub const ECDSAP384SHA384: Self    = Self(14);  // MAY
    pub const ED25519: Self            = Self(15);  // RECOMMENDED
    pub const ED448: Self              = Self(16);  // MAY
}

impl Algorithm {
    #[inline]
    pub fn is_deprecated(&self) -> bool {
        // 0        Delete DS                       DELETE              N               N          [RFC4034] [RFC4398] [RFC8078]
        // 2        Diffie-Hellman                  DH                  N               Y          [RFC2539] [proposed standard]
        match self.0 {
            0 | 2 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_unassigned(&self) -> bool {
        // 17-122   Unassigned
        match self.0 {
            17 ..= 122 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_private_use(&self) -> bool {
        // 253      private algorithm               PRIVATEDNS          Y               Y          [RFC4034]
        // 254      private algorithm OID           PRIVATEOID          Y               Y          [RFC4034]
        match self.0 {
            253 | 254 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_reserved(&self) -> bool {
        // 4        Reserved                                                                       [RFC6725]
        // 9        Reserved                                                                       [RFC6725]
        // 11       Reserved                                                                       [RFC6725]
        // 123-251  Reserved                                                                       [RFC4034] [RFC6014]
        // 252      Reserved for Indirect Keys      INDIRECT            N               N          [RFC4034] [proposed standard]
        // 255      Reserved                                                                       [RFC4034] [proposed standard]
        match self.0 {
            4 | 9 | 11 | 123 ..= 251 | 252 | 255 => true,
            _ => false,
        }
    }
}

impl std::fmt::Debug for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::RSAMD5 => write!(f, "RSAMD5"),
            Self::DSA => write!(f, "DSA"),
            Self::RSASHA1 => write!(f, "RSASHA1"),
            Self::DSA_NSEC3_SHA1 => write!(f, "DSA_NSEC3_SHA1"),
            Self::RSASHA1_NSEC3_SHA1 => write!(f, "RSASHA1_NSEC3_SHA1"),
            Self::RSASHA256 => write!(f, "RSASHA256"),
            Self::RSASHA512 => write!(f, "RSASHA512"),
            Self::ECC_GOST => write!(f, "ECC_GOST"),
            Self::ECDSAP256SHA256 => write!(f, "ECDSAP256SHA256"),
            Self::ECDSAP384SHA384 => write!(f, "ECDSAP384SHA384"),
            Self::ED25519 => write!(f, "ED25519"),
            Self::ED448 => write!(f, "ED448"),
            _ => {
                if self.is_deprecated() {
                    write!(f, "Deprecated({})", self.0)
                } else if self.is_unassigned() {
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

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

// A.2.  DNSSEC Digest Types
// https://tools.ietf.org/html/rfc4034#appendix-A.2
// 2.  Implementing the SHA-256 Algorithm for DS Record Support
// https://tools.ietf.org/html/rfc4509#section-2
// 
// VALUE   Algorithm                 STATUS
//  0      Reserved                   -
//  1      SHA-1                   MANDATORY
// 2-255   Unassigned                 -
// 
//  2      SHA-256
// 
// A SHA-256 bit digest value calculated by using the following
// formula ("|" denotes concatenation).  The resulting value is not
// truncated, and the entire 32 byte result is to be used in the
// resulting DS record and related calculations.
// 
//      digest = SHA_256(DNSKEY owner name | DNSKEY RDATA)
// 
// where DNSKEY RDATA is defined by [RFC4034] as:
// 
//      DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key
// 
#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub struct DigestKind(pub u8);

impl DigestKind {
    // Delegation Signer (DS) Resource Record (RR) Type Digest Algorithms
    // https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml
    // 
    // Value    Description     Status      Reference
    // 0        Reserved        -           [RFC3658]
    // 1        SHA-1           MANDATORY   [RFC3658]
    // 2        SHA-256         MANDATORY   [RFC4509]
    // 3        GOST R 34.11-94 OPTIONAL    [RFC5933]
    // 4        SHA-384         OPTIONAL    [RFC6605]
    // 5-255    Unassigned      -
    pub const SHA1: Self            = Self(1); // 20 bytes
    pub const SHA256: Self          = Self(2); // 32 bytes
    pub const GOST_R_34_11_94: Self = Self(3);
    pub const SHA384: Self          = Self(4);
}

impl DigestKind {
    #[inline]
    pub fn is_unassigned(&self) -> bool {
        // 5-255    Unassigned      -
        match self.0 {
            5 ..= 255 => true,
            _ => false,
        }
    }

    #[inline]
    pub fn is_reserved(&self) -> bool {
        // 0        Reserved        -           [RFC3658]
        match self.0 {
            0 => true,
            _ => false,
        }
    }
}

impl std::fmt::Debug for DigestKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::SHA1 => write!(f, "SHA1"),
            Self::SHA256 => write!(f, "SHA256"),
            Self::GOST_R_34_11_94 => write!(f, "GOST-R-34_11-94"),
            Self::SHA384 => write!(f, "SHA384"),
            _ => {
                if self.is_unassigned() {
                    write!(f, "Unassigned({})", self.0)
                } else if self.is_reserved() {
                    write!(f, "Reserved({})", self.0)
                } else {
                    write!(f, "Unknow({})", self.0)
                }
            }
        }
    }
}

impl std::fmt::Display for DigestKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
