use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;


/// A specification of an IPv4 CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Ipv4Cidr {
    address:    Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Cidr {
    /// Create an IPv4 CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the prefix length is larger than 32.
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Self {
        assert!(prefix_len <= 32);
        Self { address, prefix_len }
    }

    /// Create an IPv4 CIDR block from the given address and network mask.
    pub fn from_netmask(addr: Ipv4Addr, netmask: Ipv4Addr) -> Result<Self, ()> {
        let netmask = u32::from(netmask);
        if netmask.leading_zeros() == 0 && netmask.trailing_zeros() == netmask.count_zeros() {
            Ok(Self { address: addr, prefix_len: netmask.count_ones() as u8 })
        } else {
            Err(())
        }
    }

    /// Return the address of this IPv4 CIDR block.
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// Return the prefix length of this IPv4 CIDR block.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Return the network mask of this IPv4 CIDR.
    pub fn netmask(&self) -> Ipv4Addr {
        if self.prefix_len == 0 {
            return Ipv4Addr::UNSPECIFIED;
        }

        let number = 0xffffffffu32 << (32 - self.prefix_len);

        Ipv4Addr::new(
            ((number >> 24) & 0xff) as u8,
            ((number >> 16) & 0xff) as u8,
            ((number >>  8) & 0xff) as u8,
            ((number >>  0) & 0xff) as u8,
        )
    }

    /// Return the broadcast address of this IPv4 CIDR.
    pub fn broadcast(&self) -> Option<Ipv4Addr> {
        let network = self.network();

        if network.prefix_len == 31 || network.prefix_len == 32 {
            return None;
        }

        let network_number = u32::from(network.address);
        let number = network_number | 0xffffffffu32 >> network.prefix_len;

        Some(Ipv4Addr::new(
            ((number >> 24) & 0xff) as u8,
            ((number >> 16) & 0xff) as u8,
            ((number >>  8) & 0xff) as u8,
            ((number >>  0) & 0xff) as u8,
        ))
    }

    /// Return the network block of this IPv4 CIDR.
    pub fn network(&self) -> Self {
        let mask = self.netmask().octets();
        let octets = self.address.octets();
        let network = Ipv4Addr::new(
            octets[0] & mask[0],
            octets[1] & mask[1],
            octets[2] & mask[2],
            octets[3] & mask[3],
        );
        Self { address: network, prefix_len: self.prefix_len }
    }

    /// Query whether the subnetwork described by this IPv4 CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Ipv4Addr) -> bool {
        // right shift by 32 is not legal
        if self.prefix_len == 0 { return true }

        let shift = 32 - self.prefix_len;
        let self_prefix = u32::from(self.address) >> shift;
        let addr_prefix = u32::from(*addr) >> shift;
        self_prefix == addr_prefix
    }

    /// Query whether the subnetwork described by this IPv4 CIDR block contains
    /// the subnetwork described by the given IPv4 CIDR block.
    pub fn contains_subnet(&self, subnet: &Self) -> bool {
        self.prefix_len <= subnet.prefix_len && self.contains_addr(&subnet.address)
    }
}

impl Default for Ipv4Cidr {
    fn default() -> Self {
        let address = Ipv4Addr::UNSPECIFIED;
        let prefix_len = 0;

        Self { address, prefix_len }
    }
}

impl std::fmt::Display for Ipv4Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}




/// A specification of an IPv6 CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct Ipv6Cidr {
    address:    Ipv6Addr,
    prefix_len: u8,
}

impl Ipv6Cidr {
    /// The [solicited node prefix].
    ///
    /// [solicited node prefix]: https://tools.ietf.org/html/rfc4291#section-2.7.1
    pub const SOLICITED_NODE_PREFIX: Self =
        // Solicited-Node Address:  FF02:0:0:0:0:1:FFXX:XXXX
        Self {
            address: Ipv6Addr::new(0xff02, 0x0, 0x0, 0x0, 0x0, 0x01, 0xff00, 0x0),
            prefix_len: 104
        };

    /// Create an IPv6 CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the prefix length is larger than 128.
    pub fn new(address: Ipv6Addr, prefix_len: u8) -> Self {
        assert!(prefix_len <= 128);
        Self { address, prefix_len }
    }

    /// Return the address of this IPv6 CIDR block.
    pub fn address(&self) -> Ipv6Addr {
        self.address
    }

    /// Return the prefix length of this IPv6 CIDR block.
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Query whether the subnetwork described by this IPv6 CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &Ipv6Addr) -> bool {
        // right shift by 128 is not legal
        if self.prefix_len == 0 { return true }

        let shift = 128 - self.prefix_len;

        // Helper function used to mask an addres given a prefix.
        //
        // # Panics
        // This function panics if `mask` is greater than 128.
        fn mask(addr: &Ipv6Addr, mask: u8) -> [u8; 16] {
            assert!(mask <= 128);
            let mut bytes = [0u8; 16];
            let idx = (mask as usize) / 8;
            let modulus = (mask as usize) % 8;
            let octets = addr.octets();
            let (first, second) = octets.split_at(idx);
            bytes[0..idx].copy_from_slice(&first);
            if idx < 16 {
                let part = second[0];
                bytes[idx] = part & (!(0xff >> modulus) as u8);
            }
            bytes
        }
        
        mask(&self.address, shift) == mask(addr, shift)
    }

    /// Query whether the subnetwork described by this IPV6 CIDR block contains
    /// the subnetwork described by the given IPv6 CIDR block.
    pub fn contains_subnet(&self, subnet: &Self) -> bool {
        self.prefix_len <= subnet.prefix_len && self.contains_addr(&subnet.address)
    }
}

impl Default for Ipv6Cidr {
    fn default() -> Self {
        let address = Ipv6Addr::UNSPECIFIED;
        let prefix_len = 0;

        Self { address, prefix_len }
    }
}

impl std::fmt::Display for Ipv6Cidr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        // https://tools.ietf.org/html/rfc4291#section-2.3
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}



/// A specification of a CIDR block, containing an address and a variable-length
/// subnet masking prefix length.
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub enum IpCidr {
    V4(Ipv4Cidr),
    V6(Ipv6Cidr),
}

impl IpCidr {
    /// Create a CIDR block from the given address and prefix length.
    ///
    /// # Panics
    /// This function panics if the given address is unspecified, or
    /// the given prefix length is invalid for the given address.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Self {
        if addr.is_unspecified() {
            // NOTE: 当 addr 是 UNSPECIFIED 时，需要 panic 吗？
            panic!("a CIDR block cannot be based on an unspecified address");
        }

        match addr {
            IpAddr::V4(addr) => IpCidr::V4(Ipv4Cidr::new(addr, prefix_len)),
            IpAddr::V6(addr) => IpCidr::V6(Ipv6Cidr::new(addr, prefix_len)),
        }
    }

    /// Return the IP address of this CIDR block.
    pub fn address(&self) -> IpAddr {
        match self {
            &Self::V4(cidr)      => IpAddr::V4(cidr.address()),
            &Self::V6(cidr)      => IpAddr::V6(cidr.address()),
        }
    }

    /// Return the prefix length of this CIDR block.
    pub fn prefix_len(&self) -> u8 {
        match self {
            &Self::V4(cidr)      => cidr.prefix_len(),
            &Self::V6(cidr)      => cidr.prefix_len(),
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the given address.
    pub fn contains_addr(&self, addr: &IpAddr) -> bool {
        if addr.is_unspecified() {
            // a fully unspecified address covers both IPv4 and IPv6,
            // and no CIDR block can do that.
            return false;
        }

        match (self, addr) {
            (&Self::V4(ref cidr), &IpAddr::V4(ref addr)) => cidr.contains_addr(addr),
            (&Self::V6(ref cidr), &IpAddr::V6(ref addr)) => cidr.contains_addr(addr),
            (&Self::V4(_), &IpAddr::V6(_)) => false,
            (&Self::V6(_), &IpAddr::V4(_)) => false,
        }
    }

    /// Query whether the subnetwork described by this CIDR block contains
    /// the subnetwork described by the given CIDR block.
    pub fn contains_subnet(&self, subnet: &Self) -> bool {
        match (self, subnet) {
            (&Self::V4(ref cidr), &Self::V4(ref other)) => cidr.contains_subnet(other),
            (&Self::V6(ref cidr), &Self::V6(ref other)) => cidr.contains_subnet(other),
            (&Self::V4(_), &Self::V6(_)) => false,
            (&Self::V6(_), &Self::V4(_)) => false,
        }
    }
}

impl From<Ipv4Cidr> for IpCidr {
    fn from(addr: Ipv4Cidr) -> Self {
        IpCidr::V4(addr)
    }
}

impl From<Ipv6Cidr> for IpCidr {
    fn from(addr: Ipv6Cidr) -> Self {
        IpCidr::V6(addr)
    }
}

impl std::fmt::Display for IpCidr {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &Self::V4(cidr) => write!(f, "{}", cidr),
            &Self::V6(cidr) => write!(f, "{}", cidr),
        }
    }
}