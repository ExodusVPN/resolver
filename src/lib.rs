#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;
extern crate punycode;
extern crate base64;
extern crate hex;
extern crate openssl;
extern crate chrono;

mod error;
pub use error::Error;

pub mod wire;
pub mod net;
pub mod server;
pub mod db;

// 2.3.4. Size limits
// https://tools.ietf.org/html/rfc1035#section-2.3.4
// 
// Various objects and parameters in the DNS have size limits.  They are
// listed below.  Some could be easily changed, others are more
// fundamental.
// 
// labels          63 octets or less
// 
// names           255 octets or less
// 
// TTL             positive values of a signed 32 bit number.
// 
// UDP messages    512 octets or less
// 
// https://tools.ietf.org/html/rfc2671#section-4.5
// 

// Maximum
/// 63 octets or less
pub const MAXIMUM_LABEL_SIZE: usize        = 63;
/// 255 octets or less
pub const MAXIMUM_NAMES_SIZE: usize        = 255;
/// 512 octets or less
pub const MAXIMUM_UDP_MESSAGES_SIZE: usize = 512;
pub const MAXIMUM_TCP_MESSAGES_SIZE: usize = std::u16::MAX as usize;

// ethernet frame header: 14 bytes
// ipv4 header: 20 bytes
// ipv6 header: 40 bytes
// udp header: 8 bytes
// 
// Max Ipv4UDP size: MTU - 14 - 20 - 8
// Max Ipv6UDP size: MTU - 14 - 40 - 8
// M
pub fn init() {
    openssl::init();
}
