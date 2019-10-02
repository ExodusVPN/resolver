#[macro_use]
extern crate bitflags;
extern crate punycode;

mod error;
pub mod packet;

pub use error::Error;


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
