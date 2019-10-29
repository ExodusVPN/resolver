#[macro_use]
extern crate log;

#[cfg(feature = "wire")]
#[macro_use]
extern crate bitflags;
#[cfg(feature = "wire")]
extern crate punycode;
#[cfg(feature = "wire")]
extern crate base64;
#[cfg(feature = "wire")]
extern crate hex;
#[cfg(feature = "wire")]
extern crate chrono;

#[cfg(feature = "resolver")]
extern crate mio;
#[cfg(feature = "dnssec-validator")]
extern crate openssl;
#[cfg(feature = "proto-tls")]
extern crate native_tls;


mod error;
pub use error::Error;
pub mod db;

#[cfg(feature = "wire")]
pub mod wire;
#[cfg(feature = "wire")]
pub mod storage;

pub mod net;
pub mod server;



/// OpenSSL init.
#[cfg(feature = "dnssec-validator")]
pub fn init() {
    openssl::init();
}
