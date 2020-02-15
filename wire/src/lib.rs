#![allow(dead_code, unused_variables, unused_assignments, unused_imports)]

#[macro_use]
extern crate log;
#[macro_use]
extern crate bitflags;
extern crate base64;
extern crate punycode;
extern crate chrono;


/// 255 octets or less
pub const MAXIMUM_NAMES_SIZE: usize = 255;
/// 63 octets or less
pub const MAXIMUM_LABEL_SIZE: usize = 63;


pub mod fmt;
pub mod error;

pub mod kind;
pub mod class;
pub mod opcode;
pub mod rcode;
pub mod header;

pub mod edns;
pub mod dnssec;
pub mod record;

pub mod ser;
pub mod de;