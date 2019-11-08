use crate::wire::Kind;
use crate::wire::Class;
use crate::wire::ExtensionFlags;

macro_rules! rr {
    ($name:ident, $($element: ident: $ty: ty),*) => {
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $name {
            pub name: String,
            pub kind: Kind,
            pub class: Class,
            pub ttl: u32,
            $(pub $element: $ty),*  // RDATA
        }
    };
}

// pseudo resource records
macro_rules! pseudo_rr {
    ($name:ident, $($element: ident: $ty: ty),*) => {
        #[derive(Debug, PartialEq, Eq, Clone)]
        pub struct $name {
            pub name: String,          // MUST be 0 (root domain)
            pub kind: Kind,
            // pub class: Class,
            pub udp_size: u16,         // requestor's UDP payload size
            // pub ttl: u32,
            pub rcode: u8,             // extended RCODE
            pub version: u8,           // version
            pub flags: ExtensionFlags, // flags
            $(pub $element: $ty),*     // RDATA
        }
    };
}
