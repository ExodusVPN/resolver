
// 5.  Transport Protocol Selection
// https://tools.ietf.org/html/rfc7766#section-5
// 
// Section 6.1.3.2 of [RFC1123] is updated: All general-purpose DNS
// implementations MUST support both UDP and TCP transport.
// 
// o  Authoritative server implementations MUST support TCP so that they
//   do not limit the size of responses to what fits in a single UDP
//   packet.
// 
// o  Recursive server (or forwarder) implementations MUST support TCP
//       so that they do not prevent large responses from a TCP-capable
//       server from reaching its TCP-capable clients.
// 
// o  Stub resolver implementations (e.g., an operating system's DNS
//   resolution library) MUST support TCP since to do otherwise would
//   limit the interoperability between their own clients and upstream
//   servers.
// 
// Regarding the choice of when to use UDP or TCP, Section 6.1.3.2 of
// RFC 1123 also says:
// 
//   ... a DNS resolver or server that is sending a non-zone-transfer
//   query MUST send a UDP query first.
// 
// This requirement is hereby relaxed.  Stub resolvers and recursive
// resolvers MAY elect to send either TCP or UDP queries depending on
// local operational reasons.  TCP MAY be used before sending any UDP
// queries.  If the resolver already has an open TCP connection to the
// server, it SHOULD reuse this connection.  In essence, TCP ought to be
// considered a valid alternative transport to UDP, not purely a retry
// option.
// 
// In addition, it is noted that all recursive and authoritative servers
// MUST send responses using the same transport as the query arrived on.
// In the case of TCP, this MUST also be the same connection.
// 

mod tcp;
mod udp;
mod tls;
mod dtls;

pub use self::tcp::*;
pub use self::udp::*;
pub use self::tls::*;
pub use self::dtls::*;


pub const DEFAULT_UDP_PORT: u16 = 53;
pub const DEFAULT_TCP_PORT: u16 = 53;
pub const DEFAULT_DOT_PORT: u16 = 853;
pub const DEFAULT_DOH_PORT: u16 = 443;
pub const DEFAULT_TCP_DNSCRYPT_PORT: u16 = 443;
pub const DEFAULT_UDP_DNSCRYPT_PORT: u16 = 443;

