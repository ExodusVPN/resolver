

// 3.3. Standard RRs
// https://tools.ietf.org/html/rfc1035#section-3.3
// 
// 3.3.1. CNAME RDATA format

//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                     CNAME                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 
// where:
// 
// CNAME           A <domain-name> which specifies the canonical or primary
//                 name for the owner.  The owner name is an alias.
// 
// CNAME RRs cause no additional section processing, but name servers may
// choose to restart the query at the canonical name in certain cases.  See
// the description of name server logic in [RFC-1034] for details.


// 3.3.2. HINFO RDATA format
// 
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                      CPU                      /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                       OS                      /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 
// where:
// 
// CPU             A <character-string> which specifies the CPU type.
// 
// OS              A <character-string> which specifies the operating
//                 system type.
// 
// Standard values for CPU and OS can be found in [RFC-1010].
// 
// HINFO records are used to acquire general information about a host.  The
// main use is for protocols such as FTP that can use special procedures
// when talking between machines or operating systems of the same type.
// 


// 3.3.3. MB RDATA format (EXPERIMENTAL)
// 
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     /                   MADNAME                     /
//     /                                               /
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 
// where:
// 
// MADNAME         A <domain-name> which specifies a host which has the
//                 specified mailbox.
// MB records cause additional section processing which looks up an A type
// RRs corresponding to MADNAME.


// 3.4. Internet specific RRs
// https://tools.ietf.org/html/rfc1035#section-3.4
// 
// 3.4.1. A RDATA format
// 
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
//     |                    ADDRESS                    |
//     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// 
// where:
// 
// ADDRESS         A 32 bit Internet address.
// 
// Hosts that have multiple Internet addresses will have multiple A
// records.
// 
// A records cause no additional section processing.  The RDATA section of
// an A line in a master file is an Internet address expressed as four
// decimal numbers separated by dots without any imbedded spaces (e.g.,
// "10.2.0.52" or "192.0.5.6").

use std::net::{Ipv4Addr, Ipv6Addr};

pub enum Record {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
}

