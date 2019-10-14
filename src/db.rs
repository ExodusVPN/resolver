
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// https://www.iana.org/domains/root/db/com.html
// 
// ROOT
// a.root-servers.net. 3600000 IN  A   198.41.0.4
// b.root-servers.net. 3600000 IN  A   199.9.14.201
// c.root-servers.net. 3600000 IN  A   192.33.4.12
// d.root-servers.net. 3600000 IN  A   199.7.91.13
// e.root-servers.net. 3600000 IN  A   192.203.230.10
// f.root-servers.net. 3600000 IN  A   192.5.5.241
// g.root-servers.net. 3600000 IN  A   192.112.36.4
// h.root-servers.net. 3600000 IN  A   198.97.190.53
// i.root-servers.net. 3600000 IN  A   192.36.148.17
// j.root-servers.net. 3600000 IN  A   192.58.128.30
// k.root-servers.net. 3600000 IN  A   193.0.14.129
// l.root-servers.net. 3600000 IN  A   199.7.83.42
// m.root-servers.net. 3600000 IN  A   202.12.27.33
// a.root-servers.net. 3600000 IN  AAAA    2001:503:ba3e::2:30
// b.root-servers.net. 3600000 IN  AAAA    2001:500:200::b
// c.root-servers.net. 3600000 IN  AAAA    2001:500:2::c
// d.root-servers.net. 3600000 IN  AAAA    2001:500:2d::d
// e.root-servers.net. 3600000 IN  AAAA    2001:500:a8::e
// f.root-servers.net. 3600000 IN  AAAA    2001:500:2f::f
// g.root-servers.net. 3600000 IN  AAAA    2001:500:12::d0d
// h.root-servers.net. 3600000 IN  AAAA    2001:500:1::53
// i.root-servers.net. 3600000 IN  AAAA    2001:7fe::53
// j.root-servers.net. 3600000 IN  AAAA    2001:503:c27::2:30
// k.root-servers.net. 3600000 IN  AAAA    2001:7fd::1
// l.root-servers.net. 3600000 IN  AAAA    2001:500:9f::42
// m.root-servers.net. 3600000 IN  AAAA    2001:dc3::35

pub static ROOT_SERVERS: [(&'static str, IpAddr); 26] = [
    ("a.root-servers.net.", IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4))),     // 198.41.0.4
    ("b.root-servers.net.", IpAddr::V4(Ipv4Addr::new(199, 9, 14, 201))),   // 199.9.14.201
    ("c.root-servers.net.", IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12))),    // 192.33.4.12
    ("d.root-servers.net.", IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13))),    // 199.7.91.13
    ("e.root-servers.net.", IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10))), // 192.203.230.10
    ("f.root-servers.net.", IpAddr::V4(Ipv4Addr::new(192, 5, 5, 241))),    // 192.5.5.241
    ("g.root-servers.net.", IpAddr::V4(Ipv4Addr::new(192, 112, 36, 4))),   // 192.112.36.4
    ("h.root-servers.net.", IpAddr::V4(Ipv4Addr::new(198, 97, 190, 53))),  // 198.97.190.53
    ("i.root-servers.net.", IpAddr::V4(Ipv4Addr::new(192, 36, 148, 17))),  // 192.36.148.17
    ("j.root-servers.net.", IpAddr::V4(Ipv4Addr::new(192, 58, 128, 30))),  // 192.58.128.30
    ("k.root-servers.net.", IpAddr::V4(Ipv4Addr::new(193, 0, 14, 129))),   // 193.0.14.129
    ("l.root-servers.net.", IpAddr::V4(Ipv4Addr::new(199, 7, 83, 42))),    // 199.7.83.42
    ("m.root-servers.net.", IpAddr::V4(Ipv4Addr::new(202, 12, 27, 33))),   // 202.12.27.33
    ("a.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0503, 0xba3e, 0x0000, 0x0000, 0x0000, 0x0002, 0x0030))), // 2001:503:ba3e::2:30
    ("b.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x0200, 0x0000, 0x0000, 0x0000, 0x0000, 0x000b))), // 2001:500:200::b
    ("c.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x0002, 0x0000, 0x0000, 0x0000, 0x0000, 0x000c))), // 2001:500:2::c
    ("d.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x002d, 0x0000, 0x0000, 0x0000, 0x0000, 0x000d))), // 2001:500:2d::d
    ("e.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x00a8, 0x0000, 0x0000, 0x0000, 0x0000, 0x000e))), // 2001:500:a8::e
    ("f.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x002f, 0x0000, 0x0000, 0x0000, 0x0000, 0x000f))), // 2001:500:2f::f
    ("g.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x0012, 0x0000, 0x0000, 0x0000, 0x0000, 0x0d0d))), // 2001:500:12::d0d
    ("h.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x0001, 0x0000, 0x0000, 0x0000, 0x0000, 0x0053))), // 2001:500:1::53
    ("i.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x07fe, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0053))), // 2001:7fe::53
    ("j.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0503, 0x0c27, 0x0000, 0x0000, 0x0000, 0x0002, 0x0030))), // 2001:503:c27::2:30
    ("k.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x07fd, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0001))), // 2001:7fd::1
    ("l.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0500, 0x009f, 0x0000, 0x0000, 0x0000, 0x0000, 0x0042))), // 2001:500:9f::42
    ("m.root-servers.net.", IpAddr::V6(Ipv6Addr::new(0x2001, 0x0dc3, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0035))), // 2001:dc3::35
];

// IANA L
// 199.7.83.42
pub const BEST_ROOT_IPV4_NAME_SERVER: Ipv4Addr = Ipv4Addr::new(199, 7, 83, 42);
// 2001:500:9f::42
pub const BEST_ROOT_IPV6_NAME_SERVER: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0500, 0x009f, 0x0000, 0x0000, 0x0000, 0x0000, 0x0042);

// https://root-servers.org/
// 
// L: Asia/Shanghai
// IPv4: 199.7.83.42
// IPv6: 2001:500:9f::42
// 
// L: Asia/Beijing
// IPv4    199.7.83.42
// IPv6    2001:500:9f::42
// 
// I: Asia/Hongkong
// IPv4    192.36.148.17
// IPv6    2001:7fe::53
// 
// L: Asia/Mandalay
// IPv4 199.7.83.42
// IPv6    2001:500:9f::42
// L: Asia/Yangon
// IPv4    199.7.83.42
// IPv6    2001:500:9f::42