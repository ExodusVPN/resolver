#![allow(unused_imports, unused_labels, unused_variables, dead_code)]

#[macro_use]
extern crate log;
extern crate rand;
pub extern crate wire;

pub mod boot;

pub mod net;
pub mod cache;
pub mod config;
pub mod protocol;
pub mod name_server;

pub mod gather;
// pub mod query;
pub mod stub;


use tokio::net::UdpSocket;
use tokio::net::TcpListener;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::ToSocketAddrs;


use wire::Kind;
use wire::Class;
use wire::Request;
use wire::Response;
use wire::ResponseCode;
use wire::Protocols;
use wire::record::Record;
use wire::serialize_req;
use wire::serialize_res;
use wire::deserialize_req;
use wire::deserialize_res;

use self::cache::Cache;


use std::io;
use std::env;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::time::Instant;
use std::time::Duration;
use std::pin::Pin;
use std::future::Future;


const MAX_BUFF_SIZE: usize = 1 << 16 + 2; // 64 Kb
const MAX_NS_HOP: usize    = 16;
const MAX_CNAME_HOP: usize = 16;



use self::config::ResolvOptions;


pub trait Resolver {
    fn cache(&self) -> Option<Cache>;
    fn option(&self) -> ResolvOptions;
    // fn name_servers(&self);
    fn query(&self, req: wire::Request) -> Pin<Box<dyn Future<Output = Result<wire::Response, wire::Error> > + Send >>;
    fn resolve<B: AsRef<[u8]>>(&self, pkt: B) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, wire::Error> > + Send >>;
    // fn lookup_host(&self);
}

