extern crate resolver;

use resolver::packet;


use std::env;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::collections::HashMap;

// Root Servers
// a.root-servers.net. 3600000 IN  A   198.41.0.4
// 
// Top-level dns servers
// 
// .com
// a.gtld-servers.net. 172800  IN  A   192.5.6.30
// 
// .cn
// a.dns.cn
// 

fn usage() -> ! {
    println!("
用例:

    $ cargo run --example dig 8.8.8.8:53 www.gov.cn
");
    std::process::exit(0);
}

fn main() -> Result<(), io::Error> {
    let mut args = env::args().skip(1);

    let name_server = match args.next() {
        Some(ns) => ns,
        None => usage(),
    };
    let domain_name = match args.next() {
        Some(name) => name,
        None => usage(),
    };

    println!("Domain Name Server: {}", name_server);
    println!("Domain Name       : {}", domain_name);
    println!("Protocol          : DNS Transport over TCP\n");

    let mut conn = TcpStream::connect(name_server)?;

    resolve(&mut conn, &domain_name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Resolve Error: {:?}", e) ) )?;


    Ok(())
}

fn resolve(conn: &mut TcpStream, name: &str) -> Result<(), resolver::Error> {
    let mut buffer = [0u8; 64*1024];
    let mut qname = String::new();
    let mut cache: HashMap<u64, u16> = HashMap::new();

    let mut pkt = packet::HeaderPacket::new_unchecked(&mut buffer[..]);
    pkt.set_id(1);

    // let mut flags = packet::Flags::REQUEST;
    let flags = packet::Flags::RECURSION_REQUEST;
    // flags.set_do(true);
    // flags.set_ad(true);
    // flags.set_cd(true);

    println!("flags: {:?}", flags);

    pkt.set_flags(flags);
    pkt.set_qdcount(1);
    pkt.set_ancount(0);
    pkt.set_nscount(0);
    pkt.set_arcount(1);
    
    let header_size = packet::HeaderPacket::<&[u8]>::HEADER_SIZE;

    let mut offset = pkt.len();
    
    let amt = packet::write_name(name, offset, &mut buffer, &mut cache)?;
    offset += amt;

    let mut pkt = packet::QuestionPacket::new_unchecked(&mut buffer[offset..]);
    pkt.set_kind(packet::Kind::A);
    pkt.set_class(packet::Class::IN);

    offset += pkt.len();

    // DNSSEC
    // let amt = packet::write_name(name, offset, &mut buffer, &mut cache)?;
    buffer[offset] = 0;

    offset += 1;
    let mut pkt = packet::AnswerPacket::new_unchecked(&mut buffer[offset..]);
    //           ext_rcode    version  do  z
    let ttl = 0b_0000_0000___0000_0000_1___000_0000_0000_0000u32;
    pkt.set_kind(packet::Kind::OPT);
    pkt.set_class(packet::Class(std::u16::MAX)); // requestor's UDP payload size
    pkt.set_ttl(ttl);  // extended RCODE and flags
    pkt.set_rdlen(4);
    let rdata = pkt.rdata_mut();
    rdata[0] = 0;
    rdata[1] = 0;
    rdata[2] = 0;
    rdata[3] = 0;

    offset += pkt.header_len() + 4;
    // Option record
    // DNS EDNS0 Option Codes (OPT)
    // https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
    // 
    // 8  edns-client-subnet
    // 9  EDNS EXPIRE
    // 11 edns-tcp-keepalive
    // 14 edns-key-tag
    // 16 EDNS-Client-Tag
    // 17 EDNS-Server-Tag
    // 
    // Client Subnet in DNS Queries
    // https://tools.ietf.org/html/rfc7871#page-8
    // 

    println!("Send Packet:");
    println!("Header Packet: {}", packet::HeaderPacket::new_checked(&buffer[..header_size])?);

    let pkt = packet::QuestionPacket::new_checked(&buffer[header_size + amt..offset])?;
    let _amt = packet::read_name(header_size, &buffer, &mut qname, 0)?;
    println!("Question Packet: QNAME={:?} QTYPE={} QCLASS={}", qname.to_string(), pkt.kind(), pkt.class());

    assert!(offset <= std::u16::MAX as usize);
    conn.write_all(&(offset as u16).to_be_bytes()).unwrap();

    println!("send message: {:?}", &buffer[..offset]);
    conn.write_all(&buffer[..offset]).unwrap();

    println!();

    // Read
    conn.read(&mut buffer[..2]).unwrap();

    let amt = conn.read(&mut buffer).unwrap();
    println!("recv {:?} bytes from name server.", amt);
    

    let buffer = &buffer[..amt];
    // println!("message: {:?}", &buffer);

    let hdr = packet::HeaderPacket::new_checked(&buffer[..])?;
    // println!("message body: {:?}", &buffer[header_size..amt]);
    let qdcount = hdr.qdcount() as usize;
    let ancount = hdr.ancount() as usize;
    let nscount = hdr.nscount() as usize;
    let arcount = hdr.arcount() as usize;
    
    println!("{}", hdr);

    let mut offset = header_size;

    for _ in 0..qdcount {
        qname.clear();
        let amt = packet::read_name(offset, &buffer, &mut qname, 0)?;
        offset += amt;

        let pkt = packet::QuestionPacket::new_checked(&buffer[offset..])?;
        offset += pkt.len();

        println!("Question Section: QNAME={:?} QTYPE={} QCLASS={}", qname.to_string(), pkt.kind(), pkt.class());
    }
    
    for _ in 0..ancount {
        qname.clear();
        let amt = packet::read_name(offset, &buffer, &mut qname, 0)?;
        offset += amt;

        let pkt = packet::AnswerPacket::new_checked(&buffer[offset..])?;
        offset += pkt.header_len();

        let kind  = pkt.kind();
        let class = pkt.class();
        let ttl   = pkt.ttl();
        let rdlen = pkt.rdlen();
        let rdata = pkt.rdata();
        let record = packet::Record::parse(offset, &buffer, kind, class, rdata)?;
        println!("  Answer Section: QNAME={:?} ATYPE={} ACLASS={} TTL={} RDATA={:?}",
                qname,
                kind,
                class,
                ttl,
                record,
                );
        offset += rdlen as usize;
    }

    for _ in 0..nscount {
        qname.clear();
        let amt = packet::read_name(offset, &buffer, &mut qname, 0)?;
        offset += amt;

        let pkt = packet::AnswerPacket::new_checked(&buffer[offset..])?;
        offset += pkt.header_len();
        
        let kind  = pkt.kind();
        let class = pkt.class();
        let ttl   = pkt.ttl();
        let rdlen = pkt.rdlen();
        let rdata = pkt.rdata();

        let record = packet::Record::parse(offset, &buffer, kind, class, rdata)?;
        println!("Authority Records Section: QNAME={:?} ATYPE={} ACLASS={} TTL={} RDATA={:?}",
                qname,
                kind,
                class,
                ttl,
                record,
                );
        println!("rdlenL: {:?}", rdlen);
        offset += rdlen as usize;
    }
    
    for _ in 0..arcount {
        qname.clear();
        let amt = packet::read_name(offset, &buffer, &mut qname, 0)?;
        offset += amt;

        let pkt = packet::AnswerPacket::new_checked(&buffer[offset..])?;
        offset += pkt.header_len();

        let kind  = pkt.kind();
        let class = pkt.class();
        let ttl   = pkt.ttl();
        let rdlen = pkt.rdlen();
        let rdata = pkt.rdata();
        let record = packet::Record::parse(offset, &buffer, kind, class, rdata)?;
        println!("Additional Records Section: QNAME={:?} ATYPE={} ACLASS={} TTL={} RDATA={:?}",
                qname,
                kind,
                class,
                ttl,
                record,
                );
        offset += rdlen as usize;
    }

    Ok(())
}
