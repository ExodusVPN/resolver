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
    let mut buffer = [0u8; 2048];
    let mut qname = String::new();
    let mut cache: HashMap<u64, u16> = HashMap::new();

    let mut pkt = packet::HeaderPacket::new_unchecked(&mut buffer[..]);
    pkt.set_id(1);

    let mut flags = packet::Flags::REQUEST;
    // let mut flags = packet::Flags::RECURSION_REQUEST;
    flags.set_do(true);

    println!("flags: {:?}", flags);

    pkt.set_flags(flags);
    pkt.set_qdcount(1);
    pkt.set_ancount(0);
    pkt.set_nscount(0);
    pkt.set_arcount(0);
    
    let header_size = packet::HeaderPacket::<&[u8]>::HEADER_SIZE;
    // let ques_size   = packet::QuestionPacket::<&[u8]>::SIZE;

    let mut offset = pkt.len();
    
    let amt = packet::write_name(name, offset, &mut buffer, &mut cache)?;
    offset += amt;

    let mut pkt = packet::QuestionPacket::new_unchecked(&mut buffer[offset..]);
    pkt.set_qtype(packet::Kind::A);
    pkt.set_qclass(packet::Class::IN);

    offset += pkt.len();

    println!("Send Packet:");
    println!("Header Packet: {}", packet::HeaderPacket::new_checked(&buffer[..header_size])?);

    let pkt = packet::QuestionPacket::new_checked(&buffer[header_size + amt..offset])?;
    let _amt = packet::read_name(header_size, &buffer, &mut qname, 0)?;
    println!("Question Packet: QNAME={:?} QTYPE={} QCLASS={}", qname.to_string(), pkt.qtype(), pkt.qclass());

    assert!(offset <= std::u16::MAX as usize);
    conn.write_all(&(offset as u16).to_be_bytes()).unwrap();

    println!("send bytes: {:?}", &buffer[..offset]);
    conn.write_all(&buffer[..offset]).unwrap();

    println!();

    // Read
    conn.read(&mut buffer[..2]).unwrap();

    let amt = conn.read(&mut buffer).unwrap();
    println!("recv {:?} bytes from name server.", amt);
    println!("message body: {:?}", &buffer[header_size..amt]);

    let buffer = &buffer[..amt];
    println!("{:?}", &buffer);

    let hdr = packet::HeaderPacket::new_checked(&buffer[..])?;
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

        println!("Question Section: QNAME={:?} QTYPE={} QCLASS={}", qname.to_string(), pkt.qtype(), pkt.qclass());
    }
    


    for _ in 0..ancount {
        qname.clear();
        let amt = packet::read_name(offset, &buffer, &mut qname, 0)?;
        offset += amt;

        let pkt = packet::AnswerPacket::new_checked(&buffer[offset..])?;
        offset += pkt.len();

        let kind  = pkt.atype();
        let class = pkt.aclass();
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
        offset += pkt.len();
        
        let kind  = pkt.atype();
        let class = pkt.aclass();
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

        offset += rdlen as usize;
    }
    
    for _ in 0..arcount {
        qname.clear();
        let amt = packet::read_name(offset, &buffer, &mut qname, 0)?;
        offset += amt;

        let pkt = packet::AnswerPacket::new_checked(&buffer[offset..])?;
        offset += pkt.len();

        let kind  = pkt.atype();
        let class = pkt.aclass();
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
