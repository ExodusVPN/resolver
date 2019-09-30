extern crate resolver;

use resolver::packet;


use std::env;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::collections::HashMap;


fn main() -> Result<(), io::Error> {
    // Example:
    //      $ cargo run --example tcp www.gov.cn
    let name = env::args().skip(1).next().expect("请在命令行参数当中加上需要查询的域名！");

    let name_server = "8.8.8.8:53";       // 第三方
    println!("NameServer: {:?} Name: {:?}\n", name_server, name);
    let mut conn = TcpStream::connect(name_server)?;

    resolve(&mut conn, &name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Resolve Error: {:?}", e) ) )?;


    Ok(())
}

fn resolve(conn: &mut TcpStream, name: &str) -> Result<(), resolver::Error> {
    let mut buffer = [0u8; 2048];

    let mut cache: HashMap<u64, u16> = HashMap::new();

    let mut pkt = packet::HeaderPacket::new_unchecked(&mut buffer[..]);
    pkt.set_id(1);
    pkt.set_flags(packet::Flags::RECURSION_REQUEST);
    pkt.set_qdcount(1);
    pkt.set_ancount(0);
    pkt.set_nscount(0);
    pkt.set_arcount(0);
    
    let header_size = packet::HeaderPacket::<&[u8]>::HEADER_SIZE;
    let ques_size   = packet::QuestionPacket::<&[u8]>::SIZE;

    let mut offset = header_size;
    
    let amt = packet::write_name(name, offset, &mut buffer, &mut cache)?;
    offset += amt;

    let mut pkt = packet::QuestionPacket::new_unchecked(&mut buffer[offset..]);
    pkt.set_qtype(packet::Kind::A);
    pkt.set_qclass(packet::Class::IN);
    
    offset += ques_size;

    println!("Send Packet:");
    println!("Header Packet: {}", packet::HeaderPacket::new_checked(&buffer[..header_size])?);

    let pkt = packet::QuestionPacket::new_checked(&buffer[header_size + amt..offset])?;
    let qname = packet::read_name(header_size, &buffer)?;
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

    let buffer = &buffer[..amt];
    println!("{:?}", &buffer);

    let hdr = packet::HeaderPacket::new_checked(&buffer[..])?;
    let qdcount = hdr.qdcount() as usize;
    let ancount = hdr.ancount() as usize;
    let nscount = hdr.nscount() as usize;
    let arcount = hdr.arcount() as usize;
    
    println!("{}", hdr);

    let mut offset = header_size;

    for i in 0..qdcount {
        let qname = packet::read_name(offset, &buffer)?;
        let qname_len = qname.len();
        offset += qname_len;

        let pkt = packet::QuestionPacket::new_checked(&buffer[offset..])?;
        offset += ques_size;

        println!("Question Section: QNAME={:?} QTYPE={} QCLASS={}", qname.to_string(), pkt.qtype(), pkt.qclass());
    }
    
    
    for i in 0..ancount {
        let qname = packet::read_name(offset, &buffer)?;
        let qname_len = qname.len();
        // FIXME: 压缩域名的写法还需要再多做些测试。
        offset += qname_len;
        let pkt = packet::AnswerPacket::new_checked(&buffer[offset..])?;
        offset += pkt.len();

        println!("Answer Section: QNAME={:?} ATYPE={} ACLASS={} TTL={} RDLEN: {} RDATA={:?}",
                qname.to_string(),
                pkt.atype(),
                pkt.aclass(),
                pkt.ttl(),
                pkt.rdlen(),
                pkt.rdata());
    }

    for i in 0..nscount {
        let qname = packet::read_name(offset, &buffer)?;
        let qname_len = qname.len();
        // FIXME: 压缩域名的写法还需要再多做些测试。
        offset += qname_len;
        let pkt = packet::AnswerPacket::new_checked(&buffer[offset..])?;
        offset += pkt.len();
        
        println!("Authority Records Section: QNAME={:?} ATYPE={} ACLASS={} TTL={} RDLEN: {} RDATA={:?}",
                qname.to_string(),
                pkt.atype(),
                pkt.aclass(),
                pkt.ttl(),
                pkt.rdlen(),
                pkt.rdata());
    }
    
    for i in 0..arcount {
        let qname = packet::read_name(offset, &buffer)?;
        let qname_len = qname.len();
        // FIXME: 压缩域名的写法还需要再多做些测试。
        offset += qname_len;

        let pkt = packet::AnswerPacket::new_checked(&buffer[offset..])?;
        offset += pkt.len();
        
        println!("Additional Records Section: QNAME={:?} ATYPE={} ACLASS={} TTL={} RDLEN: {} RDATA={:?}",
                qname.to_string(),
                pkt.atype(),
                pkt.aclass(),
                pkt.ttl(),
                pkt.rdlen(),
                pkt.rdata());
    }

    Ok(())
}
