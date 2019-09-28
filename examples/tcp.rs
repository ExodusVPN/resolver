extern crate resolver;

use resolver::packet;


use std::env;
use std::io::{self, Read, Write};
use std::net::TcpStream;


fn main() -> Result<(), io::Error> {
    // Example:
    //      $ cargo run --example tcp www.gov.cn
    let name = env::args().skip(1).next().expect("请在命令行参数当中加上需要查询的域名！");

    // let name_server = "f.root-servers.net:53";
    let name_server = "8.8.8.8:53";
    println!("NameServer: {:?} Name: {:?}\n", name_server, name);
    let mut conn = TcpStream::connect(name_server)?;

    resolve(&mut conn, &name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Resolve Error: {:?}", e) ) )?;


    Ok(())
}

fn resolve(conn: &mut TcpStream, name: &str) -> Result<(), resolver::Error> {

    let mut buffer = [0u8; 1024*4];
    let mut pkt = packet::HeaderPacket::new_unchecked(&mut buffer[..]);
    pkt.set_id(1);
    pkt.set_qr(packet::MessageType::Query);
    pkt.set_opcode(packet::OpCode::QUERY);
    pkt.set_aa(false); // Authoritative Answer
    pkt.set_tc(false); // TrunCation
    pkt.set_rd(true);  // Recursion Desired
    pkt.set_ra(false); // Recursion Available
    pkt.set_z(0);
    pkt.set_rcode(packet::ResponseCode::OK);
    pkt.set_qdcount(1);
    pkt.set_ancount(0);
    pkt.set_nscount(0);
    pkt.set_arcount(0);
    
    let mut qpkt = packet::QuestionPacket::new_unchecked(pkt.payload_mut());

    qpkt.set_names(name);
    qpkt.set_qtype(packet::QuestionType::A);
    qpkt.set_qclass(packet::QuestionClass::IN);

    let mut buffer = pkt.into_inner();
    let packet_len = packet::query_packet_min_size(name);

    assert!(packet_len <= std::u16::MAX as usize);

    conn.write_all(&(packet_len as u16).to_be_bytes()).unwrap();
    conn.write_all(&buffer[..packet_len]).unwrap();

    println!("send {:?}", &buffer[..packet_len]);

    conn.read(&mut buffer[..2]).unwrap();
    let amt = conn.read(&mut buffer).unwrap();
    println!("amt: {:?}", amt);
    println!("recv: {:?}", &buffer[..amt]);

    let buffer = &buffer[..amt];
    let hdr = packet::HeaderPacket::new_checked(&buffer[..])?;
    println!("{}", hdr);
    let ancount = hdr.ancount() as usize;

    let mut payload = hdr.payload();
    let ques = packet::QuestionPacket::new_checked(payload)?;
    println!("{}", ques);
    payload = ques.payload();

    for _ in 0..ancount {
        let ans = packet::AnswerPacket::new_checked(payload)?;
        println!("AnswerPacket:");
        println!("\tatype: {}", ans.atype());
        println!("\taclass: {}", ans.aclass());
        println!("\tttl: {:?}", ans.ttl());
        println!("\trdlen: {:?}", ans.rdlen());
        println!("\trdata: {:?}\n", ans.rdata());

        payload = &ans.payload()[..];
    }
    
    Ok(())
}
