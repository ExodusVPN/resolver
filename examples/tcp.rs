extern crate resolver;

use resolver::packet;


use std::env;
use std::io::{self, Read, Write};
use std::net::TcpStream;


fn main() -> Result<(), io::Error> {
    let name = env::args().skip(1).next().unwrap();

    // let name_server = "f.root-servers.net:53";
    let name_server = "8.8.8.8:53";
    let mut conn = TcpStream::connect(name_server)?;

    resolve(&mut conn, &name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Resolve Error: {:?}", e) ) )?;


    Ok(())
}

fn resolve(conn: &mut TcpStream, name: &str) -> Result<(), resolver::Error> {

    let mut buffer = [0u8; 1024];
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

    let hdr = packet::HeaderPacket::new_checked(&buffer[..amt])?;
    println!("{}", hdr);
    // let ques = packet::QuestionPacket::new_checked(&buffer[12..])?;
    // println!("{}", ques);

    let ans = packet::AnswerPacket::new_checked(&buffer[12..])?;
    // println!("rdlen: {:?}", ans.rdlen());
    println!("{}", ans);
    println!("{:?}", ans.payload());

    Ok(())
}
