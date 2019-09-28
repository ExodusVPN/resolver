extern crate resolver;

use resolver::packet;


fn main() -> Result<(), resolver::Error> {
    let mut buffer = vec![0u8; 1024];

    let mut pkt = packet::QuestionPacket::new_unchecked(&mut buffer);
    pkt.set_names("www.example.com");
    pkt.set_qtype(packet::QuestionType(111));
    pkt.set_qclass(packet::QuestionClass(222));
    
    let buffer = pkt.into_inner();

    println!("{}", packet::QuestionPacket::new_checked(&buffer)? );

    let mut buffer = vec![0u8; 1024];
    let mut pkt = packet::HeaderPacket::new_unchecked(&mut buffer[..]);
    pkt.set_id(1);
    pkt.set_qr(packet::MessageType::Response);
    pkt.set_opcode(packet::OpCode::UPDATE);
    pkt.set_aa(false);
    pkt.set_tc(true);
    pkt.set_rd(false);
    pkt.set_ra(false);
    pkt.set_z(0);
    pkt.set_rcode(packet::ResponseCode::OK);
    pkt.set_qdcount(1);
    pkt.set_ancount(0);
    pkt.set_nscount(0);
    pkt.set_arcount(0);
    
    let buffer = pkt.into_inner();
    println!("{}", packet::HeaderPacket::new_checked(&buffer)? );

    Ok(())
}
