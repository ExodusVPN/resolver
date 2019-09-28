extern crate resolver;

use resolver::packet;


fn main() -> Result<(), resolver::Error> {
    let mut buffer = vec![0u8; 1024 * 4];

    let mut pkt = packet::QuestionPacket::new_unchecked(&mut buffer);
    pkt.set_names("www.example.com");
    pkt.set_qtype(packet::QuestionType(111));
    pkt.set_qclass(packet::QuestionClass(222));
    
    let buffer = pkt.into_inner();

    println!("{}", packet::QuestionPacket::new_checked(&buffer)? );

    Ok(())
}
