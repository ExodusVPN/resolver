extern crate resolver;
extern crate env_logger;

use resolver::wire;

use std::env;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};


fn usage() -> ! {
    println!("用例:

    $ cargo run --example dig 8.8.8.8:53 www.gov.cn
    $ cargo run --example dig 199.7.83.42:53 www.youtube.com");

    std::process::exit(0);
}

fn main() -> Result<(), io::Error> {
    env_logger::init();

    let mut args = env::args().skip(1);

    let name_server = match args.next() {
        Some(ns) => ns,
        None => usage(),
    };
    let domain_name = match args.next() {
        Some(name) => name,
        None => usage(),
    };

    resolver::init();
    
    println!("🔍 DNS Query {:?} over tcp://{}", domain_name, name_server);
    let mut conn = TcpStream::connect(name_server)?;

    resolve(&mut conn, &domain_name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Resolve Error: {:?}", e) ) )?;

    Ok(())
}

fn resolve(conn: &mut TcpStream, name: &str) -> Result<(), resolver::Error> {
    let mut buffer = wire::alloc();

    let client_ip = IpAddr::V4(Ipv4Addr::new(180, 164, 57, 109));
    let client_cidr_prefix_len = 32;

    let ecs = wire::ClientSubnet {
        src_prefix_len: client_cidr_prefix_len,
        scope_prefix_len: 0,
        address: client_ip,
    };
    let request = wire::Request {
        id: 1,
        flags: wire::ReprFlags::default(),
        opcode: wire::OpCode::QUERY,
        client_subnet: Some(ecs),
        question: wire::Question {
            name: name.to_string(),
            kind: wire::Kind::A,
            class: wire::Class::IN,
        },
    };

    let amt = request.serialize(&mut buffer[2..])?;
    assert!(amt <= std::u16::MAX as usize);

    let amt_octets = (amt as u16).to_be_bytes();
    buffer[0] = amt_octets[0];
    buffer[1] = amt_octets[1];

    let request = wire::Request::parse(&buffer[2..amt+2])?;
    request.pretty_print();

    // TCP Write
    conn.write_all(&buffer[..amt+2]).unwrap();

    // TCP Read
    let amt = conn.read(&mut buffer[..2]).unwrap();
    assert!(amt <= std::u16::MAX as usize);
    
    let amt = conn.read(&mut buffer[..]).unwrap();
    if amt == 0 {
        return Ok(());
    }

    let buffer = &buffer[..amt];
    println!("🌏 DNS Response: ");
    let response = wire::Response::parse(&buffer)?;
    response.pretty_print();

    Ok(())
}

