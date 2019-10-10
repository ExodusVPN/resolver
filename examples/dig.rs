extern crate resolver;

use resolver::packet;

use std::env;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, TcpStream};


fn usage() -> ! {
    println!("用例:

    $ cargo run --example dig 8.8.8.8:53 www.gov.cn");

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

    resolver::init();
    
    println!("🔍 DNS Query {:?} over tcp://{}", domain_name, name_server);
    let mut conn = TcpStream::connect(name_server)?;

    resolve(&mut conn, &domain_name)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Resolve Error: {:?}", e) ) )?;
    
    Ok(())
}

fn resolve(conn: &mut TcpStream, name: &str) -> Result<(), resolver::Error> {
    let mut buffer = packet::alloc();

    let client_ip = IpAddr::V4(Ipv4Addr::new(180, 164, 57, 109));
    let client_cidr_prefix_len = 32;

    let mut builder = packet::QueryBuilder::new(&mut buffer[..]);
    let _msg = builder
        .set_id(1)
        .set_flags(packet::Flags::RECURSION_REQUEST)
        .add_question(name, packet::Kind::A, packet::Class::IN)?
        // WARN: 绝大部分 DNS 递归解析器不支持添加多个 Question.
        // .add_question(name, packet::Kind::AAAA, packet::Class::IN)?
        .add_opt_record(Some((client_ip, client_cidr_prefix_len)))?
        .build();
    let msg_len = builder.len();

    packet::pretty_print(4, &buffer);

    // TCP Write
    assert!(msg_len <= std::u16::MAX as usize);
    conn.write_all(&(msg_len as u16).to_be_bytes()).unwrap();
    conn.write_all(&buffer[..msg_len]).unwrap();

    // TCP Read
    conn.read(&mut buffer[..2]).unwrap();
    let amt = conn.read(&mut buffer).unwrap();
    if amt == 0 {
        return Ok(());
    }

    let buffer = &buffer[..amt];
    println!("🌏 DNS Response: ");
    packet::pretty_print(4, buffer);

    Ok(())
}

