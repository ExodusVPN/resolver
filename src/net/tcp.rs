use std::io::{self, Read, Write};

// 4.2.2. TCP usage
// https://tools.ietf.org/html/rfc1035#section-4.2.2
// 
// Messages sent over TCP connections use server port 53 (decimal).  The
// message is prefixed with a two byte length field which gives the message
// 
// length, excluding the two byte length field.  This length field allows
// the low-level processing to assemble a complete message before beginning
// to parse it.
// 
// 
// 8.  TCP Message Length Field
// https://tools.ietf.org/html/rfc7766#section-8
// 
// DNS clients and servers SHOULD pass the two-octet length field, and
// the message described by that length field, to the TCP layer at the
// same time (e.g., in a single "write" system call) to make it more
// likely that all the data will be transmitted in a single TCP segment.
// This is for reasons of both efficiency and to avoid problems due to
// some DNS server implementations behaving undesirably when reading
// data from the TCP layer (due to a lack of clarity in previous
// documents).  For example, some DNS server implementations might abort
// a TCP session if the first "read" from the TCP layer does not contain
// both the length field and the entire message.
// 
// To clarify, DNS servers MUST NOT close a connection simply because
// the first "read" from the TCP layer does not contain the entire DNS
// message, and servers SHOULD apply the connection timeouts as
// specified in Section 6.2.3.
// 

// 
// fn resolve(conn: &mut TcpStream, name: &str) -> Result<(), resolver::Error> {
//     let mut buffer = wire::alloc();

//     let client_ip = IpAddr::V4(Ipv4Addr::new(180, 164, 57, 109));
//     let client_cidr_prefix_len = 32;
    
//     let mut builder = wire::QueryBuilder::new(&mut buffer[..]);
//     let _msg = builder
//         .set_id(1)
//         .set_flags(wire::Flags::RECURSION_REQUEST)
//         .add_question(name, wire::Kind::A, wire::Class::IN)?
//         // WARN: 绝大部分 DNS 递归解析器不支持添加多个 Question.
//         // .add_question(name, wire::Kind::AAAA, wire::Class::IN)?
//         .add_opt_record(Some((client_ip, client_cidr_prefix_len)))?
//         .build();
//     let msg_len = builder.len();

//     wire::pretty_print(4, &buffer);

//     // TCP Write
//     assert!(msg_len <= std::u16::MAX as usize);
//     conn.write_all(&(msg_len as u16).to_be_bytes()).unwrap();
//     conn.write_all(&buffer[..msg_len]).unwrap();

//     // TCP Read
//     conn.read(&mut buffer[..2]).unwrap();
//     let amt = conn.read(&mut buffer).unwrap();
//     if amt == 0 {
//         return Ok(());
//     }

//     let buffer = &buffer[..amt];
//     println!("🌏 DNS Response: ");
//     wire::pretty_print(4, buffer);

//     Ok(())
// }

pub fn read<R: Read>(stream: &mut R, buffer: &mut [u8]) -> Result<usize, io::Error> {
    debug_assert!(buffer.len() > 2);

    stream.read_exact(&mut buffer[..2])?;

    let amt = u16::from_be_bytes([buffer[0], buffer[1]]) as usize;
    if amt == 0 {
        return Ok(amt);
    }

    if amt > buffer.len() {
        return Err(io::Error::new(io::ErrorKind::Other, "Buffer is too small"));
    }

    stream.read_exact(&mut buffer[..amt])?;

    Ok(amt)
}

pub fn write_all<W: Write>(stream: &mut W, buffer: &[u8]) -> Result<(), io::Error> {
    let amt = buffer.len();
    if amt > std::u16::MAX as usize {
        // NOTE: TCP协议本身没有长度限制，
        //       但是在TCP协议中，发送DNS消息前必须要先发送两个Byte的DNS消息长度，
        //       所以实际上，运行在TCP协议上的DNS消息长度最大为 65535。
        return Err(io::Error::new(io::ErrorKind::Other, "Buffer is too large"));
    }

    let amt_bytes = (amt as u16).to_be_bytes();
    stream.write_all(&amt_bytes)?;
    stream.write_all(buffer)
}

