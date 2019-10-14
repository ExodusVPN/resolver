use crate::net::UdpChannel;

use std::fs;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::time::Instant;
use std::time::Duration;


// DNS over DTLS
// https://tools.ietf.org/html/rfc8094
// 
// DTLS 服务端如果不支持 DTLS 则不应该回复任何讯息。
// DTLS 在客户端发出 clienthello 15秒之后，如果没有收到回应，则应该重试，或者选择其它协议。
// 

pub struct DtlsListener {
    udp_socket: mio::net::UdpSocket,
    dtls_acceptor: openssl::ssl::SslAcceptor,
    dtls_sessions: HashMap<SocketAddr, DtlsStream>,
}

impl DtlsListener {
    pub fn accept<'a>(&'a mut self) -> Result<Option<&'a mut DtlsStream>, io::Error> {
        let mut bufer = [0u8; 0];
        let (_, remote_addr) = self.udp_socket.recv_from(&mut bufer)?;

        if !self.dtls_sessions.contains_key(&remote_addr) {
            let instant = Instant::now();
            let mut udp_channel = UdpChannel::new(&self.udp_socket)?;

            udp_channel.set_peer_addr(remote_addr);

            let can_send = true;
            let can_recv = true;
            let mut session = DtlsSession {
                remote_addr, udp_channel, instant, can_send, can_recv
            };

            match self.dtls_acceptor.accept(session) {
                Ok(s) => {
                    self.dtls_sessions.insert(remote_addr, DtlsStream::Ready(s));
                    return Ok(None);
                },
                Err(openssl::ssl::HandshakeError::SetupFailure(e)) => {
                    return Err(io::Error::new(io::ErrorKind::Other, format!("OpenSSL DTLS Setup Failure: {}", e) ))
                },
                Err(openssl::ssl::HandshakeError::Failure(s)) => {
                    return Err(io::Error::new(io::ErrorKind::Other, "OpenSSL DTLS Handshake Failed" ))
                },
                Err(openssl::ssl::HandshakeError::WouldBlock(s)) => {
                    self.dtls_sessions.insert(remote_addr, DtlsStream::Auth(s));
                    return Ok(None);
                },
            }
        }

        let stream = self.dtls_sessions.get(&remote_addr).unwrap();
        if stream.is_ready() {
            let mut stream = self.dtls_sessions.get_mut(&remote_addr).unwrap();
            let mut session = stream.session_mut();
            session.can_recv = true;
            // DTLS 层已经握手通讯完毕，可以传输 DTLS Payload 了。
            return Ok(Some(stream));
        } else {
            // DTLS 的握手流程还没有走完
            let mut stream = self.dtls_sessions.remove(&remote_addr).unwrap();
            let stream = stream.handshake()?;

            self.dtls_sessions.insert(remote_addr, stream);

            // NOTE: 等待下一次读取
            return Ok(None)
        }
    }
}


pub enum DtlsStream {
    Auth(openssl::ssl::MidHandshakeSslStream<DtlsSession>),
    Ready(openssl::ssl::SslStream<DtlsSession>)
}

impl DtlsStream {
    #[inline]
    pub fn is_ready(&self) -> bool {
        match self {
            &Self::Auth(_) => false,
            &Self::Ready(_) => true,
        }
    }

    pub fn session(&self) -> &DtlsSession {
        match self {
            &Self::Auth(ref s) => s.get_ref(),
            &Self::Ready(ref s) => s.get_ref(),
        }
    }

    pub fn session_mut(&mut self) -> &mut DtlsSession {
        match self {
            &mut Self::Auth(ref mut s) => s.get_mut(),
            &mut Self::Ready(ref mut s) => s.get_mut(),
        }
    }

    pub fn handshake(self) -> Result<Self, io::Error> {
        match self {
            Self::Auth(stream) => {
                match stream.handshake() {
                    Ok(s) => return Ok(Self::Ready(s)),
                    Err(openssl::ssl::HandshakeError::SetupFailure(e)) => {
                        return Err(io::Error::new(io::ErrorKind::Other, format!("OpenSSL DTLS Setup Failure: {}", e) ))
                    },
                    Err(openssl::ssl::HandshakeError::Failure(s)) => {
                        return Err(io::Error::new(io::ErrorKind::Other, "OpenSSL DTLS Handshake Failed" ))
                    },
                    Err(openssl::ssl::HandshakeError::WouldBlock(s)) => {
                        return Ok(Self::Auth(s));
                    },
                }
            },
            Self::Ready(_) => Ok(self),
        }
    }
}

pub struct DtlsSession {
    remote_addr: SocketAddr,
    udp_channel: UdpChannel,
    instant: Instant,
    can_send: bool,
    can_recv: bool,
}

impl DtlsSession {
    pub fn is_timeout(&self) -> bool {
        const DTLS_TIMEOUT: Duration = Duration::from_secs(60);
        self.instant.elapsed() > DTLS_TIMEOUT
    }
}

impl Write for DtlsSession {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        if !self.can_send {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }

        // NOTE: 传输层不做检查（暂时没有想好怎么做检查）
        // if buf.len() > 512 {
        //     return Err(io::Error::from(io::ErrorKind::WriteZero));
        // }
        
        self.udp_channel.send_to(buf, &self.remote_addr)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl Read for DtlsSession {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        if !self.can_recv {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }

        let ret = self.udp_channel.read(buf);

        self.can_recv = false;

        ret
    }
}


impl Write for DtlsStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match self {
            &mut DtlsStream::Auth(_) => unreachable!(),
            &mut DtlsStream::Ready(ref mut s) => {
                if buf.len() > 512 {
                    return Err(io::Error::from(io::ErrorKind::WriteZero));
                }

                s.write(buf)
            }
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl Read for DtlsStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self {
            &mut DtlsStream::Auth(_) => unreachable!(),
            &mut DtlsStream::Ready(ref mut s) => {
                s.read(buf)
            }
        }
    }
}

pub fn dtls_acceptor() -> Result<openssl::ssl::SslAcceptor, io::Error> {
    let certs = [
        fs::read("./keys/root.crt")?,
        fs::read("./keys/ca.crt")?,
        fs::read("./keys/server.crt")?,
    ];

    fn f(certs: &[Vec<u8>]) -> Result<openssl::ssl::SslAcceptor, openssl::error::ErrorStack> {
        let method = openssl::ssl::SslMethod::dtls();
        let mut builder = openssl::ssl::SslAcceptor::mozilla_intermediate_v5(method)?;
        let mut store = builder.cert_store_mut();
        for cert in certs.iter() {
            store.add_cert(openssl::x509::X509::from_pem(cert)?)?;
        }

        builder.set_private_key_file("./keys/server.key", openssl::ssl::SslFiletype::PEM)?;
        builder.set_certificate_chain_file("./keys/server.crt")?;
        builder.check_private_key()?;

        Ok(builder.build())
    }

    f(&certs).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}
