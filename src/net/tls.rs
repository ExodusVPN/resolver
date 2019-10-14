use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::collections::HashMap;
use std::io::{self, Read, Write};

// Specification for DNS over Transport Layer Security (TLS)
// https://tools.ietf.org/html/rfc7858
// 
// 3.3.  Transmitting and Receiving Messages
// https://tools.ietf.org/html/rfc7858#section-3.3
// 
// 

pub enum TlsStream {
    Auth(native_tls::MidHandshakeTlsStream<mio::net::TcpStream>),
    Ready(native_tls::TlsStream<mio::net::TcpStream>),
}

impl TlsStream {
    #[inline]
    pub fn is_ready(&self) -> bool {
        match self {
            &Self::Auth(_) => false,
            &Self::Ready(_) => true,
        }
    }

    #[inline]
    pub fn tcp_stream(&self) -> &mio::net::TcpStream {
        match self {
            &Self::Auth(ref s) => s.get_ref(),
            &Self::Ready(ref s) => s.get_ref(),
        }
    }

    #[inline]
    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        match self {
            &Self::Auth(ref s) => s.get_ref().local_addr(),
            &Self::Ready(ref s) => s.get_ref().local_addr(),
        }
    }

    #[inline]
    pub fn peer_addr(&self) -> Result<SocketAddr, io::Error> {
        match self {
            &Self::Auth(ref s) => s.get_ref().peer_addr(),
            &Self::Ready(ref s) => s.get_ref().peer_addr(),
        }
    }

    pub fn handshake(self) -> Result<Self, io::Error> {
        match self {
            Self::Auth(stream) => {
                match stream.handshake() {
                    Ok(s) => Ok(Self::Ready(s)),
                    Err(native_tls::HandshakeError::WouldBlock(s)) => Ok(Self::Auth(s)),
                    Err(native_tls::HandshakeError::Failure(e)) => {
                        Err(io::Error::new(io::ErrorKind::Other, e))
                    },
                }
            },
            Self::Ready(_) => Ok(self),
        }
    }
}

impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match self {
            &mut Self::Ready(ref mut stream) => stream.write(buf),
            _ => Err(io::Error::from(io::ErrorKind::WriteZero)),
        }
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        match self {
            &mut Self::Ready(ref mut stream) => stream.read(buf),
            _ => Ok(0),
        }
    }
}


pub struct TlsListener {
    tcp_listener: mio::net::TcpListener,
    tls_acceptor: native_tls::TlsAcceptor,
}

impl TlsListener {
    #[inline]
    pub fn new(tcp_listener: mio::net::TcpListener, tls_acceptor: native_tls::TlsAcceptor) -> Self {
        Self { tcp_listener, tls_acceptor }
    }

    #[inline]
    pub fn acceptor(&self) -> &native_tls::TlsAcceptor {
        &self.tls_acceptor
    }

    #[inline]
    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.tcp_listener.local_addr()
    }

    #[inline]
    pub fn tcp_listener(&self) -> &mio::net::TcpListener {
        &self.tcp_listener
    }

    pub fn accept(&self) -> Result<(TlsStream, SocketAddr), io::Error> {
        let (tcp_stream, peer_addr) = self.tcp_listener.accept()?;

        match self.tls_acceptor.accept(tcp_stream) {
            Ok(s) => Ok((TlsStream::Ready(s), peer_addr)),
            Err(native_tls::HandshakeError::WouldBlock(s)) => Ok((TlsStream::Auth(s), peer_addr)),
            Err(native_tls::HandshakeError::Failure(e)) => {
                Err(io::Error::new(io::ErrorKind::Other, e))
            },
        }
    }
}


impl mio::event::Evented for TlsStream {
    fn register(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready, opts: mio::PollOpt)
        -> io::Result<()>
    {
        self.tcp_stream().register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready, opts: mio::PollOpt)
        -> io::Result<()>
    {
        self.tcp_stream().reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        self.tcp_stream().deregister(poll)
    }
}

impl mio::event::Evented for TlsListener {
    fn register(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready, opts: mio::PollOpt)
        -> io::Result<()>
    {
        self.tcp_listener().register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready, opts: mio::PollOpt)
        -> io::Result<()>
    {
        self.tcp_listener().reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        self.tcp_listener().deregister(poll)
    }
}