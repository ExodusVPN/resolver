use native_tls;
use tokio_tls::TlsAcceptor;

use tokio::net::TcpListener;
use tokio::net::TcpStream;

use std::io;
use std::fs;
use std::path::Path;
use std::net::SocketAddr;

pub type TlsStream = tokio_tls::TlsStream<TcpStream>;

pub struct TlsIdentity {
    inner: native_tls::Identity,
}

impl TlsIdentity {
    pub fn from_pkcs12<K: AsRef<[u8]>, P: AsRef<str>>(key: K, pass: P) -> Result<Self, io::Error> {
        let ident = native_tls::Identity::from_pkcs12(key.as_ref(), pass.as_ref())
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        Ok(Self { inner: ident })
    }

    pub fn from_pkcs12_file<K: AsRef<Path>, P: AsRef<str>>(key_path: K, pass: P) -> Result<Self, io::Error> {
        let key = fs::read(key_path.as_ref())?;
        Self::from_pkcs12(&key, pass)
    }
}

#[derive(Debug)]
pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    pub async fn bind<A: tokio::net::ToSocketAddrs>(addr: A, identity: TlsIdentity) -> Result<Self, io::Error> {
        let listener = TcpListener::bind(&addr).await?;

        let tls_acceptor = native_tls::TlsAcceptor::builder(identity.inner)
            .min_protocol_version(Some(native_tls::Protocol::Tlsv11))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let tls_acceptor = tokio_tls::TlsAcceptor::from(tls_acceptor);

        Ok(Self { listener, acceptor: tls_acceptor })
    }

    pub async fn accept(&mut self) -> Result<(TlsStream, SocketAddr), io::Error> {
        loop {
            let (tcp_stream, peer_addr) = self.listener.accept().await?;
            match self.acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    return Ok((tls_stream, peer_addr));
                },
                Err(e) => {
                    trace!("TLS Handshake Error({}): {:?}", peer_addr, e);
                }
            }
        }
    }

    pub fn acceptor(&self) -> &TlsAcceptor {
        &self.acceptor
    }

    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.listener.local_addr()
    }

    pub fn ttl(&self) -> Result<u32, io::Error> {
        self.listener.ttl()
    }

    pub fn set_ttl(&self, ttl: u32) -> Result<(), io::Error> {
        self.listener.set_ttl(ttl)
    }
}