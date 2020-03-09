use native_tls;
use tokio_tls::TlsAcceptor;

use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

use std::io;
use std::fs;
use std::pin::Pin;
use std::path::Path;
use std::net::SocketAddr;
use std::mem::MaybeUninit;
use std::task::Poll;
use std::task::Context;

pub type TlsVersion = native_tls::Protocol;

const MIN_TLS_VERSION: TlsVersion = native_tls::Protocol::Tlsv12;

#[derive(Debug, Clone, Copy)]
pub struct TlsOption {
    pub min_version: TlsVersion,
    pub use_sni: bool,
}

#[derive(Debug)]
pub struct TlsStream {
    pub(crate) inner: tokio_tls::TlsStream<TcpStream>,
}

impl TlsStream {
    pub async fn connect<S: AsRef<str>, A: tokio::net::ToSocketAddrs>(domain: S, addr: A) -> Result<Self, io::Error> {
        let tcp_stream = TcpStream::connect(addr).await?;
        let tls_connector = native_tls::TlsConnector::builder()
            .min_protocol_version(Some(MIN_TLS_VERSION))
            .use_sni(true)
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let tls_connector = tokio_tls::TlsConnector::from(tls_connector);

        let tls_stream = tls_connector
            .connect(domain.as_ref(), tcp_stream)
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Self { inner: tls_stream })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.inner.get_ref().local_addr()
    }

    pub fn peer_addr(&self) -> Result<SocketAddr, io::Error> {
        self.inner.get_ref().peer_addr()
    }

    pub fn ttl(&self) -> Result<u32, io::Error> {
        self.inner.get_ref().ttl()
    }

    pub fn set_ttl(&self, ttl: u32) -> Result<(), io::Error> {
        self.inner.get_ref().set_ttl(ttl)
    }

    pub fn into_inner(self) -> tokio_tls::TlsStream<TcpStream> {
        self.inner
    }
}

impl AsyncRead for TlsStream {
    unsafe fn prepare_uninitialized_buffer(&self, buf: &mut [MaybeUninit<u8>]) -> bool {
        self.inner.prepare_uninitialized_buffer(buf)
    }

    fn poll_read(self: Pin<&mut Self>, cx: &mut Context, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut (self.get_mut()).inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut (self.get_mut()).inner).poll_write(ctx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut (self.get_mut()).inner).poll_flush(ctx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut (self.get_mut()).inner).poll_shutdown(ctx)
    }
}

impl AsRef<tokio_tls::TlsStream<TcpStream>> for TlsStream {
    #[inline]
    fn as_ref(&self) -> &tokio_tls::TlsStream<TcpStream> {
        &self.inner
    }
}

impl AsMut<tokio_tls::TlsStream<TcpStream>> for TlsStream {
    #[inline]
    fn as_mut(&mut self) -> &mut tokio_tls::TlsStream<TcpStream> {
        &mut self.inner
    }
}


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

    pub fn into_acceptor(self) -> Result<TlsAcceptor, io::Error> {
        let tls_acceptor = native_tls::TlsAcceptor::builder(self.inner)
            .min_protocol_version(Some(MIN_TLS_VERSION))
            .build()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(tokio_tls::TlsAcceptor::from(tls_acceptor))
    }
}

#[derive(Debug)]
pub struct TlsListener {
    listener: TcpListener,
    acceptor: TlsAcceptor,
}

impl TlsListener {
    pub async fn bind<A: tokio::net::ToSocketAddrs>(addr: A, identity: TlsIdentity) -> Result<Self, io::Error> {
        let listener = TcpListener::bind(addr).await?;
        let acceptor = identity.into_acceptor()?;

        Ok(Self { listener, acceptor, })
    }

    pub async fn accept(&mut self) -> Result<(TlsStream, SocketAddr), io::Error> {
        loop {
            let (tcp_stream, peer_addr) = self.listener.accept().await?;
            match self.acceptor.accept(tcp_stream).await {
                Ok(tls_stream) => {
                    let tls_stream = TlsStream { inner: tls_stream };
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