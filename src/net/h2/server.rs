use crate::net::tls::TlsIdentity;
use crate::net::tls::TlsListener;
use crate::net::tls::TlsStream;

use http;
use h2;
use bytes::Bytes;
use bytes::BytesMut;

use tokio_tls;

use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::stream::Stream;

use std::io;
use std::pin::Pin;
use std::future::Future;
use std::net::SocketAddr;


#[derive(Debug)]
pub struct Http2Listener<T> {
    listener: T,
}

// 
// H2 , HTTP/2.0 over TLS
// H2C, HTTP/2.0 over TCP
// H3 , HTTP/3.0 over DTLS
// H3C, HTTP/3.0 over UDP

pub type H2Listener  = Http2Listener<TlsListener>;
pub type H2CListener = Http2Listener<TcpListener>;


impl H2Listener {
    pub fn new(listener: TlsListener) -> Self {
        Self { listener }
    }

    pub async fn accept(&mut self) -> Result<H2Connection, io::Error> {
        loop {
            let (inner_stream, peer_addr) = self.listener.accept().await?;

            match h2::server::handshake(inner_stream).await {
                Ok(h2_conn) => return Ok(H2Connection { inner: h2_conn, peer_addr, }),
                Err(e) => trace!("Peer={} H2 Connection Handshake Error: {:?}", peer_addr, e),
            }
        }
    }

    pub fn tls_acceptor(&self) -> &tokio_tls::TlsAcceptor {
        &self.listener.acceptor()
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


pub type H2Connection  = Http2Connection<TlsStream>;
pub type H2CConnection = Http2Connection<TcpStream>;

#[derive(Debug)]
pub struct Http2Connection<T> {
    inner: h2::server::Connection<T, bytes::Bytes>,
    peer_addr: SocketAddr,
}

impl H2Connection {
    pub async fn accept(&mut self) -> Option<Result<Http2Stream, h2::Error>> {
        match self.inner.accept().await {
            None => None,
            Some(stream) => match stream {
                Ok((request, respond)) => {
                    debug!("Peer={} Got a H2 Stream: {:?}", self.peer_addr, request.body().stream_id());
                    let (parts, recv_stream) = request.into_parts();
                    return Some(Ok(Http2Stream { parts, recv_stream, send_response: respond, peer_addr: self.peer_addr }));
                },
                Err(e) => {
                    error!("Peer={} H2 Stream ( aka: Channel ) Got Error: {:?}", self.peer_addr, e);
                    return Some(Err(e));
                }
            },
        }
    }

    pub fn abrupt_shutdown(&mut self, reason: h2::Reason) {
        self.inner.abrupt_shutdown(reason)
    }

    pub fn graceful_shutdown(&mut self) {
        self.inner.graceful_shutdown()
    }
}

// pub type H2Stream = Http2Stream<TlsStream>;
// pub type H2CStream = Http2Stream<TcpStream>;

#[derive(Debug)]
pub struct Http2Stream {
    parts: http::request::Parts,
    recv_stream: h2::RecvStream,
    send_response: h2::server::SendResponse<bytes::Bytes>,
    peer_addr: SocketAddr,
}

impl Http2Stream {
    pub fn is_end_stream(&self) -> bool {
        self.recv_stream.is_end_stream()
    }

    #[inline]
    pub fn stream_id(&self) -> h2::StreamId {
        self.recv_stream.stream_id()
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub fn head(&self) -> &http::request::Parts {
        &self.parts
    }

    pub async fn read_body(&mut self) -> Result<Vec<u8>, h2::Error> {
        let mut body: Vec<u8> = Vec::new();
        loop {
            match self.recv_stream.data().await {
                Some(Ok(data)) => {
                    // TODO: 需要手动释放内存吗？
                    //       flow_control().release_capacity()
                    body.extend_from_slice(data.as_ref());
                },
                Some(Err(e)) => {
                    error!("Peer={} StreamId={:?} H2 Request Stream read body data error: {:?}", self.peer_addr, self.stream_id(), e);
                    return Err(e);
                },
                None => {
                    break;
                }
            }
        }

        Ok(body)
    }

    pub async fn write_response(&mut self, res: http::Response<Option<Vec<u8>>>) -> Result<(), h2::Error> {
        let (parts, body) = res.into_parts();
        let res = http::Response::from_parts(parts, ());

        let flag = if body.is_some() { false } else { true };
        match self.send_response.send_response(res, flag) {
            Ok(mut sender) => {
                match body {
                    Some(body) => {
                        if let Err(e) = sender.send_data(bytes::Bytes::from(body), true) {
                            error!("Peer={} StreamId={:?} H2 Request Stream write response body error: {:?}",
                                self.peer_addr,
                                self.stream_id(),
                                e);
                            return Err(e);
                        }
                    },
                    None => { },
                }

                Ok(())
            },
            Err(e) => {
                error!("Peer={} StreamId={:?} H2 Request Stream write response head error: {:?}",
                    self.peer_addr,
                    self.stream_id(),
                    e);
                Err(e)
            }
        }
    }
}


