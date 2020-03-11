use crate::net::tls::TlsIdentity;
use crate::net::tls::TlsListener;
use crate::net::tls::TlsStream;

use http;
use base64;
use h2;

use tokio::net::TcpStream;
use tokio::stream::Stream;

use std::io;


pub struct H2ReadResponse {
    inner: h2::client::ResponseFuture,
    peer_addr: std::net::SocketAddr,
}

impl H2ReadResponse {
    pub fn stream_id(&self) -> h2::StreamId {
        self.inner.stream_id()
    }

    pub fn peer_addr(&self) -> std::net::SocketAddr {
        self.peer_addr
    }

    pub async fn read_response(self) -> Result<http::Response<Vec<u8>>, io::Error> {
        let stream_id = self.stream_id();
        let peer_addr = self.peer_addr;

        let (head, mut recv_stream) = self.inner.await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?
            .into_parts();

        trace!("Got Response from Peer={} StreamId={:?}:", peer_addr, stream_id);
        println!("{:?} {}", head.version, head.status);
        for (k, v) in head.headers.iter() {
            println!("{}: {:?}", k, v);
        }
        println!();

        let mut body = Vec::new();
        let mut flow_control = recv_stream.flow_control().clone();
        while let Some(chunk) = recv_stream.data().await {
            let chunk = chunk.map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
            body.extend_from_slice(&chunk);
            // NOTE: mem free
            let _ = flow_control.release_capacity(chunk.len());
        }
        
        if log_enabled!(log::Level::Trace) {
            let hexbody = body.iter().fold(String::new(), |mut acc, n| {
                acc.push_str(&format!("{:x}", n));
                acc
            });
            println!("0x{}", hexbody);
        }

        Ok(http::Response::from_parts(head, body))
    }
}

pub struct H2Connection {
    inner: h2::client::SendRequest<bytes::Bytes>,
    peer_addr: std::net::SocketAddr,
}

impl H2Connection {
    pub async fn connect<A: AsRef<str>>(addr: A) -> Result<Self, io::Error> {
        let uri = addr.as_ref()
            .parse::<http::uri::Uri>()
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        let domain = uri.host().ok_or_else(|| io::Error::new(io::ErrorKind::Other, "host not found."))?;

        if !addr.as_ref().contains(':') {
            Self::connect2(domain, &format!("{}:443", addr.as_ref())).await
        } else {
            Self::connect2(domain, addr.as_ref()).await
        }
    }

    pub async fn connect2<S: AsRef<str>, A: tokio::net::ToSocketAddrs>(domain: S, addr: A) -> Result<Self, io::Error> {
        let tls_stream = TlsStream::connect(domain.as_ref(), addr).await?;
        
        let peer_addr  = tls_stream.peer_addr()?;

        let (send_request, connection) = h2::client::handshake(tls_stream.into_inner())
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        let domain = domain.as_ref().to_string();
        tokio::spawn(async move {
            if let Err(e) = connection.await {
                error!("Peer={} Domain={} H2 Client Connection got error: {:?}", peer_addr, domain, e);
            }
        });

        let send_request = send_request.ready()
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

        Ok(Self { inner: send_request, peer_addr, })
    }

    pub fn peer_addr(&self) -> std::net::SocketAddr {
        self.peer_addr
    }

    pub async fn write_request(&mut self, req: http::Request<Option<Vec<u8>>>) -> Result<H2ReadResponse, io::Error> {
        // TODO: Check Ready first ?
        let (parts, body) = req.into_parts();

        trace!("Send Request to Peer={}:", self.peer_addr);
        if log_enabled!(log::Level::Trace) {
            println!("{} {} {:?}", parts.method, parts.uri, parts.version);
            for (k, v) in parts.headers.iter() {
                println!("{}: {:?}", k, v);
            }
            println!();

            if let Some(ref body) = body {
                let hexbody = body.iter().fold(String::new(), |mut acc, n| {
                    acc.push_str(&format!("{:x}", n));
                    acc
                });
                println!("0x{}", hexbody);
            }
        }

        let req = http::Request::from_parts(parts, ());
        let has_body = match body {
            Some(ref d) => !d.is_empty(),
            None => false,
        };
        let flag = if has_body { false } else { true };
        match self.inner.send_request(req, flag) {
            Ok((response, mut send_stream)) => {
                match body {
                    Some(body) => {
                        if !body.is_empty() {
                            if let Err(e) = send_stream.send_data(bytes::Bytes::from(body), true) {
                                error!("Peer={} H2 Client write request body error: {:?}", self.peer_addr, e);
                                return Err(io::Error::new(io::ErrorKind::Other, e));
                            }
                        }
                    },
                    None => { },
                }

                Ok(H2ReadResponse {
                    inner: response,
                    peer_addr: self.peer_addr,
                })
            },
            Err(e) => {
                error!("Peer={} H2 Client write request head error: {:?}", self.peer_addr, e);
                Err(io::Error::new(io::ErrorKind::Other, e))
            }
        }
    }
}
