
use crate::tls::TlsIdentity;
use crate::tls::TlsListener;
use crate::tls::TlsStream;

use h2;
use bytes;
use http;
use tokio_tls;

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::future::Future;

pub use http::Response;

pub type H2Connection = h2::server::Connection<TlsStream, bytes::Bytes>;
pub type Request = http::Request<h2::RecvStream>;
pub type Respond = h2::server::SendResponse<bytes::Bytes>;


const URI_PATH: &str = "/dns-query";
const CONTENT_TYPE: &str = "application/dns-message";


#[derive(Debug)]
pub struct HttpsListener {
    listener: TlsListener,
}

type FN<S> = fn(S, Request, Respond) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, std::io::Error> > + Send >>;

impl HttpsListener {
    pub fn new(listener: TlsListener) -> Self {
        Self { listener }
    }

    pub async fn accept(&mut self) -> Result<(H2Connection, SocketAddr), io::Error> {
        loop {
            let (tls_stream, peer_addr) = self.listener.accept().await?;

            match h2::server::handshake(tls_stream).await {
                Ok(h2_stream) => {
                    return Ok((h2_stream, peer_addr));
                },
                Err(e) => {
                    trace!("H2 Handshake Error({}): {:?}", peer_addr, e);
                }
            }
        }
    }
    
    pub async fn on_request<S: 'static + Send + Sync + Clone + ?Sized>(&mut self, state: S, f: FN<S> ) {
        let (mut h2_conn, peer_addr) = self.accept().await.unwrap();
        loop {
            match h2_conn.accept().await {
                Some(h2_channel) => {
                    match h2_channel {
                        Ok((request, respond)) => {
                            tokio::spawn(h2_request_handle(state.clone(), request, respond));
                        },
                        Err(e) => {
                            trace!("H2 accept stream Error({}): {:?}", peer_addr, e);
                        }
                    }
                },
                None => {
                    break;
                }
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

const GET: http::Method  = http::Method::GET;
const POST: http::Method = http::Method::POST;

pub async fn h2_request_handle<S: Send>(state: S, mut req: Request, mut res: Respond) {
    let method = req.method();
    let uri = req.uri();
    let headers = req.headers();
    let content_type = headers.get(http::header::CONTENT_TYPE);
    let accept = headers.get(http::header::ACCEPT);

    match (content_type, accept) {
        (Some(content_type), Some(accept)) => {
            if content_type != CONTENT_TYPE {

            }
            
            if accept != CONTENT_TYPE {

            }
        },
        _ => {
            // Error ?
        }
    }

    if uri.path() != URI_PATH {

    }

    let recv_stream = req.body_mut();
    let recv_stream_id = recv_stream.stream_id();

    let mut req_body: Vec<u8> = Vec::new();
    loop {
        match recv_stream.data().await {
            Some(Ok(data)) => {
                req_body.extend_from_slice(data.as_ref());
            },
            Some(Err(e)) => {
                trace!("H2 RecvStream({:?}) read data error: {:?}", recv_stream.stream_id(), e);
                return ();
            },
            None => {
                break;
            }
        }
    }

    let response = http::Response::builder()
        .status(http::StatusCode::OK)
        .header("Accept", CONTENT_TYPE)
        .header("Content-Type", CONTENT_TYPE)
        .version(http::Version::HTTP_2)
        .body(())
        .unwrap();

    let dns_res_pkt: Vec<u8> = vec![1u8, 2, 3, 4];
    match res.send_response(response, false) {
        Ok(mut sender) => {
            if let Err(e) = sender.send_data(bytes::Bytes::from(dns_res_pkt), true) {
                trace!("H2 SendStream({:?}) send_data Error: {:?}", sender.stream_id(), e);
            }
        },
        Err(e) => {
            trace!("H2 SendResponse({:?}) send_response Error: {:?}", res.stream_id(), e);
        },
    }
}

