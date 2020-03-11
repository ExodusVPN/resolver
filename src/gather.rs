
use tokio::io::AsyncRead;
use tokio::io::AsyncWrite;
use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;

use std::io;
use std::pin::Pin;
use std::future::Future;
use std::task::Context;
use std::task::Poll;


type Item = Pin<Box<dyn Future<Output = Result<(), ()> > + Send >>;

#[derive(Debug)]
pub struct Gather<T: AsRef<[ Item ]>> {
    futs: T
}

impl<T: AsRef<[ Item ]>> Future for Gather<T> {
    type Output = Result<(), ()>;
    
    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        todo!()
    }
}

