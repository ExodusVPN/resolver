use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::io::{self, Read, Write};
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};
use std::mem::ManuallyDrop;


#[derive(Debug)]
pub struct UdpChannel {
    udp_socket: ManuallyDrop<mio::net::UdpSocket>,
    remote_addr: SocketAddr,
}

impl UdpChannel {
    #[inline]
    pub fn new(udp_socket: &mio::net::UdpSocket) -> Result<Self, io::Error> {
        let udp_socket = ManuallyDrop::new(udp_socket.try_clone()?);
        let remote_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));

        Ok(Self { udp_socket, remote_addr })
    }

    #[inline]
    pub fn local_addr(&self) -> Result<SocketAddr, io::Error> {
        self.udp_socket.local_addr()
    }

    #[inline]
    pub fn peer_addr(&self) -> Result<SocketAddr, io::Error> {
        Ok(self.remote_addr)
    }

    #[inline]
    pub fn set_peer_addr(&mut self, addr: SocketAddr) {
        self.remote_addr = addr;
    }

    #[inline]
    pub fn recv(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        let (amt, _) = self.recv_from(buf)?;

        Ok(amt)
    }

    #[inline]
    pub fn send(&self, buf: &[u8]) -> Result<usize, io::Error> {
        self.send_to(buf, &self.remote_addr)
    }

    #[inline]
    pub fn recv_from(&mut self, buf: &mut [u8]) -> Result<(usize, SocketAddr), io::Error> {
        let (amt, remote_addr) = self.udp_socket.recv_from(buf)?;
        self.remote_addr = remote_addr;

        Ok((amt, remote_addr))
    }

    #[inline]
    pub fn send_to(&self, buf: &[u8], remote_addr: &SocketAddr) -> Result<usize, io::Error> {
        self.udp_socket.send_to(buf, remote_addr)
    }
}

impl mio::event::Evented for UdpChannel {
    fn register(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready, opts: mio::PollOpt)
        -> io::Result<()>
    {
        self.udp_socket.register(poll, token, interest, opts)
    }

    fn reregister(&self, poll: &mio::Poll, token: mio::Token, interest: mio::Ready, opts: mio::PollOpt)
        -> io::Result<()>
    {
        self.udp_socket.reregister(poll, token, interest, opts)
    }

    fn deregister(&self, poll: &mio::Poll) -> io::Result<()> {
        self.udp_socket.deregister(poll)
    }
}

impl Write for UdpChannel {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        // NOTE: DNS over DTLS 的消息长度在 UDP 协议中传输时依然受限，
        //       在这里，可以做下长度检查，超长的消息做下符合协议规范的处理。
        // if buf.len() > 512 {
        //     return Err(io::Error::from(io::ErrorKind::WriteZero));
        // }
        self.send(buf)
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}

impl Read for UdpChannel {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, io::Error> {
        self.recv(buf)
    }
}

impl Drop for UdpChannel {
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.udp_socket);
        }
    }
}