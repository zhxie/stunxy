//! Deal with NAT traversal using STUN.

use rand::Rng;
use socks::{Socks5Datagram, TargetAddr};
use std::io::{Error, ErrorKind, Result};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

mod codec;
use codec::{ChangeRequest, Request, Response};

/// Represents an socket which can send data to and receive data from a certain address.
pub trait RW: Send + Sync {
    /// Returns the socket address that this socket was created from.
    fn local_addr(&self) -> Result<SocketAddr>;

    /// Sends data on the socket to the given address.
    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize>;

    /// Receives a single datagram message on the socket.
    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)>;

    /// Sets the read timeout to the timeout specified.
    fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()>;

    /// Sets the write timeout to the timeout specified.
    fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()>;

    /// Returns the read timeout of this socket.
    fn read_timeout(&self) -> Result<Option<Duration>>;

    /// Returns the write timeout of this socket.
    fn write_timeout(&self) -> Result<Option<Duration>>;
}

/// Represents an UDP datagram, containing a TCP stream keeping the SOCKS proxy alive and an UDP
/// socket sending and receiving data.
#[derive(Debug)]
pub struct Datagram {
    datagram: Socks5Datagram,
}

impl Datagram {
    /// Creates a new `Datagram`.
    pub fn bind(proxy: SocketAddr, addr: SocketAddr) -> Result<Datagram> {
        let datagram = Socks5Datagram::bind(proxy, addr)?;

        Ok(Datagram { datagram })
    }
}

impl RW for Datagram {
    fn local_addr(&self) -> Result<SocketAddr> {
        let addr = self.datagram.get_ref().local_addr()?;

        Ok(addr)
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        let size = self.datagram.send_to(buf, addr)?;

        Ok(size)
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (size, addr) = self.datagram.recv_from(buf)?;

        return match addr {
            TargetAddr::Ip(addr) => Ok((size, addr)),
            _ => unreachable!(),
        };
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        self.datagram.get_ref().set_read_timeout(dur)?;

        Ok(())
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()> {
        self.datagram.get_ref().set_write_timeout(dur)?;

        Ok(())
    }

    fn read_timeout(&self) -> Result<Option<Duration>> {
        let duration = self.datagram.get_ref().read_timeout()?;

        Ok(duration)
    }

    fn write_timeout(&self) -> Result<Option<Duration>> {
        let duration = self.datagram.get_ref().write_timeout()?;

        Ok(duration)
    }
}

/// Represents an UDP socket.
#[derive(Debug)]
pub struct Socket {
    socket: UdpSocket,
}

impl Socket {
    /// Creates a new `Socket`.
    pub fn bind(addr: SocketAddr) -> Result<Socket> {
        let socket = UdpSocket::bind(addr)?;

        Ok(Socket { socket })
    }
}

impl RW for Socket {
    fn local_addr(&self) -> Result<SocketAddr> {
        let addr = self.socket.local_addr()?;

        Ok(addr)
    }

    fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize> {
        let size = self.socket.send_to(buf, addr)?;

        Ok(size)
    }

    fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let (size, addr) = self.socket.recv_from(buf)?;

        Ok((size, addr))
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> Result<()> {
        self.socket.set_read_timeout(dur)?;

        Ok(())
    }

    fn set_write_timeout(&self, dur: Option<Duration>) -> Result<()> {
        self.socket.set_write_timeout(dur)?;

        Ok(())
    }

    fn read_timeout(&self) -> Result<Option<Duration>> {
        let duration = self.socket.read_timeout()?;

        Ok(duration)
    }

    fn write_timeout(&self) -> Result<Option<Duration>> {
        let duration = self.socket.write_timeout()?;

        Ok(duration)
    }
}

/// Generates a random transaction ID with 64 bits.
pub fn generate_rand_id() -> u64 {
    let mut rng = rand::thread_rng();
    let r: u64 = rng.gen();

    r
}

/// Executes a STUN test I.
pub fn stun_test_1(rw: &Box<dyn RW>, addr: SocketAddr, id: u64) -> Result<Response> {
    // Request echo from same address, same port
    let req = Request {
        response_address: None,
        change_request: ChangeRequest::None,
        username: None,
    };

    stun_test(rw, addr, id, req)
}

/// Executes a STUN test II.
pub fn stun_test_2(rw: &Box<dyn RW>, addr: SocketAddr, id: u64) -> Result<Response> {
    // Request echo from different address, different port
    let req = Request {
        response_address: None,
        change_request: ChangeRequest::IpAndPort,
        username: None,
    };

    stun_test(rw, addr, id, req)
}

/// Executes a STUN test III.
pub fn stun_test_3(rw: &Box<dyn RW>, addr: SocketAddr, id: u64) -> Result<Response> {
    // Request echo from same address, different port
    let req = Request {
        response_address: None,
        change_request: ChangeRequest::Port,
        username: None,
    };

    stun_test(rw, addr, id, req)
}

fn stun_test(rw: &Box<dyn RW>, addr: SocketAddr, id: u64, req: Request) -> Result<Response> {
    // Encode
    let mut buffer = vec![0u8; u16::MAX as usize];
    let size = codec::encode((id, req), buffer.as_mut_slice())?;

    // Send request
    let mut recv_buffer = vec![0u8; u16::MAX as usize];
    let _ = rw.send_to(&buffer[..size], addr)?;

    // Receive
    loop {
        let (size, _) = rw.recv_from(recv_buffer.as_mut_slice())?;
        if size <= 0 {
            return Err(Error::from(ErrorKind::UnexpectedEof));
        } else {
            if let Some(outer_addr) = parse(&recv_buffer[..size], id)? {
                return Ok(outer_addr);
            }
        }
    }
}

fn parse(buffer: &[u8], id: u64) -> Result<Option<Response>> {
    // Decode
    let r = codec::decode(buffer)?;
    if let None = r {
        return Ok(None);
    }
    let (i, resp) = r.unwrap();
    if id != i {
        return Ok(None);
    }

    // Parse response
    Ok(Some(resp))
}
