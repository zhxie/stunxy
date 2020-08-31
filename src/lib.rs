//! Deal with NAT traversal using STUN.

use rand::Rng;
use socks::{Socks5Datagram, TargetAddr};
use std::fmt::{self, Display};
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
    pub fn bind(
        proxy: SocketAddr,
        addr: SocketAddr,
        auth: Option<(String, String)>,
    ) -> Result<Datagram> {
        let datagram = match auth {
            Some((username, password)) => Socks5Datagram::bind_with_password(
                proxy,
                addr,
                username.as_str(),
                password.as_str(),
            )?,
            None => Socks5Datagram::bind(proxy, addr)?,
        };

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
fn generate_rand_id() -> u64 {
    let mut rng = rand::thread_rng();
    let r: u64 = rng.gen();

    r
}

/// Executes a STUN test I.
pub fn stun_test_1(rw: &Box<dyn RW>, addr: SocketAddr) -> Result<Response> {
    // Request echo from same address, same port
    let req = Request {
        response_address: None,
        change_request: ChangeRequest::None,
        username: None,
    };

    stun_test(rw, addr, generate_rand_id(), req)
}

/// Executes a STUN test II.
pub fn stun_test_2(rw: &Box<dyn RW>, addr: SocketAddr) -> Result<Response> {
    // Request echo from different address, different port
    let req = Request {
        response_address: None,
        change_request: ChangeRequest::IpAndPort,
        username: None,
    };

    stun_test(rw, addr, generate_rand_id(), req)
}

/// Executes a STUN test III.
pub fn stun_test_3(rw: &Box<dyn RW>, addr: SocketAddr) -> Result<Response> {
    // Request echo from same address, different port
    let req = Request {
        response_address: None,
        change_request: ChangeRequest::Port,
        username: None,
    };

    stun_test(rw, addr, generate_rand_id(), req)
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

#[derive(Clone, Copy, Debug)]
/// Enumeration of NAT types.
pub enum NatType {
    /// Represents the open Internet.
    OpenInternet,
    /// Represents the full-cone NAT.
    FullConeNat,
    /// Represents the restricted cone NAT.
    RestrictedConeNat,
    /// Represents the port restricted cone NAT.
    PortRestrictedConeNat,
    /// Represents the symmetric NAT.
    SymmetricNat,
    /// Represents the symmetric firewall.
    SymmetricFirewall,
    /// Represents the UDP blocked.
    UdpBlocked,
}

impl Display for NatType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NatType::OpenInternet => write!(f, "Open Internet"),
            NatType::FullConeNat => write!(f, "Full-Cone NAT"),
            NatType::RestrictedConeNat => write!(f, "Restricted cone NAT"),
            NatType::PortRestrictedConeNat => write!(f, "Port restricted cone NAT"),
            NatType::SymmetricNat => write!(f, "Symmetric NAT"),
            NatType::SymmetricFirewall => write!(f, "Symmetric firewall"),
            NatType::UdpBlocked => write!(f, "UDP blocked"),
        }
    }
}

/// Represents the result of a NAT test.
pub struct NatTestResult {
    local_addr: SocketAddr,
    remote_addr: Option<SocketAddr>,
    nat_type: NatType,
}

impl NatTestResult {
    /// Returns the local address of the NAT test result.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Returns the remote address of the NAT test result.
    pub fn remote_addr(&self) -> Option<SocketAddr> {
        self.remote_addr
    }

    /// Returns the NAT type of the NAT test result.
    pub fn nat_type(&self) -> NatType {
        self.nat_type
    }
}

impl Display for NatTestResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Local Address: {}", self.local_addr)?;
        if let Some(addr) = self.remote_addr {
            write!(f, "Remote Address: {}", addr)?;
        }
        write!(f, "NAT Type: {}", self.nat_type)
    }
}

/// Executes a NAT test.
pub fn nat_test(rw: &Box<dyn RW>, server_addr: SocketAddr) -> Result<NatTestResult> {
    let local_addr = match rw.local_addr() {
        Ok(addr) => addr,
        Err(e) => return Err(Error::new(ErrorKind::NotConnected, e)),
    };

    // STUN test I
    let result = match stun_test_1(&rw, server_addr) {
        Ok(resp1) => {
            if resp1.mapped_address == local_addr {
                // No NAT, check for firewall
                // STUN test II
                match stun_test_2(&rw, server_addr) {
                    Ok(_) => NatTestResult {
                        local_addr,
                        remote_addr: Some(resp1.mapped_address),
                        nat_type: NatType::OpenInternet,
                    },
                    Err(e) => match e.kind() {
                        ErrorKind::TimedOut => NatTestResult {
                            local_addr,
                            remote_addr: Some(resp1.mapped_address),
                            nat_type: NatType::SymmetricFirewall,
                        },
                        _ => return Err(e),
                    },
                }
            } else {
                // NAT detected
                // STUN test II
                match stun_test_2(&rw, server_addr) {
                    Ok(_) => NatTestResult {
                        local_addr,
                        remote_addr: Some(resp1.mapped_address),
                        nat_type: NatType::FullConeNat,
                    },
                    Err(e) => match e.kind() {
                        ErrorKind::TimedOut => {
                            // STUN test I
                            match stun_test_1(&rw, resp1.changed_address) {
                                Ok(resp2) => {
                                    if resp1.mapped_address != resp2.mapped_address {
                                        NatTestResult {
                                            local_addr,
                                            remote_addr: Some(resp1.mapped_address),
                                            nat_type: NatType::SymmetricNat,
                                        }
                                    } else {
                                        // STUN test III
                                        match stun_test_3(&rw, resp1.changed_address) {
                                            Ok(_) => NatTestResult {
                                                local_addr,
                                                remote_addr: Some(resp1.mapped_address),
                                                nat_type: NatType::RestrictedConeNat,
                                            },
                                            Err(e) => match e.kind() {
                                                ErrorKind::TimedOut => NatTestResult {
                                                    local_addr,
                                                    remote_addr: Some(resp1.mapped_address),
                                                    nat_type: NatType::PortRestrictedConeNat,
                                                },
                                                _ => return Err(e),
                                            },
                                        }
                                    }
                                }
                                Err(e) => match e.kind() {
                                    ErrorKind::TimedOut => NatTestResult {
                                        local_addr,
                                        remote_addr: Some(resp1.mapped_address),
                                        nat_type: NatType::SymmetricNat,
                                    },
                                    _ => return Err(e),
                                },
                            }
                        }
                        _ => return Err(e),
                    },
                }
            }
        }
        Err(e) => {
            // UDP blocked
            match e.kind() {
                ErrorKind::TimedOut => NatTestResult {
                    local_addr,
                    remote_addr: None,
                    nat_type: NatType::UdpBlocked,
                },
                _ => return Err(e),
            }
        }
    };

    Ok(result)
}
