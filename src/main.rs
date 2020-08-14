use lib::{Datagram, Socket, RW};
use std::clone::Clone;
use std::fmt::Display;
use std::io::{self, ErrorKind};
use std::net::{AddrParseError, IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::time::Duration;
use structopt::StructOpt;
use stunxy as lib;

#[derive(Debug)]
enum ResolvableAddrParseError {
    AddrParseError(AddrParseError),
    ResolveError(io::Error),
}

impl Display for ResolvableAddrParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolvableAddrParseError::AddrParseError(e) => write!(f, "{}", e),
            ResolvableAddrParseError::ResolveError(e) => write!(f, "{}", e),
        }
    }
}

impl From<AddrParseError> for ResolvableAddrParseError {
    fn from(s: AddrParseError) -> Self {
        ResolvableAddrParseError::AddrParseError(s)
    }
}

impl From<io::Error> for ResolvableAddrParseError {
    fn from(s: io::Error) -> Self {
        ResolvableAddrParseError::ResolveError(s)
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct ResolvableSocketAddr {
    addr_v4: Option<SocketAddrV4>,
    addr_v6: Option<SocketAddrV6>,
    alias: Option<String>,
}

impl ResolvableSocketAddr {
    fn addr_v4(&self) -> Option<SocketAddrV4> {
        self.addr_v4
    }

    fn addr_v6(&self) -> Option<SocketAddrV6> {
        self.addr_v6
    }
}

impl Display for ResolvableSocketAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.addr_v4.is_some() && self.addr_v6.is_some() {
            write!(f, "{}/{}", self.addr_v4.unwrap(), self.addr_v6.unwrap())?;
        } else if self.addr_v4.is_some() {
            write!(f, "{}", self.addr_v4.unwrap())?;
        } else if self.addr_v6.is_some() {
            write!(f, "{}", self.addr_v6.unwrap())?;
        } else {
            unreachable!()
        }
        match &self.alias {
            Some(alias) => write!(f, " ({})", alias),
            None => Ok(()),
        }
    }
}

impl FromStr for ResolvableSocketAddr {
    type Err = ResolvableAddrParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let has_alias;
        let (addr_v4, addr_v6) = match s.parse() {
            Ok(addr) => {
                has_alias = false;

                match addr {
                    SocketAddr::V4(addr_v4) => (Some(addr_v4), None),
                    SocketAddr::V6(addr_v6) => (None, Some(addr_v6)),
                }
            }
            Err(e) => {
                has_alias = true;

                let v = s.split(":").collect::<Vec<_>>();
                if v.len() != 2 {
                    return Err(ResolvableAddrParseError::from(e));
                }

                let port = match v[1].parse() {
                    Ok(port) => port,
                    Err(_) => return Err(ResolvableAddrParseError::from(e)),
                };

                let mut ip_v4 = None;
                let mut ip_v6 = None;
                match dns_lookup::lookup_host(v[0]) {
                    Ok(addrs) => {
                        for addr in addrs {
                            match addr {
                                IpAddr::V4(addr_v4) => {
                                    if ip_v4.is_none() {
                                        ip_v4 = Some(addr_v4);
                                    }
                                }
                                IpAddr::V6(addr_v6) => {
                                    if ip_v6.is_none() {
                                        ip_v6 = Some(addr_v6);
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => return Err(ResolvableAddrParseError::from(e)),
                };

                if ip_v4.is_none() && ip_v6.is_none() {
                    return Err(ResolvableAddrParseError::from(e));
                }

                let addr_v4 = match ip_v4 {
                    Some(ip_v4) => Some(SocketAddrV4::new(ip_v4, port)),
                    None => None,
                };
                let addr_v6 = match ip_v6 {
                    Some(ip_v6) => Some(SocketAddrV6::new(ip_v6, port, 0, 0)),
                    None => None,
                };

                (addr_v4, addr_v6)
            }
        };

        let alias = match has_alias {
            true => Some(String::from_str(s).unwrap()),
            false => None,
        };
        Ok(ResolvableSocketAddr {
            addr_v4,
            addr_v6,
            alias,
        })
    }
}

#[derive(StructOpt, Clone, Debug, Eq, Hash, PartialEq)]
#[structopt(about)]
struct Flags {
    #[structopt(name = "HOST", help = "Server", default_value = "stun.ekiga.net")]
    pub server: String,
    #[structopt(
        long,
        short,
        help = "Port",
        value_name = "VALUE",
        default_value = "3478",
        display_order(0)
    )]
    pub port: u16,
    #[structopt(
        long = "socks-proxy",
        short = "s",
        help = "SOCKS proxy",
        value_name = "ADDRESS",
        display_order(1)
    )]
    pub proxy: Option<ResolvableSocketAddr>,
    #[structopt(
        long,
        help = "Username",
        value_name = "VALUE",
        requires("password"),
        display_order(2)
    )]
    pub username: Option<String>,
    #[structopt(
        long,
        help = "Password",
        value_name = "VALUE",
        requires("username"),
        display_order(2)
    )]
    pub password: Option<String>,
    #[structopt(
        long,
        short = "w",
        help = "Timeout to wait for each response",
        value_name = "VALUE",
        default_value = "3000",
        display_order(4)
    )]
    pub timeout: u64,
}

fn main() {
    // Parse arguments
    let flags = Flags::from_args();

    let resolve;
    let server = match flags.server.parse() {
        Ok(addr) => {
            resolve = false;

            addr
        }
        Err(_) => match dns_lookup::lookup_host(flags.server.as_str()) {
            Ok(addrs) => {
                if addrs.is_empty() {
                    eprintln!("Cannot resolve the hostname");
                    return;
                }

                resolve = true;

                addrs[0]
            }
            Err(ref e) => {
                eprintln!("{}", e);
                return;
            }
        },
    };
    let proxy = match flags.proxy {
        Some(proxy) => match server {
            IpAddr::V4(_) => match proxy.addr_v4() {
                Some(addr_v4) => Some(SocketAddr::V4(addr_v4)),
                None => {
                    eprintln!(
                        "The IP protocol numbers of the server {} and the proxy {} do not match",
                        server, proxy
                    );
                    return;
                }
            },
            IpAddr::V6(_) => match proxy.addr_v6() {
                Some(addr_v6) => Some(SocketAddr::V6(addr_v6)),
                None => {
                    eprintln!(
                        "The IP protocol numbers of the server {} and the proxy {} do not match",
                        server, proxy
                    );
                    return;
                }
            },
        },
        None => None,
    };

    // Bind socket
    let local: SocketAddr = match server {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let rw: Box<dyn RW> = match proxy {
        Some(proxy) => {
            let auth = match flags.username {
                Some(username) => Some((username, flags.password.unwrap())),
                None => None,
            };
            match Datagram::bind(proxy, local, auth) {
                Ok(datagram) => Box::new(datagram),
                Err(ref e) => {
                    eprintln!("{}", e);
                    return;
                }
            }
        }
        None => match Socket::bind(local) {
            Ok(socket) => Box::new(socket),
            Err(ref e) => {
                eprintln!("{}", e);
                return;
            }
        },
    };
    if flags.timeout != 0 {
        if let Err(ref e) = rw.set_read_timeout(Some(Duration::from_millis(flags.timeout))) {
            eprintln!("{}", e);
            return;
        }
    }

    if resolve {
        println!("STUN {} ({})", flags.server, server);
    } else {
        println!("STUN {}", server);
    }

    // STUN test I
    let server_addr = SocketAddr::new(server, flags.port);
    let local_addr = rw.local_addr().unwrap();
    match lib::stun_test_1(&rw, server_addr) {
        Ok(resp1) => {
            if resp1.mapped_address == local_addr {
                // No NAT, check for firewall
                // STUN test II
                match lib::stun_test_2(&rw, server_addr) {
                    Ok(_) => {
                        println!("Local Address : {}", local_addr);
                        println!("Remote Address: {}", resp1.mapped_address);
                        println!("NAT Type      : Open Internet");
                    }
                    Err(ref e) => match e.kind() {
                        ErrorKind::TimedOut => {
                            println!("Local Address : {}", local_addr);
                            println!("Remote Address: {}", resp1.mapped_address);
                            println!("NAT Type      : Symmetric Firewall");
                        }
                        _ => eprintln!("{}", e),
                    },
                }
            } else {
                // NAT detected
                // STUN test II
                match lib::stun_test_2(&rw, server_addr) {
                    Ok(_) => {
                        println!("Local Address : {}", local_addr);
                        println!("Remote Address: {}", resp1.mapped_address);
                        println!("NAT Type      : Full-cone NAT");
                    }
                    Err(ref e) => match e.kind() {
                        ErrorKind::TimedOut => {
                            // STUN test I
                            match lib::stun_test_1(&rw, resp1.changed_address) {
                                Ok(resp2) => {
                                    if resp1.mapped_address != resp2.mapped_address {
                                        println!("Local Address : {}", local_addr);
                                        println!("Remote Address: {}", resp1.mapped_address);
                                        println!("NAT Type      : Symmetric NAT");
                                    } else {
                                        // STUN test III
                                        match lib::stun_test_3(&rw, resp1.changed_address) {
                                            Ok(_) => {
                                                println!("Local Address : {}", local_addr);
                                                println!(
                                                    "Remote Address: {}",
                                                    resp1.mapped_address
                                                );
                                                println!("NAT Type      : Restricted cone NAT");
                                            }
                                            Err(ref e) => match e.kind() {
                                                ErrorKind::TimedOut => {
                                                    println!("Local Address : {}", local_addr);
                                                    println!(
                                                        "Remote Address: {}",
                                                        resp1.mapped_address
                                                    );
                                                    println!("NAT Type      : Restricted port NAT");
                                                }
                                                _ => eprintln!("{}", e),
                                            },
                                        }
                                    }
                                }
                                Err(ref e) => match e.kind() {
                                    ErrorKind::TimedOut => {
                                        println!("Local Address : {}", local_addr);
                                        println!("Remote Address: {}", resp1.mapped_address);
                                        println!("NAT Type      : Symmetric NAT");
                                    }
                                    _ => eprintln!("{}", e),
                                },
                            }
                        }
                        _ => eprintln!("{}", e),
                    },
                }
            }
        }
        Err(ref e) => {
            // UDP blocked
            match e.kind() {
                ErrorKind::TimedOut => {
                    println!("Local Address: {}", local_addr);
                    println!("NAT Type     : UDP blocked");
                }
                _ => eprintln!("{}", e),
            }
        }
    }
}
