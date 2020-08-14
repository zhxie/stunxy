use lib::{Datagram, Socket, RW};
use std::clone::Clone;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use structopt::StructOpt;
use stunxy as lib;

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
    pub proxy: Option<SocketAddr>,
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

    // Bind socket
    let local: SocketAddr = match server {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let rw: Box<dyn RW> = match flags.proxy {
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
