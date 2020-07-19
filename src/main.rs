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
    #[structopt(name = "ADDRESS", help = "Server")]
    pub server: IpAddr,
    #[structopt(
        long,
        short,
        help = "Port",
        value_name = "VALUE",
        default_value = "3478"
    )]
    pub port: u16,
    #[structopt(
        long = "socks-proxy",
        short = "s",
        help = "SOCKS proxy",
        value_name = "ADDRESS"
    )]
    pub proxy: Option<SocketAddr>,
    #[structopt(
        long,
        short = "w",
        help = "Timeout to wait for each response",
        value_name = "VALUE",
        default_value = "1000"
    )]
    pub timeout: u64,
}

fn main() {
    // Parse arguments
    let flags = Flags::from_args();

    // Bind socket
    let local: SocketAddr = match flags.server {
        IpAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
        IpAddr::V6(_) => "[::]:0".parse().unwrap(),
    };
    let rw: Box<dyn RW> = match flags.proxy {
        Some(proxy) => match Datagram::bind(proxy, local) {
            Ok(datagram) => Box::new(datagram),
            Err(ref e) => {
                eprintln!("{}", e);
                return;
            }
        },
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

    // STUN test I
    let id = lib::generate_rand_id();
    let server_addr = SocketAddr::new(flags.server, flags.port);
    let local_addr = rw.local_addr().unwrap();
    match lib::stun_test_1(&rw, server_addr, id) {
        Ok(resp1) => {
            if resp1.mapped_address == local_addr {
                // No NAT, check for firewall
                // STUN test II
                match lib::stun_test_2(&rw, server_addr, id) {
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
                match lib::stun_test_2(&rw, server_addr, id) {
                    Ok(_) => {
                        println!("Local Address : {}", local_addr);
                        println!("Remote Address: {}", resp1.mapped_address);
                        println!("NAT Type      : Full-cone NAT");
                    }
                    Err(ref e) => match e.kind() {
                        ErrorKind::TimedOut => {
                            // STUN test I
                            match lib::stun_test_3(&rw, resp1.changed_address, id) {
                                Ok(resp2) => {
                                    if resp1.mapped_address.ip() != resp2.mapped_address.ip() {
                                        println!("Local Address : {}", local_addr);
                                        println!("Remote Address: {}", resp1.mapped_address);
                                        println!("NAT Type      : Symmetric NAT");
                                    } else {
                                        // STUN test III
                                        match lib::stun_test_3(&rw, resp1.changed_address, id) {
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
