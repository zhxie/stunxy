// Transplant from `stun3489` by `Manuel Schölling <manuel.schoelling@gmx.de>`.
// https://crates.io/crates/stun3489

#![allow(dead_code)]

use byteorder::{NetworkEndian, ReadBytesExt, WriteBytesExt};
use bytes::{BufMut, BytesMut};
use std::io::{Cursor, Error, ErrorKind, Read, Result, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;
const BINDING_ERROR: u16 = 0x0111;
const SHARED_SECRET_REQUEST: u16 = 0x0002;
const SHARED_SECRET_RESPONSE: u16 = 0x0102;
const SHARED_SECRET_ERROR: u16 = 0x0112;

const MAPPED_ADDRESS: u16 = 0x0001;
const RESPONSE_ADDRESS: u16 = 0x0002;
const CHANGE_REQUEST: u16 = 0x0003;
const SOURCE_ADDRESS: u16 = 0x0004;
const CHANGED_ADDRESS: u16 = 0x0005;
const USERNAME: u16 = 0x0006;
const PASSWORD: u16 = 0x0007;
const MESSAGE_INTEGRITY: u16 = 0x0008;
const ERROR_CODE: u16 = 0x0009;
const UNKNOWN_ATTRIBUTES: u16 = 0x000a;
const REFLECTED_FROM: u16 = 0x000b;

const CHANGE_REQUEST_IP: u32 = 0x2;
const CHANGE_REQUEST_PORT: u32 = 0x4;
const CHANGE_REQUEST_IP_AND_PORT: u32 = 0x6;

/// Enumeration of the `CHANGE-REQUEST` STUN attribute.
#[derive(Debug, Clone, PartialEq)]
pub enum ChangeRequest {
    None,
    Ip,
    Port,
    IpAndPort,
}

/// Represents a STUN request.
#[derive(Debug, Clone)]
pub struct Request {
    pub response_address: Option<SocketAddr>,
    pub change_request: ChangeRequest,
    pub username: Option<Vec<u8>>,
}

impl Request {
    fn encode(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        if let Some(a) = self.response_address {
            Attribute::ResponseAddress(a).encode(&mut buf)?;
        }

        if self.change_request != ChangeRequest::None {
            let r = self.change_request.clone();
            Attribute::ChangeRequest(r).encode(&mut buf)?;
        }

        if let Some(ref u) = self.username {
            Attribute::Username(u.clone()).encode(&mut buf)?;
        }

        Ok(buf)
    }
}

/// Represents a response of a STUN request.
#[derive(Debug)]
pub struct Response {
    pub mapped_address: SocketAddr,
    pub source_address: SocketAddr,
    pub changed_address: SocketAddr,
    pub reflected_from: Option<SocketAddr>,
}

/// Enumeration of the STUN attributes.
pub enum Attribute {
    MappedAddress(SocketAddr),
    ResponseAddress(SocketAddr),
    ChangedAddress(SocketAddr),
    SourceAddress(SocketAddr),
    ReflectedFrom(SocketAddr),
    ChangeRequest(ChangeRequest),
    MessageIntegrity([u8; 20]),
    Username(Vec<u8>),
    UnknownOptional,
}

impl Attribute {
    fn read(mut c: &mut Cursor<&[u8]>) -> Result<Attribute> {
        let typ = c.read_u16::<NetworkEndian>()?;
        let len = c.read_u16::<NetworkEndian>()?;

        match typ {
            MAPPED_ADDRESS => Ok(Attribute::MappedAddress(Self::read_address(&mut c)?)),
            RESPONSE_ADDRESS => Ok(Attribute::ResponseAddress(Self::read_address(&mut c)?)),
            CHANGED_ADDRESS => Ok(Attribute::ChangedAddress(Self::read_address(&mut c)?)),
            SOURCE_ADDRESS => Ok(Attribute::SourceAddress(Self::read_address(&mut c)?)),
            REFLECTED_FROM => Ok(Attribute::ReflectedFrom(Self::read_address(&mut c)?)),
            MESSAGE_INTEGRITY => {
                let mut hash = [0; 20];
                c.read_exact(&mut hash)?;
                Ok(Attribute::MessageIntegrity(hash))
            }
            CHANGE_REQUEST => match c.read_u32::<NetworkEndian>()? {
                CHANGE_REQUEST_IP => Ok(Attribute::ChangeRequest(ChangeRequest::Ip)),
                CHANGE_REQUEST_PORT => Ok(Attribute::ChangeRequest(ChangeRequest::Port)),
                CHANGE_REQUEST_IP_AND_PORT => {
                    Ok(Attribute::ChangeRequest(ChangeRequest::IpAndPort))
                }
                _ => Err(Error::new(
                    ErrorKind::InvalidData,
                    "CHANGE_REQUEST not understood",
                )),
            },
            _ if typ <= 0x7fff => Err(Error::new(
                ErrorKind::InvalidData,
                "Unknown mandatory field",
            )),
            _ => {
                c.seek(SeekFrom::Current(i64::from(len)))?;
                Ok(Attribute::UnknownOptional)
            }
        }
    }

    fn read_address(c: &mut Cursor<&[u8]>) -> Result<SocketAddr> {
        let _ = c.read_u8()?;
        let typ = c.read_u8()?;
        let port = c.read_u16::<NetworkEndian>()?;
        let addr = c.read_u32::<NetworkEndian>()?;

        if typ != 0x01 {
            return Err(Error::new(ErrorKind::InvalidData, "Invalid address family"));
        }

        let b0 = ((addr & 0xff00_0000) >> 24) as u8;
        let b1 = ((addr & 0x00ff_0000) >> 16) as u8;
        let b2 = ((addr & 0x0000_ff00) >> 8) as u8;
        let b3 = (addr & 0x0000_00ff) as u8;
        let ip = IpAddr::V4(Ipv4Addr::new(b0, b1, b2, b3));

        Ok(SocketAddr::new(ip, port))
    }

    fn encode(&self, buf: &mut Vec<u8>) -> Result<()> {
        let (typ, opaque) = match *self {
            Attribute::MappedAddress(ref s) => (MAPPED_ADDRESS, Self::encode_address(s)?),
            Attribute::ResponseAddress(ref s) => (RESPONSE_ADDRESS, Self::encode_address(s)?),
            Attribute::ChangedAddress(ref s) => (CHANGED_ADDRESS, Self::encode_address(s)?),
            Attribute::SourceAddress(ref s) => (SOURCE_ADDRESS, Self::encode_address(s)?),
            Attribute::ReflectedFrom(ref s) => (REFLECTED_FROM, Self::encode_address(s)?),
            Attribute::MessageIntegrity(ref h) => (MESSAGE_INTEGRITY, h.to_vec()),
            Attribute::Username(ref u) => {
                let total_len = (4.0 * (u.len() as f64 / 4.0).ceil()) as usize;
                let padding_len = total_len - u.len();

                let mut buf = Vec::with_capacity(total_len);
                buf.write_all(&u[..])?;
                for _ in 0..padding_len {
                    buf.write_u8(0x00)?;
                }
                assert_eq!(buf.len(), total_len);

                (USERNAME, buf.clone())
            }
            Attribute::ChangeRequest(ref c) => (CHANGE_REQUEST, Self::encode_change_request(c)?),
            Attribute::UnknownOptional => unreachable!(),
        };

        buf.write_u16::<NetworkEndian>(typ)?;
        buf.write_u16::<NetworkEndian>(opaque.len() as u16)?;
        buf.write_all(&opaque[..])?;

        Ok(())
    }

    fn encode_change_request(c: &ChangeRequest) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(4);

        match *c {
            ChangeRequest::None => (),
            ChangeRequest::Ip => buf.write_u32::<NetworkEndian>(CHANGE_REQUEST_IP)?,
            ChangeRequest::Port => buf.write_u32::<NetworkEndian>(CHANGE_REQUEST_PORT)?,
            ChangeRequest::IpAndPort => {
                buf.write_u32::<NetworkEndian>(CHANGE_REQUEST_IP_AND_PORT)?
            }
        };

        Ok(buf)
    }

    fn encode_address(addr: &SocketAddr) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(8);
        buf.write_u8(0x00)?;
        buf.write_u8(0x01)?;

        if let SocketAddr::V4(ref addr) = *addr {
            buf.write_u16::<NetworkEndian>(addr.port())?;
            buf.write_all(&addr.ip().octets()[..])?;

            Ok(buf)
        } else {
            Err(Error::new(
                ErrorKind::InvalidInput,
                "STUN does not support IPv6",
            ))
        }
    }
}

/// Encodes STUN request into bytes array.
pub fn encode(msg: (u64, Request), buf: &mut [u8]) -> Result<usize> {
    let (trans_id, req) = msg;

    let typ = BINDING_REQUEST;
    let m = req.encode()?;

    let mut b = BytesMut::new();

    b.put_u16(typ);
    b.put_u16(m.len() as u16);
    b.put_u64(0);
    b.put_u64(trans_id);
    b.put_slice(&m);

    let b = b.freeze();
    if b.len() > buf.len() {
        return Err(Error::new(ErrorKind::WriteZero, "buffer too small"));
    }

    &buf[..b.len()].copy_from_slice(&b[..]);

    Ok(b.len())
}

/// Decodes STUN response from bytes array.
pub fn decode(msg: &[u8]) -> Result<Option<(u64, Response)>> {
    let mut c = Cursor::new(msg);

    let msg_type = c.read_u16::<NetworkEndian>()?;
    let _msg_len = c.read_u16::<NetworkEndian>()?;
    let trans_id1 = c.read_u64::<NetworkEndian>()?;
    let trans_id2 = c.read_u64::<NetworkEndian>()?;

    if trans_id1 != 0 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Invalid transaction ID!",
        ));
    }

    let res = match msg_type {
        BINDING_RESPONSE => read_binding_response(msg, &mut c),
        BINDING_ERROR => Err(Error::new(
            ErrorKind::InvalidData,
            "BINDING_ERROR unimplemented",
        )),
        SHARED_SECRET_RESPONSE => Err(Error::new(
            ErrorKind::InvalidData,
            "SHARED_SECRET_RESPONSE unimplemented",
        )),
        SHARED_SECRET_ERROR => Err(Error::new(
            ErrorKind::InvalidData,
            "SHARED_SECRET_ERROR unimplemented",
        )),
        _ => return Err(Error::new(ErrorKind::InvalidData, "Unknown message type!")),
    };

    res.map(|v| Some((trans_id2, v)))
}

fn read_binding_response(_msg: &[u8], c: &mut Cursor<&[u8]>) -> Result<Response> {
    let mut mapped_address = None;
    let mut source_address = None;
    let mut changed_address = None;
    let mut message_integrity = None;
    let mut reflected_from = None;

    let error = |reason| Error::new(ErrorKind::InvalidData, reason);

    loop {
        let attr = Attribute::read(c);
        match attr {
            Ok(Attribute::MappedAddress(s)) => {
                mapped_address.get_or_insert(s);
            }
            Ok(Attribute::SourceAddress(s)) => {
                source_address.get_or_insert(s);
            }
            Ok(Attribute::ChangedAddress(s)) => {
                changed_address.get_or_insert(s);
            }
            Ok(Attribute::ReflectedFrom(s)) => {
                reflected_from.get_or_insert(s);
            }
            Ok(Attribute::MessageIntegrity(s)) => {
                message_integrity.get_or_insert(s);
            }
            Ok(Attribute::UnknownOptional) => continue,
            Err(ref e) if e.kind() == ErrorKind::UnexpectedEof => break,
            _ => return Err(error("Unknown mandatory attribute!")),
        };
    }

    Ok(Response {
        mapped_address: mapped_address.ok_or_else(|| error("MappedAddress missing!"))?,
        source_address: source_address.ok_or_else(|| error("SourceAddress missing!"))?,
        changed_address: changed_address.ok_or_else(|| error("ChangedAddress missing!"))?,
        reflected_from,
    })
}
