//! SOCKS5 protocol implementation

use super::net::Address;
use crate::{Error, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// SOCKS5 version
pub const SOCKS5_VERSION: u8 = 0x05;

// SOCKS5 authentication methods
pub const AUTH_NO_AUTH: u8 = 0x00;
pub const AUTH_GSSAPI: u8 = 0x01;
pub const AUTH_USERNAME_PASSWORD: u8 = 0x02;
pub const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

// SOCKS5 commands
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_BIND: u8 = 0x02;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;

// SOCKS5 address types
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

// SOCKS5 reply codes
pub const REP_SUCCEEDED: u8 = 0x00;
pub const REP_GENERAL_FAILURE: u8 = 0x01;
pub const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
pub const REP_NETWORK_UNREACHABLE: u8 = 0x03;
pub const REP_HOST_UNREACHABLE: u8 = 0x04;
pub const REP_CONNECTION_REFUSED: u8 = 0x05;
pub const REP_TTL_EXPIRED: u8 = 0x06;
pub const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
pub const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 command
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Connect,
    Bind,
    UdpAssociate,
}

impl TryFrom<u8> for Command {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            CMD_CONNECT => Ok(Command::Connect),
            CMD_BIND => Ok(Command::Bind),
            CMD_UDP_ASSOCIATE => Ok(Command::UdpAssociate),
            _ => Err(Error::protocol(format!(
                "Unknown SOCKS5 command: {}",
                value
            ))),
        }
    }
}

impl From<Command> for u8 {
    fn from(cmd: Command) -> u8 {
        match cmd {
            Command::Connect => CMD_CONNECT,
            Command::Bind => CMD_BIND,
            Command::UdpAssociate => CMD_UDP_ASSOCIATE,
        }
    }
}

/// SOCKS5 authentication request
#[derive(Debug)]
pub struct AuthRequest {
    pub methods: Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct AuthMethodFlags {
    pub no_auth: bool,
    pub username_password: bool,
}

impl AuthMethodFlags {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut head = [0u8; 2];
        reader.read_exact(&mut head).await?;

        if head[0] != SOCKS5_VERSION {
            return Err(Error::protocol(format!(
                "Unsupported SOCKS version: {}",
                head[0]
            )));
        }

        let n = head[1] as usize;
        let mut methods = [0u8; 255];
        reader.read_exact(&mut methods[..n]).await?;

        let mut flags = Self {
            no_auth: false,
            username_password: false,
        };
        for &m in &methods[..n] {
            match m {
                AUTH_NO_AUTH => flags.no_auth = true,
                AUTH_USERNAME_PASSWORD => flags.username_password = true,
                _ => {}
            }
        }
        Ok(flags)
    }
}

impl AuthRequest {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut head = [0u8; 2];
        reader.read_exact(&mut head).await?;

        if head[0] != SOCKS5_VERSION {
            return Err(Error::protocol(format!(
                "Unsupported SOCKS version: {}",
                head[0]
            )));
        }

        let mut methods = vec![0u8; head[1] as usize];
        reader.read_exact(&mut methods).await?;

        Ok(AuthRequest { methods })
    }

    pub fn supports(&self, method: u8) -> bool {
        self.methods.contains(&method)
    }
}

/// SOCKS5 authentication response
pub struct AuthResponse {
    pub method: u8,
}

impl AuthResponse {
    pub fn new(method: u8) -> Self {
        AuthResponse { method }
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&[SOCKS5_VERSION, self.method]).await?;
        Ok(())
    }
}

/// SOCKS5 request
#[derive(Debug)]
pub struct Request {
    pub command: Command,
    pub address: Address,
    pub port: u16,
}

impl Request {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut header = [0u8; 4];
        reader.read_exact(&mut header).await?;

        if header[0] != SOCKS5_VERSION {
            return Err(Error::protocol(format!(
                "Unsupported SOCKS version: {}",
                header[0]
            )));
        }

        let command = Command::try_from(header[1])?;

        // Reserved byte (header[2]) is ignored
        let (address, port) = read_address_and_port(reader, header[3]).await?;

        Ok(Request {
            command,
            address,
            port,
        })
    }
}

async fn read_address_and_port<R: AsyncRead + Unpin>(
    reader: &mut R,
    atyp: u8,
) -> Result<(Address, u16)> {
    match atyp {
        ATYP_IPV4 => {
            let mut buf = [0u8; 6];
            reader.read_exact(&mut buf).await?;
            let addr = Address::Ipv4(std::net::Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
            let port = u16::from_be_bytes([buf[4], buf[5]]);
            Ok((addr, port))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            let len = len[0] as usize;
            let mut buf = vec![0u8; len + 2];
            reader.read_exact(&mut buf).await?;
            let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
            buf.truncate(len);
            let domain = String::from_utf8(buf)
                .map_err(|e| Error::parse(format!("Invalid domain: {}", e)))?;
            Ok((Address::Domain(domain), port))
        }
        ATYP_IPV6 => {
            let mut buf = [0u8; 18];
            reader.read_exact(&mut buf).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&buf[..16]);
            let addr = Address::Ipv6(std::net::Ipv6Addr::from(ip));
            let port = u16::from_be_bytes([buf[16], buf[17]]);
            Ok((addr, port))
        }
        t => Err(Error::protocol(format!("Unknown address type: {}", t))),
    }
}

/// SOCKS5 response
pub struct Response {
    pub reply: u8,
    pub address: Address,
    pub port: u16,
}

impl Response {
    pub fn success(address: Address, port: u16) -> Self {
        Response {
            reply: REP_SUCCEEDED,
            address,
            port,
        }
    }

    pub fn failure(reply: u8) -> Self {
        Response {
            reply,
            address: Address::Ipv4(std::net::Ipv4Addr::UNSPECIFIED),
            port: 0,
        }
    }

    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W) -> Result<()> {
        match &self.address {
            Address::Ipv4(ip) => {
                let mut buf = [0u8; 10];
                buf[0] = SOCKS5_VERSION;
                buf[1] = self.reply;
                buf[2] = 0x00;
                buf[3] = ATYP_IPV4;
                buf[4..8].copy_from_slice(&ip.octets());
                buf[8..10].copy_from_slice(&self.port.to_be_bytes());
                writer.write_all(&buf).await?;
                return Ok(());
            }
            Address::Ipv6(ip) => {
                let mut buf = [0u8; 22];
                buf[0] = SOCKS5_VERSION;
                buf[1] = self.reply;
                buf[2] = 0x00;
                buf[3] = ATYP_IPV6;
                buf[4..20].copy_from_slice(&ip.octets());
                buf[20..22].copy_from_slice(&self.port.to_be_bytes());
                writer.write_all(&buf).await?;
                return Ok(());
            }
            Address::Domain(domain) => {
                let mut buf = Vec::with_capacity(5 + domain.len() + 2);
                buf.extend_from_slice(&[SOCKS5_VERSION, self.reply, 0x00, ATYP_DOMAIN]);
                let bytes = domain.as_bytes();
                if bytes.len() > 255 {
                    return Err(Error::address("Domain name too long"));
                }
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
                buf.extend_from_slice(&self.port.to_be_bytes());
                writer.write_all(&buf).await?;
                return Ok(());
            }
        }
    }
}

/// Username/Password authentication
pub struct UsernamePasswordAuth {
    pub username: String,
    pub password: String,
}

impl UsernamePasswordAuth {
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Self> {
        let mut version = [0u8; 1];
        reader.read_exact(&mut version).await?;

        if version[0] != 0x01 {
            return Err(Error::protocol("Unsupported auth version"));
        }

        let mut ulen = [0u8; 1];
        reader.read_exact(&mut ulen).await?;
        let mut username = vec![0u8; ulen[0] as usize];
        reader.read_exact(&mut username).await?;

        let mut plen = [0u8; 1];
        reader.read_exact(&mut plen).await?;
        let mut password = vec![0u8; plen[0] as usize];
        reader.read_exact(&mut password).await?;

        Ok(UsernamePasswordAuth {
            username: String::from_utf8_lossy(&username).to_string(),
            password: String::from_utf8_lossy(&password).to_string(),
        })
    }

    pub async fn write_response<W: AsyncWrite + Unpin>(
        writer: &mut W,
        success: bool,
    ) -> Result<()> {
        let status = if success { 0x00 } else { 0x01 };
        writer.write_all(&[0x01, status]).await?;
        Ok(())
    }
}

/// UDP relay header
#[derive(Debug)]
pub struct UdpHeader {
    pub frag: u8,
    pub address: Address,
    pub port: u16,
}

impl UdpHeader {
    /// Parse UDP header from bytes
    pub fn from_bytes(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 10 {
            return Err(Error::protocol("UDP header too short"));
        }

        // Reserved (2 bytes) + frag (1 byte)
        let frag = data[2];

        let atyp = data[3];
        let (address, addr_len) = match atyp {
            ATYP_IPV4 => {
                if data.len() < 10 {
                    return Err(Error::protocol("UDP header too short for IPv4"));
                }
                let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
                (Address::Ipv4(ip), 4)
            }
            ATYP_DOMAIN => {
                let len = data[4] as usize;
                if data.len() < 7 + len {
                    return Err(Error::protocol("UDP header too short for domain"));
                }
                let domain = String::from_utf8_lossy(&data[5..5 + len]).to_string();
                (Address::Domain(domain), 1 + len)
            }
            ATYP_IPV6 => {
                if data.len() < 22 {
                    return Err(Error::protocol("UDP header too short for IPv6"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[4..20]);
                let ip = std::net::Ipv6Addr::from(octets);
                (Address::Ipv6(ip), 16)
            }
            _ => return Err(Error::protocol(format!("Unknown address type: {}", atyp))),
        };

        let port_offset = 4 + addr_len;
        if data.len() < port_offset + 2 {
            return Err(Error::protocol("UDP header missing port"));
        }
        let port = u16::from_be_bytes([data[port_offset], data[port_offset + 1]]);

        let header_len = port_offset + 2;
        Ok((
            UdpHeader {
                frag,
                address,
                port,
            },
            header_len,
        ))
    }

    /// Convert to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.address.len() + 4);
        buf.extend_from_slice(&[0x00, 0x00, self.frag]); // RSV + FRAG

        match &self.address {
            Address::Ipv4(ip) => {
                buf.push(ATYP_IPV4);
                buf.extend_from_slice(&ip.octets());
            }
            Address::Ipv6(ip) => {
                buf.push(ATYP_IPV6);
                buf.extend_from_slice(&ip.octets());
            }
            Address::Domain(domain) => {
                let bytes = domain.as_bytes();
                buf.push(ATYP_DOMAIN);
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
            }
        }

        buf.extend_from_slice(&self.port.to_be_bytes());
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_conversion() {
        assert_eq!(Command::try_from(0x01).unwrap(), Command::Connect);
        assert_eq!(u8::from(Command::Connect), 0x01);
    }

    #[test]
    fn test_udp_header() {
        let header = UdpHeader {
            frag: 0,
            address: Address::Ipv4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            port: 8080,
        };

        let bytes = header.to_bytes();
        let (parsed, _len) = UdpHeader::from_bytes(&bytes).unwrap();

        assert_eq!(parsed.frag, 0);
        assert_eq!(parsed.port, 8080);
        assert!(matches!(parsed.address, Address::Ipv4(_)));
    }
}
