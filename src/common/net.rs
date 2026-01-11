//! Network utilities

use crate::{Error, Result};
use socket2::SockRef;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::buffer;

#[inline]
pub fn configure_tcp_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    let sock = SockRef::from(stream);
    let _ = sock.set_keepalive(true);
    let _ = sock.set_reuse_address(true);
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let _ = sock.set_reuse_port(true);
}

/// SOCKS5 address type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// IPv4 address
    Ipv4(Ipv4Addr),
    /// IPv6 address
    Ipv6(Ipv6Addr),
    /// Domain name
    Domain(String),
}

impl Address {
    /// Parse from SOCKS5 format
    pub async fn read_from<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(Self, u16)> {
        let mut atyp = [0u8; 1];
        reader.read_exact(&mut atyp).await?;

        match atyp[0] {
            0x01 => {
                let mut buf = [0u8; 6];
                reader.read_exact(&mut buf).await?;
                let addr = Address::Ipv4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
                let port = u16::from_be_bytes([buf[4], buf[5]]);
                Ok((addr, port))
            }
            0x03 => {
                let mut len = [0u8; 1];
                reader.read_exact(&mut len).await?;
                let len = len[0] as usize;
                let mut buf = vec![0u8; len + 2];
                reader.read_exact(&mut buf).await?;
                let domain = String::from_utf8(buf[..len].to_vec())
                    .map_err(|e| Error::parse(format!("Invalid domain: {}", e)))?;
                let port = u16::from_be_bytes([buf[len], buf[len + 1]]);
                Ok((Address::Domain(domain), port))
            }
            0x04 => {
                let mut buf = [0u8; 18];
                reader.read_exact(&mut buf).await?;
                let mut ip = [0u8; 16];
                ip.copy_from_slice(&buf[..16]);
                let addr = Address::Ipv6(Ipv6Addr::from(ip));
                let port = u16::from_be_bytes([buf[16], buf[17]]);
                Ok((addr, port))
            }
            t => Err(Error::protocol(format!("Unknown address type: {}", t))),
        }
    }

    /// Write in SOCKS5 format
    pub async fn write_to<W: AsyncWrite + Unpin>(&self, writer: &mut W, port: u16) -> Result<()> {
        let mut buf = Vec::with_capacity(self.len());
        match self {
            Address::Ipv4(ip) => {
                buf.push(0x01);
                buf.extend_from_slice(&ip.octets());
            }
            Address::Ipv6(ip) => {
                buf.push(0x04);
                buf.extend_from_slice(&ip.octets());
            }
            Address::Domain(domain) => {
                let bytes = domain.as_bytes();
                if bytes.len() > 255 {
                    return Err(Error::address("Domain name too long"));
                }
                buf.push(0x03);
                buf.push(bytes.len() as u8);
                buf.extend_from_slice(bytes);
            }
        }
        buf.extend_from_slice(&port.to_be_bytes());
        writer.write_all(&buf).await?;
        Ok(())
    }

    /// Get bytes length
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        match self {
            Address::Ipv4(_) => 1 + 4 + 2,             // atyp + ip + port
            Address::Ipv6(_) => 1 + 16 + 2,            // atyp + ip + port
            Address::Domain(d) => 1 + 1 + d.len() + 2, // atyp + len + domain + port
        }
    }

    /// Convert to string representation
    pub fn to_string_with_port(&self, port: u16) -> String {
        match self {
            Address::Ipv4(ip) => format!("{}:{}", ip, port),
            Address::Ipv6(ip) => format!("[{}]:{}", ip, port),
            Address::Domain(d) => format!("{}:{}", d, port),
        }
    }

    /// Get as IP if resolved
    pub fn to_ip(&self) -> Option<IpAddr> {
        match self {
            Address::Ipv4(ip) => Some(IpAddr::V4(*ip)),
            Address::Ipv6(ip) => Some(IpAddr::V6(*ip)),
            Address::Domain(_) => None,
        }
    }

    /// Get as domain string
    pub fn to_host(&self) -> String {
        match self {
            Address::Ipv4(ip) => ip.to_string(),
            Address::Ipv6(ip) => ip.to_string(),
            Address::Domain(d) => d.clone(),
        }
    }
}

impl From<Ipv4Addr> for Address {
    fn from(ip: Ipv4Addr) -> Self {
        Address::Ipv4(ip)
    }
}

impl From<Ipv6Addr> for Address {
    fn from(ip: Ipv6Addr) -> Self {
        Address::Ipv6(ip)
    }
}

impl From<IpAddr> for Address {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(v4) => Address::Ipv4(v4),
            IpAddr::V6(v6) => Address::Ipv6(v6),
        }
    }
}

impl From<String> for Address {
    fn from(domain: String) -> Self {
        // Try to parse as IP first
        if let Ok(ip) = domain.parse::<Ipv4Addr>() {
            return Address::Ipv4(ip);
        }
        if let Ok(ip) = domain.parse::<Ipv6Addr>() {
            return Address::Ipv6(ip);
        }
        Address::Domain(domain)
    }
}

/// Copy data between two streams bidirectionally
pub async fn copy_bidirectional<A, B>(a: &mut A, b: &mut B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    buffer::greedy_copy_bidirectional(a, b).await
}

/// Copy data between two streams bidirectionally (owned).
pub async fn copy_bidirectional_owned<A, B>(a: A, b: B) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut a = a;
    let mut b = b;
    buffer::greedy_copy_bidirectional(&mut a, &mut b).await
}

/// Read a single byte
pub async fn read_u8<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u8> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf).await?;
    Ok(buf[0])
}

/// Read 2 bytes as u16 big-endian
pub async fn read_u16_be<R: AsyncRead + Unpin>(reader: &mut R) -> Result<u16> {
    let mut buf = [0u8; 2];
    reader.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}

/// Write u16 as 2 bytes big-endian
pub async fn write_u16_be<W: AsyncWrite + Unpin>(writer: &mut W, val: u16) -> Result<()> {
    writer.write_all(&val.to_be_bytes()).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_from_ip() {
        let addr = Address::from(Ipv4Addr::new(127, 0, 0, 1));
        assert!(matches!(addr, Address::Ipv4(_)));
    }

    #[test]
    fn test_address_from_domain() {
        let addr = Address::from("example.com".to_string());
        assert!(matches!(addr, Address::Domain(_)));
    }

    #[test]
    fn test_address_len() {
        let ipv4 = Address::Ipv4(Ipv4Addr::new(127, 0, 0, 1));
        assert_eq!(ipv4.len(), 7);

        let domain = Address::Domain("example.com".to_string());
        assert_eq!(domain.len(), 1 + 1 + 11 + 2);
    }
}
