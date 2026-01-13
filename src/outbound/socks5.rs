//! SOCKS5 proxy outbound
//!
//! Implements SOCKS5 protocol (RFC 1928) for tunneling TCP connections.

use super::{OutboundProxy, ProxyConnection, ProxyType};
use crate::common::Metadata;
use crate::dns::Resolver;
use crate::{Error, Result};
use async_trait::async_trait;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::debug;

/// Connection timeout
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// SOCKS5 version
const SOCKS5_VERSION: u8 = 0x05;

/// SOCKS5 authentication methods
const AUTH_NONE: u8 = 0x00;
const AUTH_GSSAPI: u8 = 0x01;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_NO_ACCEPTABLE: u8 = 0xFF;

/// SOCKS5 commands
const CMD_CONNECT: u8 = 0x01;
const CMD_BIND: u8 = 0x02;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// SOCKS5 address types
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

/// SOCKS5 reply codes
const REP_SUCCESS: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_TTL_EXPIRED: u8 = 0x06;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// SOCKS5 proxy outbound
pub struct Socks5Proxy {
    name: String,
    server: String,
    port: u16,
    username: Option<String>,
    password: Option<String>,
    udp: bool,
    dns_resolver: Arc<Resolver>,
}

impl Socks5Proxy {
    pub fn new(
        name: String,
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
        udp: bool,
        dns_resolver: Arc<Resolver>,
    ) -> Result<Self> {
        Ok(Socks5Proxy {
            name,
            server,
            port,
            username,
            password,
            udp,
            dns_resolver,
        })
    }

    /// Perform SOCKS5 handshake and connect
    async fn socks5_connect<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
        host: &str,
        port: u16,
    ) -> Result<()> {
        // Step 1: Send greeting with supported auth methods
        let mut greeting = vec![SOCKS5_VERSION];

        if self.username.is_some() && self.password.is_some() {
            greeting.push(2); // 2 methods
            greeting.push(AUTH_NONE);
            greeting.push(AUTH_PASSWORD);
        } else {
            greeting.push(1); // 1 method
            greeting.push(AUTH_NONE);
        }

        stream.write_all(&greeting).await.map_err(|e| {
            Error::connection(format!("Failed to send SOCKS5 greeting: {}", e))
        })?;

        // Step 2: Read server's choice
        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await.map_err(|e| {
            Error::connection(format!("Failed to read SOCKS5 response: {}", e))
        })?;

        if response[0] != SOCKS5_VERSION {
            return Err(Error::protocol("Invalid SOCKS5 version"));
        }

        let auth_method = response[1];

        // Step 3: Authenticate if needed
        match auth_method {
            AUTH_NONE => {
                debug!("[{}] No authentication required", self.name);
            }
            AUTH_PASSWORD => {
                debug!("[{}] Using password authentication", self.name);
                self.authenticate_password(stream).await?;
            }
            AUTH_NO_ACCEPTABLE => {
                return Err(Error::auth("No acceptable authentication method"));
            }
            _ => {
                return Err(Error::protocol(format!(
                    "Unsupported authentication method: {}",
                    auth_method
                )));
            }
        }

        // Step 4: Send connect request
        let mut request = vec![SOCKS5_VERSION, CMD_CONNECT, 0x00];

        // Encode address
        if let Ok(ip) = host.parse::<Ipv4Addr>() {
            request.push(ATYP_IPV4);
            request.extend_from_slice(&ip.octets());
        } else if let Ok(ip) = host.parse::<Ipv6Addr>() {
            request.push(ATYP_IPV6);
            request.extend_from_slice(&ip.octets());
        } else {
            // Domain name
            if host.len() > 255 {
                return Err(Error::connection("Domain name too long"));
            }
            request.push(ATYP_DOMAIN);
            request.push(host.len() as u8);
            request.extend_from_slice(host.as_bytes());
        }

        // Encode port (big endian)
        request.push((port >> 8) as u8);
        request.push((port & 0xFF) as u8);

        stream.write_all(&request).await.map_err(|e| {
            Error::connection(format!("Failed to send SOCKS5 connect request: {}", e))
        })?;

        // Step 5: Read connect response
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await.map_err(|e| {
            Error::connection(format!("Failed to read SOCKS5 reply: {}", e))
        })?;

        if reply[0] != SOCKS5_VERSION {
            return Err(Error::protocol("Invalid SOCKS5 version in reply"));
        }

        if reply[1] != REP_SUCCESS {
            return Err(Error::connection(Self::reply_error_message(reply[1])));
        }

        // Skip bound address
        let atyp = reply[3];
        match atyp {
            ATYP_IPV4 => {
                let mut buf = [0u8; 4 + 2]; // IPv4 + port
                stream.read_exact(&mut buf).await?;
            }
            ATYP_IPV6 => {
                let mut buf = [0u8; 16 + 2]; // IPv6 + port
                stream.read_exact(&mut buf).await?;
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut buf = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut buf).await?;
            }
            _ => {
                return Err(Error::protocol("Invalid address type in reply"));
            }
        }

        debug!("[{}] SOCKS5 connected to {}:{}", self.name, host, port);
        Ok(())
    }

    /// Perform password authentication
    async fn authenticate_password<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut S,
    ) -> Result<()> {
        let username = self.username.as_ref()
            .ok_or_else(|| Error::auth("Username required for authentication"))?;
        let password = self.password.as_ref()
            .ok_or_else(|| Error::auth("Password required for authentication"))?;

        if username.len() > 255 || password.len() > 255 {
            return Err(Error::auth("Username or password too long"));
        }

        // RFC 1929 - Username/Password Authentication
        let mut auth_request = vec![0x01]; // Version
        auth_request.push(username.len() as u8);
        auth_request.extend_from_slice(username.as_bytes());
        auth_request.push(password.len() as u8);
        auth_request.extend_from_slice(password.as_bytes());

        stream.write_all(&auth_request).await?;

        let mut response = [0u8; 2];
        stream.read_exact(&mut response).await?;

        if response[1] != 0x00 {
            return Err(Error::auth("Authentication failed"));
        }

        debug!("[{}] Password authentication successful", self.name);
        Ok(())
    }

    /// Convert reply code to error message
    fn reply_error_message(code: u8) -> String {
        match code {
            REP_GENERAL_FAILURE => "General SOCKS server failure".to_string(),
            REP_CONNECTION_NOT_ALLOWED => "Connection not allowed by ruleset".to_string(),
            REP_NETWORK_UNREACHABLE => "Network unreachable".to_string(),
            REP_HOST_UNREACHABLE => "Host unreachable".to_string(),
            REP_CONNECTION_REFUSED => "Connection refused".to_string(),
            REP_TTL_EXPIRED => "TTL expired".to_string(),
            REP_COMMAND_NOT_SUPPORTED => "Command not supported".to_string(),
            REP_ADDRESS_TYPE_NOT_SUPPORTED => "Address type not supported".to_string(),
            _ => format!("Unknown error: {}", code),
        }
    }
}

#[async_trait]
impl OutboundProxy for Socks5Proxy {
    fn name(&self) -> &str {
        &self.name
    }

    fn proxy_type(&self) -> ProxyType {
        ProxyType::Socks5
    }

    fn server(&self) -> &str {
        &self.server
    }

    fn support_udp(&self) -> bool {
        self.udp
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConnection>> {
        let target_host = if !metadata.host.is_empty() {
            metadata.host.clone()
        } else if let Some(ip) = metadata.dst_ip {
            ip.to_string()
        } else {
            return Err(Error::connection("No destination address"));
        };

        let target_port = metadata.dst_port;

        debug!(
            "[{}] SOCKS5 proxy connecting to {}:{} via {}:{}",
            self.name, target_host, target_port, self.server, self.port
        );

        // Connect to SOCKS5 server
        let server_addr = format!("{}:{}", self.server, self.port);

        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&server_addr))
            .await
            .map_err(|_| Error::timeout("SOCKS5 connection timeout"))?
            .map_err(|e| Error::connection(format!("Failed to connect to SOCKS5 server: {}", e)))?;

        // Set TCP options
        stream.set_nodelay(true).ok();

        // Perform SOCKS5 handshake
        self.socks5_connect(&mut stream, &target_host, target_port).await?;

        Ok(Box::new(stream))
    }

    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reply_error_messages() {
        assert_eq!(
            Socks5Proxy::reply_error_message(REP_CONNECTION_REFUSED),
            "Connection refused"
        );
        assert_eq!(
            Socks5Proxy::reply_error_message(REP_NETWORK_UNREACHABLE),
            "Network unreachable"
        );
    }

    #[test]
    fn test_constants() {
        assert_eq!(SOCKS5_VERSION, 0x05);
        assert_eq!(CMD_CONNECT, 0x01);
        assert_eq!(ATYP_DOMAIN, 0x03);
    }
}
