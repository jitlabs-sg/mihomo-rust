//! Connection metadata

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Network type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Network {
    Tcp,
    Udp,
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Tcp => write!(f, "TCP"),
            Network::Udp => write!(f, "UDP"),
        }
    }
}

/// Connection type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConnType {
    Http,
    Https,
    Socks5,
    Mixed,
    Tun,
    Inner,
}

impl fmt::Display for ConnType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnType::Http => write!(f, "HTTP"),
            ConnType::Https => write!(f, "HTTPS"),
            ConnType::Socks5 => write!(f, "SOCKS5"),
            ConnType::Mixed => write!(f, "Mixed"),
            ConnType::Tun => write!(f, "TUN"),
            ConnType::Inner => write!(f, "Inner"),
        }
    }
}

/// DNS mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum DnsMode {
    #[default]
    Normal,
    FakeIP,
    Mapping,
    Hosts,
}

/// Connection metadata containing all routing information
#[derive(Debug, Clone)]
pub struct Metadata {
    /// Network type (TCP/UDP)
    pub network: Network,

    /// Connection type
    pub conn_type: ConnType,

    /// Source IP address
    pub src_ip: IpAddr,

    /// Source port
    pub src_port: u16,

    /// Destination IP address (may be unset if only host is known)
    pub dst_ip: Option<IpAddr>,

    /// Destination port
    pub dst_port: u16,

    /// Destination host (domain name)
    pub host: String,

    /// Process name (if available)
    pub process: Option<String>,

    /// Process path (if available)
    pub process_path: Option<String>,

    /// User ID (if available)
    pub uid: Option<u32>,

    /// DNS mode
    pub dns_mode: DnsMode,

    /// Special proxy to use (bypasses rules)
    pub special_proxy: Option<String>,

    /// Special rules to use
    pub special_rules: Option<String>,
}

impl Metadata {
    /// Create new metadata
    pub fn new(network: Network, conn_type: ConnType) -> Self {
        Metadata {
            network,
            conn_type,
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_ip: None,
            dst_port: 0,
            host: String::new(),
            process: None,
            process_path: None,
            uid: None,
            dns_mode: DnsMode::Normal,
            special_proxy: None,
            special_rules: None,
        }
    }

    /// Create TCP metadata
    pub fn tcp() -> Self {
        Self::new(Network::Tcp, ConnType::Mixed)
    }

    /// Create UDP metadata
    pub fn udp() -> Self {
        Self::new(Network::Udp, ConnType::Mixed)
    }

    /// Set source address
    pub fn with_source(mut self, addr: SocketAddr) -> Self {
        self.src_ip = addr.ip();
        self.src_port = addr.port();
        self
    }

    /// Set destination IP
    pub fn with_dst_ip(mut self, ip: IpAddr) -> Self {
        self.dst_ip = Some(ip);
        self
    }

    /// Set destination port
    pub fn with_dst_port(mut self, port: u16) -> Self {
        self.dst_port = port;
        self
    }

    /// Set destination host
    pub fn with_host(mut self, host: String) -> Self {
        self.host = host;
        self
    }

    /// Check if destination is resolved
    pub fn resolved(&self) -> bool {
        self.dst_ip.is_some()
    }

    /// Get remote address string (for dialing)
    pub fn remote_address(&self) -> String {
        if !self.host.is_empty() {
            format!("{}:{}", self.host, self.dst_port)
        } else if let Some(ip) = self.dst_ip {
            format!("{}:{}", ip, self.dst_port)
        } else {
            format!("0.0.0.0:{}", self.dst_port)
        }
    }

    /// Get destination address string (host or IP)
    pub fn destination(&self) -> String {
        if !self.host.is_empty() {
            self.host.clone()
        } else if let Some(ip) = self.dst_ip {
            ip.to_string()
        } else {
            String::new()
        }
    }

    /// Get source detail string
    pub fn source_detail(&self) -> String {
        let mut detail = format!("{}:{}", self.src_ip, self.src_port);
        if let Some(ref process) = self.process {
            detail.push_str(&format!(" ({})", process));
        }
        detail
    }

    /// Check if metadata is valid
    pub fn valid(&self) -> bool {
        self.dst_port > 0 && (!self.host.is_empty() || self.dst_ip.is_some())
    }

    /// Get a pure copy for dialing (without process info)
    pub fn pure(&self) -> Self {
        Metadata {
            network: self.network,
            conn_type: self.conn_type,
            src_ip: self.src_ip,
            src_port: self.src_port,
            dst_ip: self.dst_ip,
            dst_port: self.dst_port,
            host: self.host.clone(),
            process: None,
            process_path: None,
            uid: None,
            dns_mode: self.dns_mode,
            special_proxy: None,
            special_rules: None,
        }
    }
}

impl fmt::Display for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[{}] {} --> {}",
            self.network,
            self.source_detail(),
            self.remote_address()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn test_metadata_creation() {
        let meta = Metadata::tcp()
            .with_source(SocketAddr::V4(SocketAddrV4::new(
                Ipv4Addr::new(192, 168, 1, 1),
                12345,
            )))
            .with_host("example.com".to_string())
            .with_dst_port(443);

        assert_eq!(meta.network, Network::Tcp);
        assert_eq!(meta.host, "example.com");
        assert_eq!(meta.dst_port, 443);
        assert_eq!(meta.remote_address(), "example.com:443");
    }

    #[test]
    fn test_metadata_validation() {
        let meta = Metadata::tcp().with_dst_port(443).with_host("example.com".to_string());
        assert!(meta.valid());

        let meta_invalid = Metadata::tcp();
        assert!(!meta_invalid.valid());
    }
}
