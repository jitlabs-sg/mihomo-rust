//\! Outbound adapters (proxy protocols)
//\!
//\! This module implements the hybrid architecture:
//\! - Tier 1 (Rust native): SS, VMess, Trojan, VLESS, Hysteria2, HTTP, SOCKS5
//\! - Tier 2-3 (Go fallback): Snell, TUIC, WireGuard, etc.

pub mod classifier;
mod direct;
pub mod go_fallback;
pub mod hybrid;
mod hysteria2;
mod reject;
mod shadowsocks;
mod trojan;
mod http;
mod socks5;
mod vless;
mod vmess;

pub use classifier::{
    classify_protocol, get_go_fallback_protocols, get_protocol_info, get_rust_protocols,
    is_rust_supported, requires_go_fallback, ProtocolInfo, ProtocolTier,
};
pub use direct::Direct;
pub use go_fallback::{GoFallbackManager, GoFallbackProxy, ProcessState};
pub use hybrid::{HybridProxyManager, HybridStats};
pub use hysteria2::Hysteria2;
pub use reject::Reject;
pub use shadowsocks::Shadowsocks;
pub use trojan::Trojan;
pub use http::HttpProxy;
pub use socks5::Socks5Proxy;
pub use vless::Vless;
pub use vmess::Vmess;

use crate::common::Metadata;
use crate::config::ProxyConfig;
use crate::dns::Resolver;
use crate::{Error, Result};
use async_trait::async_trait;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
/// Proxy type enum
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProxyType {
    Direct,
    Reject,
    RejectDrop,
    Shadowsocks,
    Vmess,
    Trojan,
    Hysteria2,
    Http,
    Socks5,
    Vless,
    /// Go fallback type (for UI display)
    GoFallback,
}

impl fmt::Display for ProxyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyType::Direct => write!(f, "Direct"),
            ProxyType::Reject => write!(f, "Reject"),
            ProxyType::RejectDrop => write!(f, "RejectDrop"),
            ProxyType::Shadowsocks => write!(f, "Shadowsocks"),
            ProxyType::Vmess => write!(f, "VMess"),
            ProxyType::Trojan => write!(f, "Trojan"),
            ProxyType::Hysteria2 => write!(f, "Hysteria2"),
            ProxyType::Http => write!(f, "HTTP"),
            ProxyType::Socks5 => write!(f, "SOCKS5"),
            ProxyType::Vless => write!(f, "VLESS"),
            ProxyType::GoFallback => write!(f, "GoFallback"),
        }
    }
}

impl TryFrom<&str> for ProxyType {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        match s.to_lowercase().as_str() {
            "direct" => Ok(ProxyType::Direct),
            "reject" => Ok(ProxyType::Reject),
            "reject-drop" => Ok(ProxyType::RejectDrop),
            "ss" | "shadowsocks" => Ok(ProxyType::Shadowsocks),
            "vmess" => Ok(ProxyType::Vmess),
            "trojan" => Ok(ProxyType::Trojan),
            "hysteria2" | "hy2" => Ok(ProxyType::Hysteria2),
            "http" => Ok(ProxyType::Http),
            "socks5" | "socks" => Ok(ProxyType::Socks5),
            "vless" => Ok(ProxyType::Vless),
            "snell" | "mieru" | "tuic" | "wireguard" | "ssh" | "ssr" | "hysteria" => Ok(ProxyType::GoFallback),
            _ => Err(Error::config(format!("Unknown proxy type: {}", s))),
        }
    }
}

/// Trait for outbound proxy connections
#[async_trait]
pub trait OutboundProxy: Send + Sync {
    /// Get proxy name
    fn name(&self) -> &str;

    /// Get proxy type
    fn proxy_type(&self) -> ProxyType;

    /// Get server address
    fn server(&self) -> &str;

    /// Check if UDP is supported
    fn support_udp(&self) -> bool;

    /// Dial TCP connection through this proxy
    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConnection>>;

    /// Close the proxy (cleanup resources)
    async fn close(&self) -> Result<()> {
        Ok(())
    }
}

/// Trait for proxy connections
pub trait ProxyConnection: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> ProxyConnection for T {}

/// Proxy manager holding all configured proxies
pub struct ProxyManager {
    proxies: HashMap<String, Arc<dyn OutboundProxy>>,
    dns_resolver: Arc<Resolver>,
}

impl ProxyManager {
    pub fn new(configs: &[ProxyConfig], dns_resolver: Arc<Resolver>) -> Result<Self> {
        let mut proxies: HashMap<String, Arc<dyn OutboundProxy>> = HashMap::new();

        // Always add built-in proxies
        proxies.insert("DIRECT".to_string(), Arc::new(Direct::new()));
        proxies.insert("REJECT".to_string(), Arc::new(Reject::new(false)));
        proxies.insert("REJECT-DROP".to_string(), Arc::new(Reject::new(true)));

        // Parse configured proxies
        for config in configs {
            let proxy = Self::create_proxy(config, dns_resolver.clone())?;
            proxies.insert(config.name.clone(), proxy);
        }

        Ok(ProxyManager {
            proxies,
            dns_resolver,
        })
    }

    fn create_proxy(
        config: &ProxyConfig,
        dns_resolver: Arc<Resolver>,
    ) -> Result<Arc<dyn OutboundProxy>> {
        let proxy_type = ProxyType::try_from(config.proxy_type.as_str())?;

        match proxy_type {
            ProxyType::Shadowsocks => {
                let cipher = config
                    .get_string("cipher")
                    .ok_or_else(|| Error::config("Missing cipher for Shadowsocks"))?;
                let password = config
                    .get_string("password")
                    .ok_or_else(|| Error::config("Missing password for Shadowsocks"))?;
                let udp = config.get_bool("udp").unwrap_or(false);

                Ok(Arc::new(Shadowsocks::new(
                    config.name.clone(),
                    config.server.clone(),
                    config.port,
                    cipher,
                    password,
                    udp,
                    dns_resolver,
                )?))
            }
            ProxyType::Vmess => {
                let uuid = config
                    .get_string("uuid")
                    .ok_or_else(|| Error::config("Missing uuid for VMess"))?;
                let alter_id = config.get_int("alterId").unwrap_or(0) as u16;
                let cipher = config.get_string("cipher").unwrap_or_else(|| "auto".to_string());
                let udp = config.get_bool("udp").unwrap_or(false);
                let tls = config.get_bool("tls").unwrap_or(false);
                let network = config.get_string("network").unwrap_or_else(|| "tcp".to_string());
                let server_name = config.get_string("servername");

                Ok(Arc::new(Vmess::new(
                    config.name.clone(),
                    config.server.clone(),
                    config.port,
                    uuid,
                    alter_id,
                    cipher,
                    udp,
                    tls,
                    network,
                    server_name,
                    dns_resolver,
                )?))
            }
            ProxyType::Trojan => {
                let password = config
                    .get_string("password")
                    .ok_or_else(|| Error::config("Missing password for Trojan"))?;
                let udp = config.get_bool("udp").unwrap_or(false);
                let sni = config.get_string("sni");
                let skip_cert_verify = config.get_bool("skip-cert-verify").unwrap_or(false);
                let network = config.get_string("network").unwrap_or_else(|| "tcp".to_string());

                Ok(Arc::new(Trojan::new(
                    config.name.clone(),
                    config.server.clone(),
                    config.port,
                    password,
                    udp,
                    sni,
                    skip_cert_verify,
                    network,
                    dns_resolver,
                )?))
            }
            ProxyType::Hysteria2 => {
                let password = config
                    .get_string("password")
                    .ok_or_else(|| Error::config("Missing password for Hysteria2"))?;
                let sni = config.get_string("sni");
                let skip_cert_verify = config.get_bool("skip-cert-verify").unwrap_or(false);
                let up = config.get_string("up");
                let down = config.get_string("down");
                let obfs = config.get_string("obfs");
                let obfs_password = config.get_string("obfs-password");

                Ok(Arc::new(Hysteria2::new(
                    config.name.clone(),
                    config.server.clone(),
                    config.port,
                    password,
                    sni,
                    skip_cert_verify,
                    up,
                    down,
                    obfs,
                    obfs_password,
                    dns_resolver,
                )?))
            }
            ProxyType::Http => {
                let username = config.get_string("username");
                let password = config.get_string("password");
                let tls = config.get_bool("tls").unwrap_or(false);
                let skip_cert_verify = config.get_bool("skip-cert-verify").unwrap_or(false);

                Ok(Arc::new(HttpProxy::new(
                    config.name.clone(),
                    config.server.clone(),
                    config.port,
                    username,
                    password,
                    tls,
                    skip_cert_verify,
                    dns_resolver,
                )?))
            }
            ProxyType::Socks5 => {
                let username = config.get_string("username");
                let password = config.get_string("password");
                let udp = config.get_bool("udp").unwrap_or(false);

                Ok(Arc::new(Socks5Proxy::new(
                    config.name.clone(),
                    config.server.clone(),
                    config.port,
                    username,
                    password,
                    udp,
                    dns_resolver,
                )?))
            }
            ProxyType::Vless => {
                let uuid = config
                    .get_string("uuid")
                    .ok_or_else(|| Error::config("Missing uuid for VLESS"))?;
                let flow = config.get_string("flow");
                let encryption = config.get_string("encryption");
                let udp = config.get_bool("udp").unwrap_or(false);
                let tls = config.get_bool("tls").unwrap_or(true);
                let skip_cert_verify = config.get_bool("skip-cert-verify").unwrap_or(false);
                let server_name = config.get_string("servername");
                let network = config.get_string("network").unwrap_or_else(|| "tcp".to_string());

                Ok(Arc::new(Vless::new(
                    config.name.clone(),
                    config.server.clone(),
                    config.port,
                    uuid,
                    flow,
                    encryption,
                    udp,
                    tls,
                    skip_cert_verify,
                    server_name,
                    network,
                    dns_resolver,
                )?))
            }
            ProxyType::Direct => Ok(Arc::new(Direct::new())),
            ProxyType::Reject => Ok(Arc::new(Reject::new(false))),
            ProxyType::RejectDrop => Ok(Arc::new(Reject::new(true))),
            ProxyType::GoFallback => Err(Error::unsupported(
                "GoFallback proxies must use HybridProxyManager",
            )),
        }
    }

    /// Get proxy by name
    pub fn get(&self, name: &str) -> Option<&Arc<dyn OutboundProxy>> {
        self.proxies.get(name)
    }

    /// Get all proxy names
    pub fn names(&self) -> Vec<&String> {
        self.proxies.keys().collect()
    }

    /// Get number of proxies
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Iterate over proxies
    pub fn iter(&self) -> impl Iterator<Item = (&String, &Arc<dyn OutboundProxy>)> {
        self.proxies.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_type_parsing() {
        assert_eq!(ProxyType::try_from("ss").unwrap(), ProxyType::Shadowsocks);
        assert_eq!(
            ProxyType::try_from("shadowsocks").unwrap(),
            ProxyType::Shadowsocks
        );
        assert_eq!(ProxyType::try_from("vmess").unwrap(), ProxyType::Vmess);
        assert_eq!(ProxyType::try_from("trojan").unwrap(), ProxyType::Trojan);
        assert_eq!(
            ProxyType::try_from("hysteria2").unwrap(),
            ProxyType::Hysteria2
        );
        assert!(ProxyType::try_from("unknown").is_err());
    }
}
