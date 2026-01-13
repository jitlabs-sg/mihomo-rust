//! Configuration module

mod parser;
pub mod splitter;

pub use parser::*;
pub use splitter::{
    generate_go_fallback_config, split_proxies, GoFallbackConfig, SplitConfig, SplitStats,
    DEFAULT_GO_FALLBACK_PORT,
};

use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use tokio::fs;

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Inbound listeners configuration
    pub inbound: InboundConfig,

    /// DNS configuration
    pub dns: DnsConfig,

    /// Proxy definitions
    #[serde(default)]
    pub proxies: Vec<ProxyConfig>,

    /// Proxy groups
    #[serde(default, rename = "proxy-groups")]
    pub proxy_groups: Vec<ProxyGroupConfig>,

    /// Rules
    #[serde(default)]
    pub rules: Vec<String>,

    /// Log level
    #[serde(default = "default_log_level", rename = "log-level")]
    pub log_level: Option<String>,

    /// Mode (rule, global, direct)
    #[serde(default = "default_mode")]
    pub mode: Option<String>,

    /// External controller address
    #[serde(rename = "external-controller")]
    pub external_controller: Option<String>,

    /// External controller secret
    pub secret: Option<String>,

    /// Allow LAN access
    #[serde(rename = "allow-lan")]
    pub allow_lan: Option<bool>,

    /// IPv6
    pub ipv6: Option<bool>,

    /// Bind address
    #[serde(rename = "bind-address")]
    pub bind_address: Option<String>,

    /// GeoIP database path
    #[serde(rename = "geoip-database")]
    pub geoip_database: Option<String>,

    /// GeoSite database path
    #[serde(rename = "geosite-database")]
    pub geosite_database: Option<String>,

    /// External controller via Named Pipe (Windows)
    #[serde(rename = "external-controller-pipe")]
    pub external_controller_pipe: Option<String>,

    /// External controller via Unix Socket
    #[serde(rename = "external-controller-unix")]
    pub external_controller_unix: Option<String>,
}

impl Config {
    /// Load configuration from file (synchronous)
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from file (async)
    pub async fn load_async<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(path).await?;
        let config: Config = serde_yaml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    /// Load from string
    pub fn from_str(content: &str) -> Result<Self> {
        let config: Config = serde_yaml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        // Validate at least one inbound is configured
        if self.inbound.http.is_none()
            && self.inbound.socks.is_none()
            && self.inbound.mixed.is_none()
        {
            // Warning but not error - allow running without inbounds
        }

        // Validate proxy configurations
        for proxy in &self.proxies {
            proxy.validate()?;
        }

        Ok(())
    }

    /// Save configuration to file
    pub async fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = serde_yaml::to_string(self)?;
        fs::write(path, content).await?;
        Ok(())
    }
}

impl Default for Config {
    fn default() -> Self {
        Config {
            inbound: InboundConfig::default(),
            dns: DnsConfig::default(),
            proxies: Vec::new(),
            proxy_groups: Vec::new(),
            rules: Vec::new(),
            log_level: Some("info".to_string()),
            mode: Some("rule".to_string()),
            external_controller: None,
            secret: None,
            allow_lan: None,
            ipv6: None,
            bind_address: None,
            geoip_database: None,
            geosite_database: None,
            external_controller_pipe: None,
            external_controller_unix: None,
        }
    }
}

/// Inbound configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct InboundConfig {
    /// HTTP proxy configuration
    pub http: Option<HttpInboundConfig>,

    /// SOCKS5 proxy configuration
    pub socks: Option<SocksInboundConfig>,

    /// Mixed port configuration
    pub mixed: Option<MixedInboundConfig>,

    /// TUN configuration
    pub tun: Option<TunConfig>,
}

/// HTTP inbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInboundConfig {
    /// Listen address
    pub listen: String,

    /// Authentication
    pub auth: Option<AuthConfig>,
}

impl HttpInboundConfig {
    /// Get port from listen address
    pub fn port(&self) -> u16 {
        self.listen.split(':').last().and_then(|p| p.parse().ok()).unwrap_or(7890)
    }
}

/// SOCKS5 inbound configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocksInboundConfig {
    /// Listen address
    pub listen: String,

    /// Enable UDP
    #[serde(default = "default_true")]
    pub udp: bool,

    /// Authentication
    pub auth: Option<AuthConfig>,
}

impl SocksInboundConfig {
    /// Get port from listen address
    pub fn port(&self) -> u16 {
        self.listen.split(':').last().and_then(|p| p.parse().ok()).unwrap_or(7891)
    }
}

/// Mixed port configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixedInboundConfig {
    /// Listen address
    pub listen: String,

    /// Enable UDP for SOCKS5
    #[serde(default = "default_true")]
    pub udp: bool,

    /// Authentication
    pub auth: Option<AuthConfig>,
}

impl MixedInboundConfig {
    /// Get port from listen address
    pub fn port(&self) -> u16 {
        self.listen.split(':').last().and_then(|p| p.parse().ok()).unwrap_or(7890)
    }
}

/// TUN configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    /// Enable TUN
    pub enable: bool,

    /// TUN device name
    pub device: Option<String>,

    /// Stack type (system, gvisor, mixed)
    pub stack: Option<String>,

    /// DNS hijack
    #[serde(rename = "dns-hijack")]
    pub dns_hijack: Option<Vec<String>>,

    /// Auto route
    #[serde(rename = "auto-route", default = "default_true")]
    pub auto_route: bool,

    /// Auto detect interface
    #[serde(rename = "auto-detect-interface", default = "default_true")]
    pub auto_detect_interface: bool,
}

fn default_true() -> bool {
    true
}

fn default_log_level() -> Option<String> {
    Some("info".to_string())
}

fn default_mode() -> Option<String> {
    Some("rule".to_string())
}

/// Authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// Username
    pub username: String,

    /// Password
    pub password: String,
}

/// DNS configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DnsConfig {
    /// Enable DNS
    #[serde(default = "default_true")]
    pub enable: bool,

    /// Listen address
    pub listen: Option<String>,

    /// Enhanced mode (fake-ip, redir-host)
    #[serde(rename = "enhanced-mode")]
    pub enhanced_mode: Option<String>,

    /// Fake IP range
    #[serde(rename = "fake-ip-range")]
    pub fake_ip_range: Option<String>,

    /// Fake IP filter
    #[serde(rename = "fake-ip-filter", default)]
    pub fake_ip_filter: Vec<String>,

    /// Default nameservers
    #[serde(default)]
    pub nameserver: Vec<String>,

    /// Fallback nameservers
    #[serde(default)]
    pub fallback: Vec<String>,

    /// Fallback filter
    #[serde(rename = "fallback-filter")]
    pub fallback_filter: Option<FallbackFilterConfig>,

    /// Nameserver policy
    #[serde(rename = "nameserver-policy", default)]
    pub nameserver_policy: HashMap<String, Vec<String>>,

    /// IPv6
    #[serde(default)]
    pub ipv6: bool,

    /// Use hosts
    #[serde(rename = "use-hosts", default = "default_true")]
    pub use_hosts: bool,

    /// Hosts
    #[serde(default)]
    pub hosts: HashMap<String, String>,

    /// Cache size
    #[serde(rename = "cache-size", default = "default_cache_size")]
    pub cache_size: usize,
}

fn default_cache_size() -> usize {
    4096
}

/// Fallback filter configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FallbackFilterConfig {
    /// GeoIP
    #[serde(default = "default_true")]
    pub geoip: bool,

    /// GeoIP code
    #[serde(rename = "geoip-code", default = "default_geoip_code")]
    pub geoip_code: String,

    /// IP CIDR
    #[serde(rename = "ipcidr", default)]
    pub ipcidr: Vec<String>,

    /// Domain
    #[serde(default)]
    pub domain: Vec<String>,
}

fn default_geoip_code() -> String {
    "CN".to_string()
}

/// Proxy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyConfig {
    /// Proxy name
    pub name: String,

    /// Proxy type
    #[serde(rename = "type")]
    pub proxy_type: String,

    /// Server address
    pub server: String,

    /// Server port
    pub port: u16,

    /// All other fields
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

impl ProxyConfig {
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(Error::config("Proxy name cannot be empty"));
        }
        if self.server.is_empty() {
            return Err(Error::config("Proxy server cannot be empty"));
        }
        if self.port == 0 {
            return Err(Error::config("Proxy port cannot be 0"));
        }
        Ok(())
    }

    /// Get string field
    pub fn get_string(&self, key: &str) -> Option<String> {
        self.extra.get(key).and_then(|v| v.as_str()).map(String::from)
    }

    /// Get bool field
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.extra.get(key).and_then(|v| v.as_bool())
    }

    /// Get integer field
    pub fn get_int(&self, key: &str) -> Option<i64> {
        self.extra.get(key).and_then(|v| v.as_i64())
    }

    /// Get string list field
    pub fn get_string_list(&self, key: &str) -> Vec<String> {
        self.extra
            .get(key)
            .and_then(|v| v.as_sequence())
            .map(|seq| {
                seq.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Proxy group configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyGroupConfig {
    /// Group name
    pub name: String,

    /// Group type (select, url-test, fallback, load-balance)
    #[serde(rename = "type")]
    pub group_type: String,

    /// Proxies in group
    #[serde(default)]
    pub proxies: Vec<String>,

    /// Use provider
    #[serde(default)]
    pub use_provider: Vec<String>,

    /// URL for testing
    pub url: Option<String>,

    /// Test interval
    pub interval: Option<u64>,

    /// Tolerance
    pub tolerance: Option<u64>,

    /// Lazy
    #[serde(default)]
    pub lazy: bool,

    /// All other fields
    #[serde(flatten)]
    pub extra: HashMap<String, serde_yaml::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.log_level, Some("info".to_string()));
        assert_eq!(config.mode, Some("rule".to_string()));
    }

    #[test]
    fn test_config_from_yaml() {
        let yaml = r#"
log-level: debug
mode: rule
inbound:
  http:
    listen: "127.0.0.1:7890"
  socks:
    listen: "127.0.0.1:7891"
    udp: true
dns:
  enable: true
  nameserver:
    - 8.8.8.8
    - 8.8.4.4
proxies:
  - name: test-ss
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret
rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - MATCH,DIRECT
"#;
        let config = Config::from_str(yaml).unwrap();
        assert_eq!(config.log_level, Some("debug".to_string()));
        assert!(config.inbound.http.is_some());
        assert_eq!(config.proxies.len(), 1);
        assert_eq!(config.rules.len(), 2);
    }
}
