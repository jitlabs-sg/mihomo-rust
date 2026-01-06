//! Configuration splitter for hybrid Rust/Go architecture
//!
//! This module splits the main config into:
//! - Rust-handled proxies (native implementation)
//! - Go-handled proxies (fallback to mihomo)

use crate::config::{Config, ProxyConfig, ProxyGroupConfig};
use crate::outbound::classifier::{classify_protocol, ProtocolTier};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use tokio::fs;
use tracing::{debug, info};

/// Split configuration result
#[derive(Debug)]
pub struct SplitConfig {
    /// Proxies to be handled by Rust
    pub rust_proxies: Vec<ProxyConfig>,
    /// Proxies to be handled by Go
    pub go_proxies: Vec<ProxyConfig>,
    /// Names of Go-handled proxies (for quick lookup)
    pub go_proxy_names: HashSet<String>,
}

impl SplitConfig {
    /// Check if a proxy name should use Go fallback
    pub fn is_go_fallback(&self, name: &str) -> bool {
        self.go_proxy_names.contains(name)
    }

    /// Get statistics about the split
    pub fn stats(&self) -> SplitStats {
        SplitStats {
            rust_count: self.rust_proxies.len(),
            go_count: self.go_proxies.len(),
            total: self.rust_proxies.len() + self.go_proxies.len(),
        }
    }
}

/// Statistics about configuration split
#[derive(Debug, Clone)]
pub struct SplitStats {
    pub rust_count: usize,
    pub go_count: usize,
    pub total: usize,
}

impl SplitStats {
    pub fn rust_percentage(&self) -> f64 {
        if self.total == 0 {
            100.0
        } else {
            (self.rust_count as f64 / self.total as f64) * 100.0
        }
    }

    pub fn go_percentage(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.go_count as f64 / self.total as f64) * 100.0
        }
    }
}

/// Split proxies by protocol tier
pub fn split_proxies(proxies: &[ProxyConfig]) -> SplitConfig {
    let mut rust_proxies = Vec::new();
    let mut go_proxies = Vec::new();
    let mut go_proxy_names = HashSet::new();

    for proxy in proxies {
        match classify_protocol(&proxy.proxy_type) {
            ProtocolTier::Rust => {
                debug!("Proxy '{}' ({}) -> Rust native", proxy.name, proxy.proxy_type);
                rust_proxies.push(proxy.clone());
            }
            ProtocolTier::GoFallback => {
                debug!("Proxy '{}' ({}) -> Go fallback", proxy.name, proxy.proxy_type);
                go_proxies.push(proxy.clone());
                go_proxy_names.insert(proxy.name.clone());
            }
        }
    }

    let stats = SplitStats {
        rust_count: rust_proxies.len(),
        go_count: go_proxies.len(),
        total: rust_proxies.len() + go_proxies.len(),
    };

    info!(
        "Config split: {} Rust ({:.1}%), {} Go ({:.1}%)",
        stats.rust_count,
        stats.rust_percentage(),
        stats.go_count,
        stats.go_percentage()
    );

    SplitConfig {
        rust_proxies,
        go_proxies,
        go_proxy_names,
    }
}

/// Go mihomo fallback configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoFallbackConfig {
    /// Mixed port for Go mihomo to listen on
    #[serde(rename = "mixed-port")]
    pub mixed_port: u16,

    /// Log level
    #[serde(rename = "log-level")]
    pub log_level: String,

    /// Mode (always direct for fallback)
    pub mode: String,

    /// Proxies to handle
    pub proxies: Vec<ProxyConfig>,

    /// Simple proxy group mapping all proxies
    #[serde(rename = "proxy-groups")]
    pub proxy_groups: Vec<GoProxyGroup>,

    /// Minimal rules (route everything)
    pub rules: Vec<String>,

    /// External controller (disabled for child process)
    #[serde(rename = "external-controller")]
    pub external_controller: Option<String>,

    /// DNS (use system DNS)
    pub dns: GoDnsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoProxyGroup {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: String,
    pub proxies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoDnsConfig {
    pub enable: bool,
}

impl GoFallbackConfig {
    /// Create a new Go fallback config
    pub fn new(proxies: Vec<ProxyConfig>, listen_port: u16) -> Self {
        let proxy_names: Vec<String> = proxies.iter().map(|p| p.name.clone()).collect();

        // Create a selector group with all proxies
        let proxy_groups = if proxy_names.is_empty() {
            vec![]
        } else {
            vec![GoProxyGroup {
                name: "FALLBACK".to_string(),
                group_type: "select".to_string(),
                proxies: proxy_names,
            }]
        };

        GoFallbackConfig {
            mixed_port: listen_port,
            log_level: "warning".to_string(), // Quiet logging for child process
            mode: "rule".to_string(),
            proxies,
            proxy_groups,
            rules: vec![
                "MATCH,FALLBACK".to_string(), // Route all traffic through fallback group
            ],
            external_controller: None, // Disable API for child process
            dns: GoDnsConfig { enable: false },  // Use system DNS
        }
    }

    /// Create config with no proxies (for initialization)
    pub fn empty(listen_port: u16) -> Self {
        Self::new(vec![], listen_port)
    }

    /// Serialize to YAML string
    pub fn to_yaml(&self) -> Result<String, serde_yaml::Error> {
        serde_yaml::to_string(self)
    }

    /// Write configuration to file
    pub async fn write_to_file<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let yaml = self.to_yaml().map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
        })?;
        fs::write(path, yaml).await
    }
}

/// Generate Go fallback config from main config
pub fn generate_go_fallback_config(config: &Config, listen_port: u16) -> GoFallbackConfig {
    let split = split_proxies(&config.proxies);
    GoFallbackConfig::new(split.go_proxies, listen_port)
}

/// Default Go fallback listen port
pub const DEFAULT_GO_FALLBACK_PORT: u16 = 17890;

/// Default Go fallback config path
pub fn default_go_config_path() -> String {
    "go-fallback-config.yaml".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn make_proxy(name: &str, proxy_type: &str) -> ProxyConfig {
        ProxyConfig {
            name: name.to_string(),
            proxy_type: proxy_type.to_string(),
            server: "example.com".to_string(),
            port: 443,
            extra: HashMap::new(),
        }
    }

    #[test]
    fn test_split_proxies_basic() {
        let proxies = vec![
            make_proxy("ss-node", "ss"),
            make_proxy("vmess-node", "vmess"),
            make_proxy("snell-node", "snell"),
            make_proxy("tuic-node", "tuic"),
        ];

        let split = split_proxies(&proxies);

        assert_eq!(split.rust_proxies.len(), 2);
        assert_eq!(split.go_proxies.len(), 2);
        assert!(split.is_go_fallback("snell-node"));
        assert!(split.is_go_fallback("tuic-node"));
        assert!(!split.is_go_fallback("ss-node"));
    }

    #[test]
    fn test_split_stats() {
        let proxies = vec![
            make_proxy("ss-1", "ss"),
            make_proxy("ss-2", "ss"),
            make_proxy("vmess-1", "vmess"),
            make_proxy("snell-1", "snell"),
        ];

        let split = split_proxies(&proxies);
        let stats = split.stats();

        assert_eq!(stats.rust_count, 3);
        assert_eq!(stats.go_count, 1);
        assert_eq!(stats.total, 4);
        assert!((stats.rust_percentage() - 75.0).abs() < 0.01);
        assert!((stats.go_percentage() - 25.0).abs() < 0.01);
    }

    #[test]
    fn test_all_rust() {
        let proxies = vec![
            make_proxy("ss-1", "ss"),
            make_proxy("vmess-1", "vmess"),
            make_proxy("trojan-1", "trojan"),
        ];

        let split = split_proxies(&proxies);

        assert_eq!(split.rust_proxies.len(), 3);
        assert_eq!(split.go_proxies.len(), 0);
        assert!((split.stats().rust_percentage() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_all_go() {
        let proxies = vec![
            make_proxy("snell-1", "snell"),
            make_proxy("tuic-1", "tuic"),
            make_proxy("wg-1", "wireguard"),
        ];

        let split = split_proxies(&proxies);

        assert_eq!(split.rust_proxies.len(), 0);
        assert_eq!(split.go_proxies.len(), 3);
        assert!((split.stats().go_percentage() - 100.0).abs() < 0.01);
    }

    #[test]
    fn test_go_fallback_config_creation() {
        let proxies = vec![
            make_proxy("snell-1", "snell"),
            make_proxy("tuic-1", "tuic"),
        ];

        let config = GoFallbackConfig::new(proxies, 17890);

        assert_eq!(config.mixed_port, 17890);
        assert_eq!(config.proxies.len(), 2);
        assert_eq!(config.proxy_groups.len(), 1);
        assert_eq!(config.proxy_groups[0].name, "FALLBACK");
        assert_eq!(config.proxy_groups[0].proxies.len(), 2);
    }

    #[test]
    fn test_go_fallback_config_yaml() {
        let proxies = vec![make_proxy("snell-1", "snell")];
        let config = GoFallbackConfig::new(proxies, 17890);

        let yaml = config.to_yaml().unwrap();
        assert!(yaml.contains("mixed-port: 17890"));
        assert!(yaml.contains("snell-1"));
    }

    #[test]
    fn test_empty_config() {
        let config = GoFallbackConfig::empty(17890);

        assert_eq!(config.proxies.len(), 0);
        assert_eq!(config.proxy_groups.len(), 0);
    }
}
