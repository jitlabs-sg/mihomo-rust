//! DNS resolver implementation

use super::DnsCache;
use crate::config::DnsConfig;
use crate::{Error, Result};
use hickory_resolver::config::{
    NameServerConfig, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::TokioAsyncResolver;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info};

/// DNS resolver with caching and multiple upstream servers
pub struct Resolver {
    /// Main resolver
    resolver: TokioAsyncResolver,
    /// Fallback resolver
    fallback: Option<TokioAsyncResolver>,
    /// DNS cache
    cache: Arc<DnsCache>,
    /// Hosts mapping
    hosts: HashMap<String, IpAddr>,
    /// Enable IPv6
    ipv6: bool,
    /// IPv6 timeout (wait this long for IPv6 before returning IPv4 only)
    ipv6_timeout: Duration,
}

impl Resolver {
    /// Create new resolver from config
    pub async fn new(config: &DnsConfig) -> Result<Self> {
        let cache = Arc::new(DnsCache::new(config.cache_size));

        // Build hosts map
        let mut hosts = HashMap::new();
        for (domain, ip_str) in &config.hosts {
            if let Ok(ip) = ip_str.parse() {
                hosts.insert(domain.clone(), ip);
            }
        }

        // Build main resolver
        let resolver = Self::build_resolver(&config.nameserver).await?;

        // Build fallback resolver
        let fallback = if !config.fallback.is_empty() {
            Some(Self::build_resolver(&config.fallback).await?)
        } else {
            None
        };

        let ipv6_timeout = Duration::from_millis(100);

        Ok(Resolver {
            resolver,
            fallback,
            cache,
            hosts,
            ipv6: config.ipv6,
            ipv6_timeout,
        })
    }

    /// Build resolver from nameserver list
    async fn build_resolver(nameservers: &[String]) -> Result<TokioAsyncResolver> {
        if nameservers.is_empty() {
            // Use system default
            let resolver = TokioAsyncResolver::tokio_from_system_conf()
                .map_err(|e| Error::dns(format!("Failed to create system resolver: {}", e)))?;
            return Ok(resolver);
        }

        let mut config = ResolverConfig::new();

        for ns in nameservers {
            if let Some(ns_config) = Self::parse_nameserver(ns) {
                config.add_name_server(ns_config);
            }
        }

        let mut opts = ResolverOpts::default();
        opts.cache_size = 0; // We use our own cache
        opts.timeout = Duration::from_secs(5);
        opts.attempts = 2;
        opts.rotate = true;

        let resolver = TokioAsyncResolver::tokio(config, opts);
        Ok(resolver)
    }

    /// Parse nameserver string
    fn parse_nameserver(ns: &str) -> Option<NameServerConfig> {
        // Handle different formats:
        // - 8.8.8.8
        // - 8.8.8.8:53
        // - https://dns.google/dns-query
        // - tls://dns.google

        if ns.starts_with("https://") {
            // DoH
            // Note: hickory-resolver has specific DoH support
            let addr: SocketAddr = "8.8.8.8:443".parse().unwrap(); // Placeholder
            return Some(NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Https,
                tls_dns_name: Some(ns[8..].split('/').next()?.to_string()),
                trust_negative_responses: true,
                bind_addr: None,
                tls_config: None,
            });
        }

        if ns.starts_with("tls://") {
            // DoT
            let host = &ns[6..];
            let addr: SocketAddr = format!("{}:853", host).parse().ok()?;
            return Some(NameServerConfig {
                socket_addr: addr,
                protocol: Protocol::Tls,
                tls_dns_name: Some(host.to_string()),
                trust_negative_responses: true,
                bind_addr: None,
                tls_config: None,
            });
        }

        // Plain UDP/TCP
        let addr: SocketAddr = if ns.contains(':') {
            ns.parse().ok()?
        } else {
            format!("{}:53", ns).parse().ok()?
        };

        Some(NameServerConfig {
            socket_addr: addr,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
                tls_config: None,
        })
    }

    /// Resolve domain to single IP
    pub async fn resolve(&self, domain: &str) -> Result<IpAddr> {
        // Check if it's already an IP
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(ip);
        }

        // Check hosts
        if let Some(ip) = self.hosts.get(domain) {
            debug!("DNS {} -> {} (hosts)", domain, ip);
            return Ok(*ip);
        }

        // Check cache
        if let Some(entry) = self.cache.get(domain) {
            if let Some(ip) = entry.first_ip() {
                debug!("DNS {} -> {} (cache)", domain, ip);
                return Ok(ip);
            }
        }

        // Query upstream
        let ips = self.lookup(domain).await?;

        if ips.is_empty() {
            return Err(Error::dns(format!("No IP found for {}", domain)));
        }

        // Cache result
        self.cache.put(domain.to_string(), ips.clone());

        let ip = ips[0];
        debug!("DNS {} -> {}", domain, ip);
        Ok(ip)
    }

    /// Resolve domain to all IPs
    pub async fn resolve_all(&self, domain: &str) -> Result<Vec<IpAddr>> {
        // Check if it's already an IP
        if let Ok(ip) = domain.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }

        // Check hosts
        if let Some(ip) = self.hosts.get(domain) {
            return Ok(vec![*ip]);
        }

        // Check cache
        if let Some(entry) = self.cache.get(domain) {
            return Ok(entry.all_ips().to_vec());
        }

        // Query upstream
        let ips = self.lookup(domain).await?;

        if ips.is_empty() {
            return Err(Error::dns(format!("No IP found for {}", domain)));
        }

        // Cache result
        self.cache.put(domain.to_string(), ips.clone());

        Ok(ips)
    }

    /// Lookup domain using upstream resolvers
    async fn lookup(&self, domain: &str) -> Result<Vec<IpAddr>> {
        let mut ips = Vec::new();

        // Query IPv4 and IPv6 concurrently for lower latency
        if self.ipv6 {
            // Concurrent query: IPv4 + IPv6 (with timeout)
            let ipv4_future = self.resolver.ipv4_lookup(domain);
            let ipv6_future = tokio::time::timeout(
                self.ipv6_timeout,
                self.resolver.ipv6_lookup(domain),
            );

            let (ipv4_result, ipv6_result) = tokio::join!(ipv4_future, ipv6_future);

            // Process IPv4 results
            match ipv4_result {
                Ok(response) => {
                    for ip in response.iter() {
                        ips.push(IpAddr::V4(ip.0));
                    }
                }
                Err(e) => {
                    debug!("IPv4 lookup failed for {}: {}", domain, e);
                }
            }

            // Process IPv6 results
            match ipv6_result {
                Ok(Ok(response)) => {
                    for ip in response.iter() {
                        ips.push(IpAddr::V6(ip.0));
                    }
                }
                Ok(Err(e)) => {
                    debug!("IPv6 lookup failed for {}: {}", domain, e);
                }
                Err(_) => {
                    debug!("IPv6 lookup timed out for {}", domain);
                }
            }
        } else {
            // IPv4 only
            match self.resolver.ipv4_lookup(domain).await {
                Ok(response) => {
                    for ip in response.iter() {
                        ips.push(IpAddr::V4(ip.0));
                    }
                }
                Err(e) => {
                    debug!("IPv4 lookup failed for {}: {}", domain, e);
                }
            }
        }

        // Try fallback if no results
        if ips.is_empty() {
            if let Some(ref fallback) = self.fallback {
                debug!("Trying fallback resolver for {}", domain);
                if let Ok(response) = fallback.ipv4_lookup(domain).await {
                    for ip in response.iter() {
                        ips.push(IpAddr::V4(ip.0));
                    }
                }
            }
        }

        Ok(ips)
    }

    /// Clear DNS cache
    pub fn clear_cache(&self) {
        self.cache.clear();
        info!("DNS cache cleared");
    }

    /// Get cache size
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_resolver_ip_passthrough() {
        let config = DnsConfig::default();
        let resolver = Resolver::new(&config).await.unwrap();

        let ip = resolver.resolve("8.8.8.8").await.unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[test]
    fn test_parse_nameserver() {
        let ns = Resolver::parse_nameserver("8.8.8.8").unwrap();
        assert_eq!(ns.protocol, Protocol::Udp);

        let ns = Resolver::parse_nameserver("8.8.8.8:53").unwrap();
        assert_eq!(ns.protocol, Protocol::Udp);
    }
}
