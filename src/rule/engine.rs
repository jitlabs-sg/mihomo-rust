//! Rule matching engine

use super::{DomainTrie, GeoIpReader};
use crate::common::Metadata;
use crate::{Error, Result};
use ipnet::IpNet;
use std::sync::Arc;
use tracing::debug;

/// Rule type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleType {
    /// Match domain suffix
    DomainSuffix,
    /// Match exact domain
    Domain,
    /// Match domain keyword
    DomainKeyword,
    /// Match GeoIP
    GeoIP,
    /// Match IP CIDR
    IpCidr,
    /// Match source IP CIDR
    SrcIpCidr,
    /// Match source port
    SrcPort,
    /// Match destination port
    DstPort,
    /// Match process name
    ProcessName,
    /// Match process path
    ProcessPath,
    /// Match network type (TCP/UDP)
    Network,
    /// Match inbound type
    InboundType,
    /// Final rule (MATCH)
    Match,
}

impl TryFrom<&str> for RuleType {
    type Error = Error;

    fn try_from(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "DOMAIN-SUFFIX" => Ok(RuleType::DomainSuffix),
            "DOMAIN" => Ok(RuleType::Domain),
            "DOMAIN-KEYWORD" => Ok(RuleType::DomainKeyword),
            "GEOIP" => Ok(RuleType::GeoIP),
            "IP-CIDR" | "IP-CIDR6" => Ok(RuleType::IpCidr),
            "SRC-IP-CIDR" => Ok(RuleType::SrcIpCidr),
            "SRC-PORT" => Ok(RuleType::SrcPort),
            "DST-PORT" => Ok(RuleType::DstPort),
            "PROCESS-NAME" => Ok(RuleType::ProcessName),
            "PROCESS-PATH" => Ok(RuleType::ProcessPath),
            "NETWORK" => Ok(RuleType::Network),
            "INBOUND-TYPE" | "IN-TYPE" => Ok(RuleType::InboundType),
            "MATCH" | "FINAL" => Ok(RuleType::Match),
            _ => Err(Error::Rule(format!("Unknown rule type: {}", s))),
        }
    }
}

/// Parsed rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub rule_type: RuleType,
    pub payload: String,
    pub target: String,
    pub no_resolve: bool,
}

impl Rule {
    /// Parse rule from string
    pub fn parse(rule_str: &str) -> Result<Self> {
        let parts: Vec<&str> = rule_str.split(',').map(|s| s.trim()).collect();

        if parts.len() < 2 {
            return Err(Error::Rule(format!("Invalid rule: {}", rule_str)));
        }

        let rule_type = RuleType::try_from(parts[0])?;

        let (payload, target, no_resolve) = if rule_type == RuleType::Match {
            // MATCH,target
            (String::new(), parts[1].to_string(), false)
        } else if parts.len() >= 3 {
            // TYPE,payload,target[,no-resolve]
            let no_resolve = parts.len() > 3 && parts[3].to_lowercase() == "no-resolve";
            (parts[1].to_string(), parts[2].to_string(), no_resolve)
        } else {
            return Err(Error::Rule(format!("Invalid rule: {}", rule_str)));
        };

        Ok(Rule {
            rule_type,
            payload,
            target,
            no_resolve,
        })
    }
}

/// Rule engine for matching connections to proxies
pub struct RuleEngine {
    /// Domain suffix rules (using trie for fast matching)
    domain_suffix_trie: DomainTrie<String>,
    /// Exact domain rules
    domain_exact: DomainTrie<String>,
    /// Domain keyword rules
    domain_keywords: Vec<(String, String)>,
    /// IP CIDR rules
    ip_cidrs: Vec<(IpNet, String, bool)>, // (cidr, target, no_resolve)
    /// Source IP CIDR rules
    src_ip_cidrs: Vec<(IpNet, String)>,
    /// Source port rules
    src_ports: Vec<(u16, String)>,
    /// Destination port rules
    dst_ports: Vec<(u16, String)>,
    /// Process name rules
    process_names: Vec<(String, String)>,
    /// GeoIP rules
    geoip_rules: Vec<(String, String)>, // (country_code, target)
    /// GeoIP database reader
    geoip_reader: Arc<GeoIpReader>,
    /// Network rules
    network_rules: Vec<(String, String)>, // (tcp/udp, target)
    /// Final (MATCH) rule target
    final_target: Option<String>,
    /// Total rule count
    rule_count: usize,
}

impl RuleEngine {
    /// Create new rule engine from rules list
    pub fn new(rules: &[String]) -> Result<Self> {
        let mut engine = RuleEngine {
            domain_suffix_trie: DomainTrie::new(),
            domain_exact: DomainTrie::new(),
            domain_keywords: Vec::new(),
            ip_cidrs: Vec::new(),
            src_ip_cidrs: Vec::new(),
            src_ports: Vec::new(),
            dst_ports: Vec::new(),
            process_names: Vec::new(),
            geoip_rules: Vec::new(),
            geoip_reader: Arc::new(GeoIpReader::default()),
            network_rules: Vec::new(),
            final_target: None,
            rule_count: 0,
        };

        for rule_str in rules {
            engine.add_rule(rule_str)?;
        }

        Ok(engine)
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule_str: &str) -> Result<()> {
        let rule = Rule::parse(rule_str)?;
        self.rule_count += 1;

        match rule.rule_type {
            RuleType::DomainSuffix => {
                // DOMAIN-SUFFIX matches both the domain and all subdomains
                // Insert as wildcard for subdomain matching
                self.domain_suffix_trie
                    .insert(&format!("*.{}", rule.payload), rule.target.clone());
                // Also insert exact match for the base domain
                self.domain_suffix_trie
                    .insert(&rule.payload, rule.target);
            }
            RuleType::Domain => {
                self.domain_exact.insert(&rule.payload, rule.target);
            }
            RuleType::DomainKeyword => {
                self.domain_keywords
                    .push((rule.payload.to_lowercase(), rule.target));
            }
            RuleType::IpCidr => {
                let cidr: IpNet = rule
                    .payload
                    .parse()
                    .map_err(|e| Error::Rule(format!("Invalid CIDR: {}", e)))?;
                self.ip_cidrs.push((cidr, rule.target, rule.no_resolve));
            }
            RuleType::SrcIpCidr => {
                let cidr: IpNet = rule
                    .payload
                    .parse()
                    .map_err(|e| Error::Rule(format!("Invalid CIDR: {}", e)))?;
                self.src_ip_cidrs.push((cidr, rule.target));
            }
            RuleType::SrcPort => {
                let port: u16 = rule
                    .payload
                    .parse()
                    .map_err(|e| Error::Rule(format!("Invalid port: {}", e)))?;
                self.src_ports.push((port, rule.target));
            }
            RuleType::DstPort => {
                let port: u16 = rule
                    .payload
                    .parse()
                    .map_err(|e| Error::Rule(format!("Invalid port: {}", e)))?;
                self.dst_ports.push((port, rule.target));
            }
            RuleType::ProcessName => {
                self.process_names
                    .push((rule.payload.to_lowercase(), rule.target));
            }
            RuleType::ProcessPath => {
                self.process_names
                    .push((rule.payload.to_lowercase(), rule.target));
            }
            RuleType::GeoIP => {
                self.geoip_rules
                    .push((rule.payload.to_uppercase(), rule.target));
            }
            RuleType::Network => {
                self.network_rules
                    .push((rule.payload.to_uppercase(), rule.target));
            }
            RuleType::InboundType => {
                // TODO: Implement inbound type matching
            }
            RuleType::Match => {
                self.final_target = Some(rule.target);
            }
        }

        Ok(())
    }

    /// Match metadata against rules
    ///
    /// Returns (proxy_name, rule_description)
    pub fn match_rules(&self, metadata: &Metadata) -> (String, String) {
        // Try domain rules first
        let host = metadata.host.to_lowercase();
        if !host.is_empty() {
            // Exact domain match
            if let Some(target) = self.domain_exact.search(&host) {
                debug!("Rule matched: DOMAIN,{} -> {}", host, target);
                return (target.clone(), format!("DOMAIN,{}", host));
            }

            // Domain suffix match
            if let Some(target) = self.domain_suffix_trie.search(&host) {
                debug!("Rule matched: DOMAIN-SUFFIX,{} -> {}", host, target);
                return (target.clone(), format!("DOMAIN-SUFFIX,{}", host));
            }

            // Domain keyword match
            for (keyword, target) in &self.domain_keywords {
                if host.contains(keyword) {
                    debug!("Rule matched: DOMAIN-KEYWORD,{} -> {}", keyword, target);
                    return (target.clone(), format!("DOMAIN-KEYWORD,{}", keyword));
                }
            }
        }

        // Source port rules
        for (port, target) in &self.src_ports {
            if metadata.src_port == *port {
                debug!("Rule matched: SRC-PORT,{} -> {}", port, target);
                return (target.clone(), format!("SRC-PORT,{}", port));
            }
        }

        // Destination port rules
        for (port, target) in &self.dst_ports {
            if metadata.dst_port == *port {
                debug!("Rule matched: DST-PORT,{} -> {}", port, target);
                return (target.clone(), format!("DST-PORT,{}", port));
            }
        }

        // Source IP CIDR rules
        for (cidr, target) in &self.src_ip_cidrs {
            if cidr.contains(&metadata.src_ip) {
                debug!("Rule matched: SRC-IP-CIDR,{} -> {}", cidr, target);
                return (target.clone(), format!("SRC-IP-CIDR,{}", cidr));
            }
        }

        // IP CIDR rules (destination)
        if let Some(dst_ip) = metadata.dst_ip {
            for (cidr, target, _) in &self.ip_cidrs {
                if cidr.contains(&dst_ip) {
                    debug!("Rule matched: IP-CIDR,{} -> {}", cidr, target);
                    return (target.clone(), format!("IP-CIDR,{}", cidr));
                }
            }
        }

        // Process name rules
        if let Some(ref process) = metadata.process {
            let process_lower = process.to_lowercase();
            for (name, target) in &self.process_names {
                if process_lower == *name || process_lower.ends_with(name) {
                    debug!("Rule matched: PROCESS-NAME,{} -> {}", name, target);
                    return (target.clone(), format!("PROCESS-NAME,{}", name));
                }
            }
        }

        // Network rules
        let network = format!("{:?}", metadata.network).to_uppercase();
        for (net, target) in &self.network_rules {
            if &network == net {
                debug!("Rule matched: NETWORK,{} -> {}", net, target);
                return (target.clone(), format!("NETWORK,{}", net));
            }
        }

        // GeoIP rules
        if let Some(dst_ip) = metadata.dst_ip {
            for (country_code, target) in &self.geoip_rules {
                if self.geoip_reader.matches(dst_ip, country_code) {
                    debug!("Rule matched: GEOIP,{} -> {}", country_code, target);
                    return (target.clone(), format!("GEOIP,{}", country_code));
                }
            }
        }

        // Final rule
        if let Some(ref target) = self.final_target {
            debug!("Rule matched: MATCH -> {}", target);
            return (target.clone(), "MATCH".to_string());
        }

        // Default to DIRECT
        debug!("No rule matched, using DIRECT");
        ("DIRECT".to_string(), "default".to_string())
    }

    /// Get number of rules
    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Check if any rules are defined
    pub fn has_rules(&self) -> bool {
        self.rule_count > 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Network;

    fn create_metadata(host: &str, port: u16) -> Metadata {
        Metadata::tcp()
            .with_host(host.to_string())
            .with_dst_port(port)
    }

    #[test]
    fn test_parse_rule() {
        let rule = Rule::parse("DOMAIN-SUFFIX,google.com,PROXY").unwrap();
        assert_eq!(rule.rule_type, RuleType::DomainSuffix);
        assert_eq!(rule.payload, "google.com");
        assert_eq!(rule.target, "PROXY");
    }

    #[test]
    fn test_parse_match_rule() {
        let rule = Rule::parse("MATCH,DIRECT").unwrap();
        assert_eq!(rule.rule_type, RuleType::Match);
        assert_eq!(rule.target, "DIRECT");
    }

    #[test]
    fn test_rule_engine() {
        let rules = vec![
            "DOMAIN-SUFFIX,google.com,PROXY".to_string(),
            "DOMAIN,example.org,DIRECT".to_string(),
            "DOMAIN-KEYWORD,facebook,PROXY".to_string(),
            "MATCH,DIRECT".to_string(),
        ];

        let engine = RuleEngine::new(&rules).unwrap();
        assert_eq!(engine.rule_count(), 4);

        // Test domain suffix
        let meta = create_metadata("www.google.com", 443);
        let (target, _) = engine.match_rules(&meta);
        assert_eq!(target, "PROXY");

        // Test exact domain
        let meta = create_metadata("example.org", 80);
        let (target, _) = engine.match_rules(&meta);
        assert_eq!(target, "DIRECT");

        // Test keyword
        let meta = create_metadata("m.facebook.com", 443);
        let (target, _) = engine.match_rules(&meta);
        assert_eq!(target, "PROXY");

        // Test final match
        let meta = create_metadata("unknown.com", 80);
        let (target, _) = engine.match_rules(&meta);
        assert_eq!(target, "DIRECT");
    }

    #[test]
    fn test_ip_cidr_rule() {
        let rules = vec![
            "IP-CIDR,192.168.0.0/16,DIRECT".to_string(),
            "MATCH,PROXY".to_string(),
        ];

        let engine = RuleEngine::new(&rules).unwrap();

        let mut meta = create_metadata("", 80);
        meta.dst_ip = Some("192.168.1.1".parse().unwrap());

        let (target, _) = engine.match_rules(&meta);
        assert_eq!(target, "DIRECT");
    }
}
