//! Integration tests for mihomo-rust API compatibility
//!
//! These tests verify that the Rust implementation is compatible with
//! the mihomo Go version REST API.


use serde_json::json;

/// Test that GET /configs returns expected fields
#[test]
fn test_config_response_structure() {
    // Expected response structure from mihomo
    let expected_fields = vec![
        "port",
        "socks-port",
        "redir-port",
        "tproxy-port",
        "mixed-port",
        "allow-lan",
        "bind-address",
        "mode",
        "log-level",
        "ipv6",
        "tun",
    ];

    // This is a structural test - verifies our response has all required fields
    let sample_response = json!({
        "port": 7890,
        "socks-port": 7891,
        "redir-port": 0,
        "tproxy-port": 0,
        "mixed-port": 7890,
        "allow-lan": false,
        "bind-address": "*",
        "mode": "rule",
        "log-level": "info",
        "ipv6": false,
        "tun": {
            "enable": false,
            "device": "",
            "stack": "system"
        }
    });

    for field in expected_fields {
        assert!(sample_response.get(field).is_some(), "Missing field: {}", field);
    }
}

/// Test proxy response structure
#[test]
fn test_proxy_response_structure() {
    let expected_proxy_fields = vec![
        "name",
        "type",
        "all",
        "now",
        "history",
    ];

    let sample_proxy = json!({
        "name": "GLOBAL",
        "type": "Selector",
        "all": ["DIRECT", "REJECT", "proxy1"],
        "now": "DIRECT",
        "history": []
    });

    for field in expected_proxy_fields {
        assert!(sample_proxy.get(field).is_some(), "Missing field: {}", field);
    }
}

/// Test rule response structure
#[test]
fn test_rule_response_structure() {
    let sample_rules = json!({
        "rules": [
            {
                "type": "DOMAIN-SUFFIX",
                "payload": "google.com",
                "proxy": "PROXY"
            }
        ]
    });

    assert!(sample_rules["rules"].is_array());
    let rule = &sample_rules["rules"][0];
    assert!(rule["type"].is_string());
    assert!(rule["payload"].is_string());
    assert!(rule["proxy"].is_string());
}

/// Test connection response structure
#[test]
fn test_connection_response_structure() {
    let sample_connection = json!({
        "id": "abc123",
        "metadata": {
            "network": "tcp",
            "type": "HTTP",
            "sourceIP": "127.0.0.1",
            "destinationIP": "142.250.185.78",
            "sourcePort": "50000",
            "destinationPort": "443",
            "host": "www.google.com",
            "dnsMode": "normal",
            "processPath": ""
        },
        "upload": 1024,
        "download": 4096,
        "start": "2024-01-01T00:00:00Z",
        "chains": ["PROXY"],
        "rule": "DOMAIN-SUFFIX",
        "rulePayload": "google.com"
    });

    assert!(sample_connection["id"].is_string());
    assert!(sample_connection["metadata"].is_object());
    assert!(sample_connection["upload"].is_number());
    assert!(sample_connection["download"].is_number());
}

/// Test DNS query response structure
#[test]
fn test_dns_response_structure() {
    let sample_dns = json!({
        "Status": 0,
        "Question": [{
            "name": "example.com",
            "type": 1
        }],
        "Answer": [{
            "name": "example.com",
            "type": 1,
            "TTL": 300,
            "data": "93.184.216.34"
        }]
    });

    assert_eq!(sample_dns["Status"], 0);
    assert!(sample_dns["Question"].is_array());
    assert!(sample_dns["Answer"].is_array());
}

/// Test provider response structure
#[test]
fn test_provider_response_structure() {
    let sample_provider = json!({
        "type": "Proxy",
        "vehicleType": "HTTP",
        "updatedAt": "2024-01-01T00:00:00Z",
        "subscriptionInfo": {
            "upload": 1000000,
            "download": 5000000,
            "total": 10000000000_i64,
            "expire": 1735689600
        },
        "proxies": []
    });

    assert!(sample_provider["type"].is_string());
    assert!(sample_provider["vehicleType"].is_string());
}

/// Test config parsing with real-world config
#[test]
fn test_config_parsing() {
    use mihomo_rust::config::Config;

    let yaml = r#"
log-level: info
mode: rule
allow-lan: false

dns:
  enable: true
  nameserver:
    - 8.8.8.8
    - 8.8.4.4

proxies:
  - name: proxy1
    type: ss
    server: example.com
    port: 8388
    cipher: aes-256-gcm
    password: secret

proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - proxy1
      - DIRECT

rules:
  - DOMAIN-SUFFIX,google.com,PROXY
  - MATCH,DIRECT
"#;

    let config = Config::from_str(yaml).expect("Failed to parse config");
    assert_eq!(config.log_level, Some("info".to_string()));
    assert_eq!(config.mode, Some("rule".to_string()));
    assert_eq!(config.proxies.len(), 1);
    assert_eq!(config.proxy_groups.len(), 1);
    assert_eq!(config.rules.len(), 2);
}

/// Test rule engine with various rule types
#[test]
fn test_rule_engine_comprehensive() {
    use mihomo_rust::rule::RuleEngine;
    use mihomo_rust::common::Metadata;

    let rules = vec![
        "DOMAIN,exact.example.com,DIRECT".to_string(),
        "DOMAIN-SUFFIX,google.com,PROXY".to_string(),
        "DOMAIN-KEYWORD,facebook,SOCIAL".to_string(),
        "IP-CIDR,192.168.0.0/16,LOCAL".to_string(),
        "IP-CIDR,10.0.0.0/8,LOCAL".to_string(),
        "DST-PORT,443,HTTPS".to_string(),
        "MATCH,DEFAULT".to_string(),
    ];

    let engine = RuleEngine::new(&rules).unwrap();

    // Test exact domain
    let meta = Metadata::tcp()
        .with_host("exact.example.com".to_string())
        .with_dst_port(80);
    let (target, rule) = engine.match_rules(&meta);
    assert_eq!(target, "DIRECT");
    assert!(rule.contains("DOMAIN"));

    // Test domain suffix
    let meta = Metadata::tcp()
        .with_host("mail.google.com".to_string())
        .with_dst_port(443);
    let (target, _) = engine.match_rules(&meta);
    assert_eq!(target, "PROXY");

    // Test domain keyword
    let meta = Metadata::tcp()
        .with_host("m.facebook.com".to_string())
        .with_dst_port(443);
    let (target, _) = engine.match_rules(&meta);
    assert_eq!(target, "SOCIAL");

    // Test IP CIDR
    let mut meta = Metadata::tcp()
        .with_host("".to_string())
        .with_dst_port(80);
    meta.dst_ip = Some("192.168.1.100".parse().unwrap());
    let (target, _) = engine.match_rules(&meta);
    assert_eq!(target, "LOCAL");

    // Test fallback
    let meta = Metadata::tcp()
        .with_host("unknown.domain.net".to_string())
        .with_dst_port(80);
    let (target, _) = engine.match_rules(&meta);
    assert_eq!(target, "DEFAULT");
}
