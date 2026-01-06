//! Configuration parser utilities

use crate::{Error, Result};
use std::collections::HashMap;

/// Parse proxy URL (ss://, vmess://, trojan://, etc.)
pub fn parse_proxy_url(url: &str) -> Result<HashMap<String, String>> {
    let mut result = HashMap::new();

    if url.starts_with("ss://") {
        parse_shadowsocks_url(url, &mut result)?;
    } else if url.starts_with("vmess://") {
        parse_vmess_url(url, &mut result)?;
    } else if url.starts_with("trojan://") {
        parse_trojan_url(url, &mut result)?;
    } else if url.starts_with("hysteria2://") || url.starts_with("hy2://") {
        parse_hysteria2_url(url, &mut result)?;
    } else {
        return Err(Error::parse(format!("Unknown proxy URL scheme: {}", url)));
    }

    Ok(result)
}

fn parse_shadowsocks_url(url: &str, result: &mut HashMap<String, String>) -> Result<()> {
    result.insert("type".to_string(), "ss".to_string());

    // Format: ss://base64(method:password)@host:port#name
    // or SIP002: ss://base64(method:password)@host:port/?plugin=...#name
    let url = &url[5..]; // Remove "ss://"

    // Split by # to get the name
    let (url, name) = if let Some(idx) = url.rfind('#') {
        let name = urlencoding::decode(&url[idx + 1..])
            .map_err(|e| Error::parse(e.to_string()))?
            .to_string();
        (&url[..idx], Some(name))
    } else {
        (url, None)
    };

    // Try to parse as SIP002 first (base64@host:port)
    if let Some(at_idx) = url.rfind('@') {
        let user_info = &url[..at_idx];
        let host_port = &url[at_idx + 1..];

        // Decode base64 user info
        let decoded = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD_NO_PAD,
            user_info,
        )
        .or_else(|_| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, user_info)
        })
        .map_err(|e| Error::parse(format!("Invalid base64: {}", e)))?;

        let decoded_str = String::from_utf8(decoded)
            .map_err(|e| Error::parse(format!("Invalid UTF-8: {}", e)))?;

        // method:password
        if let Some(colon_idx) = decoded_str.find(':') {
            result.insert("cipher".to_string(), decoded_str[..colon_idx].to_string());
            result.insert("password".to_string(), decoded_str[colon_idx + 1..].to_string());
        }

        // Parse host:port (may have query string)
        let (host_port, query) = if let Some(q_idx) = host_port.find('?') {
            (&host_port[..q_idx], Some(&host_port[q_idx + 1..]))
        } else {
            (host_port, None)
        };

        if let Some(colon_idx) = host_port.rfind(':') {
            result.insert("server".to_string(), host_port[..colon_idx].to_string());
            result.insert("port".to_string(), host_port[colon_idx + 1..].to_string());
        }

        // Parse query string for plugin
        if let Some(query) = query {
            for param in query.split('&') {
                if let Some(eq_idx) = param.find('=') {
                    let key = &param[..eq_idx];
                    let value = urlencoding::decode(&param[eq_idx + 1..])
                        .map_err(|e| Error::parse(e.to_string()))?;
                    result.insert(key.to_string(), value.to_string());
                }
            }
        }
    }

    if let Some(name) = name {
        result.insert("name".to_string(), name);
    }

    Ok(())
}

fn parse_vmess_url(url: &str, result: &mut HashMap<String, String>) -> Result<()> {
    result.insert("type".to_string(), "vmess".to_string());

    // Format: vmess://base64(json)
    let encoded = &url[8..]; // Remove "vmess://"

    let decoded = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
        .or_else(|_| {
            base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE, encoded)
        })
        .map_err(|e| Error::parse(format!("Invalid base64: {}", e)))?;

    let json_str = String::from_utf8(decoded)
        .map_err(|e| Error::parse(format!("Invalid UTF-8: {}", e)))?;

    let json: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| Error::parse(format!("Invalid JSON: {}", e)))?;

    if let Some(obj) = json.as_object() {
        // Standard VMess JSON fields
        if let Some(v) = obj.get("ps").and_then(|v| v.as_str()) {
            result.insert("name".to_string(), v.to_string());
        }
        if let Some(v) = obj.get("add").and_then(|v| v.as_str()) {
            result.insert("server".to_string(), v.to_string());
        }
        if let Some(v) = obj.get("port") {
            let port = match v {
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::String(s) => s.clone(),
                _ => return Err(Error::parse("Invalid port")),
            };
            result.insert("port".to_string(), port);
        }
        if let Some(v) = obj.get("id").and_then(|v| v.as_str()) {
            result.insert("uuid".to_string(), v.to_string());
        }
        if let Some(v) = obj.get("aid") {
            let aid = match v {
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::String(s) => s.clone(),
                _ => "0".to_string(),
            };
            result.insert("alterId".to_string(), aid);
        }
        if let Some(v) = obj.get("net").and_then(|v| v.as_str()) {
            result.insert("network".to_string(), v.to_string());
        }
        if let Some(v) = obj.get("type").and_then(|v| v.as_str()) {
            result.insert("cipher".to_string(), v.to_string());
        }
        if let Some(v) = obj.get("tls").and_then(|v| v.as_str()) {
            result.insert("tls".to_string(), (v == "tls").to_string());
        }
        if let Some(v) = obj.get("sni").and_then(|v| v.as_str()) {
            result.insert("servername".to_string(), v.to_string());
        }
        if let Some(v) = obj.get("host").and_then(|v| v.as_str()) {
            result.insert("ws-host".to_string(), v.to_string());
        }
        if let Some(v) = obj.get("path").and_then(|v| v.as_str()) {
            result.insert("ws-path".to_string(), v.to_string());
        }
    }

    Ok(())
}

fn parse_trojan_url(url: &str, result: &mut HashMap<String, String>) -> Result<()> {
    result.insert("type".to_string(), "trojan".to_string());

    // Format: trojan://password@host:port?params#name
    let url = &url[9..]; // Remove "trojan://"

    // Split by # to get the name
    let (url, name) = if let Some(idx) = url.rfind('#') {
        let name = urlencoding::decode(&url[idx + 1..])
            .map_err(|e| Error::parse(e.to_string()))?
            .to_string();
        (&url[..idx], Some(name))
    } else {
        (url, None)
    };

    // Split by @ to get password and host:port
    if let Some(at_idx) = url.find('@') {
        let password = urlencoding::decode(&url[..at_idx])
            .map_err(|e| Error::parse(e.to_string()))?
            .to_string();
        result.insert("password".to_string(), password);

        let host_port_query = &url[at_idx + 1..];

        // Split by ? to get query params
        let (host_port, query) = if let Some(q_idx) = host_port_query.find('?') {
            (&host_port_query[..q_idx], Some(&host_port_query[q_idx + 1..]))
        } else {
            (host_port_query, None)
        };

        // Parse host:port
        if let Some(colon_idx) = host_port.rfind(':') {
            result.insert("server".to_string(), host_port[..colon_idx].to_string());
            result.insert("port".to_string(), host_port[colon_idx + 1..].to_string());
        }

        // Parse query params
        if let Some(query) = query {
            for param in query.split('&') {
                if let Some(eq_idx) = param.find('=') {
                    let key = &param[..eq_idx];
                    let value = urlencoding::decode(&param[eq_idx + 1..])
                        .map_err(|e| Error::parse(e.to_string()))?;

                    match key {
                        "sni" => result.insert("sni".to_string(), value.to_string()),
                        "type" => result.insert("network".to_string(), value.to_string()),
                        "path" => result.insert("ws-path".to_string(), value.to_string()),
                        "host" => result.insert("ws-host".to_string(), value.to_string()),
                        "security" => result.insert("security".to_string(), value.to_string()),
                        "alpn" => result.insert("alpn".to_string(), value.to_string()),
                        "fp" => result.insert("fingerprint".to_string(), value.to_string()),
                        _ => result.insert(key.to_string(), value.to_string()),
                    };
                }
            }
        }
    }

    if let Some(name) = name {
        result.insert("name".to_string(), name);
    }

    Ok(())
}

fn parse_hysteria2_url(url: &str, result: &mut HashMap<String, String>) -> Result<()> {
    result.insert("type".to_string(), "hysteria2".to_string());

    // Format: hysteria2://password@host:port?params#name
    // or: hy2://password@host:port?params#name
    let url = if url.starts_with("hysteria2://") {
        &url[12..]
    } else {
        &url[6..] // hy2://
    };

    // Split by # to get the name
    let (url, name) = if let Some(idx) = url.rfind('#') {
        let name = urlencoding::decode(&url[idx + 1..])
            .map_err(|e| Error::parse(e.to_string()))?
            .to_string();
        (&url[..idx], Some(name))
    } else {
        (url, None)
    };

    // Split by @ to get password and host:port
    if let Some(at_idx) = url.find('@') {
        let password = urlencoding::decode(&url[..at_idx])
            .map_err(|e| Error::parse(e.to_string()))?
            .to_string();
        result.insert("password".to_string(), password);

        let host_port_query = &url[at_idx + 1..];

        // Split by ? to get query params
        let (host_port, query) = if let Some(q_idx) = host_port_query.find('?') {
            (&host_port_query[..q_idx], Some(&host_port_query[q_idx + 1..]))
        } else {
            (host_port_query, None)
        };

        // Parse host:port
        if let Some(colon_idx) = host_port.rfind(':') {
            result.insert("server".to_string(), host_port[..colon_idx].to_string());
            result.insert("port".to_string(), host_port[colon_idx + 1..].to_string());
        }

        // Parse query params
        if let Some(query) = query {
            for param in query.split('&') {
                if let Some(eq_idx) = param.find('=') {
                    let key = &param[..eq_idx];
                    let value = urlencoding::decode(&param[eq_idx + 1..])
                        .map_err(|e| Error::parse(e.to_string()))?;

                    match key {
                        "sni" => result.insert("sni".to_string(), value.to_string()),
                        "insecure" => result.insert("skip-cert-verify".to_string(), value.to_string()),
                        "obfs" => result.insert("obfs".to_string(), value.to_string()),
                        "obfs-password" => result.insert("obfs-password".to_string(), value.to_string()),
                        _ => result.insert(key.to_string(), value.to_string()),
                    };
                }
            }
        }
    }

    if let Some(name) = name {
        result.insert("name".to_string(), name);
    }

    Ok(())
}

/// Parse bandwidth string (e.g., "100 Mbps", "50mbps", "10 MB/s")
pub fn parse_bandwidth(s: &str) -> Result<u64> {
    let s = s.trim().to_lowercase();

    let (num_str, unit) = if let Some(idx) = s.find(|c: char| !c.is_ascii_digit() && c != '.') {
        (&s[..idx], s[idx..].trim())
    } else {
        return Err(Error::parse(format!("Invalid bandwidth: {}", s)));
    };

    let num: f64 = num_str
        .parse()
        .map_err(|e| Error::parse(format!("Invalid bandwidth number: {}", e)))?;

    // Note: SI units (decimal): kbps/mbps/gbps = bits per second
    // Binary units: kb/mb/gb = bytes (for data transfer rates)
    let multiplier = match unit {
        "bps" | "b/s" => 1.0,
        "kbps" | "kb/s" => 1000.0,  // SI: kilobits per second
        "mbps" | "mb/s" => 1_000_000.0,  // SI: megabits per second
        "gbps" | "gb/s" => 1_000_000_000.0,  // SI: gigabits per second
        "kb" => 1024.0,  // Binary: kilobytes
        "mb" => 1024.0 * 1024.0,  // Binary: megabytes
        "gb" => 1024.0 * 1024.0 * 1024.0,  // Binary: gigabytes
        _ => return Err(Error::parse(format!("Unknown bandwidth unit: {}", unit))),
    };

    Ok((num * multiplier) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_bandwidth() {
        assert_eq!(parse_bandwidth("100 Mbps").unwrap(), 100_000_000);
        assert_eq!(parse_bandwidth("50mbps").unwrap(), 50_000_000);
        assert_eq!(parse_bandwidth("1 Gbps").unwrap(), 1_000_000_000);
    }

    #[test]
    fn test_parse_trojan_url() {
        let mut result = HashMap::new();
        parse_trojan_url(
            "trojan://password123@example.com:443?sni=example.com#MyTrojan",
            &mut result,
        )
        .unwrap();

        assert_eq!(result.get("type").unwrap(), "trojan");
        assert_eq!(result.get("password").unwrap(), "password123");
        assert_eq!(result.get("server").unwrap(), "example.com");
        assert_eq!(result.get("port").unwrap(), "443");
        assert_eq!(result.get("name").unwrap(), "MyTrojan");
    }
}
