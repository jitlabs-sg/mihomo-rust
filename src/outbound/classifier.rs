//! Protocol classifier: determines Rust native vs Go fallback
//!
//! This module implements the hybrid architecture's core decision logic:
//! - Tier 1 (90% traffic): Rust native implementation
//! - Tier 2-3 (<10% traffic): Go mihomo fallback

/// Protocol tier classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolTier {
    /// Rust native implementation (high performance)
    Rust,
    /// Go mihomo fallback (compatibility)
    GoFallback,
}

impl std::fmt::Display for ProtocolTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProtocolTier::Rust => write!(f, "Rust"),
            ProtocolTier::GoFallback => write!(f, "Go"),
        }
    }
}

/// Classify a protocol type into Rust native or Go fallback
///
/// # Tier 1 (Rust Native)
/// - ss/shadowsocks: Fully implemented
/// - vmess: Fully implemented
/// - trojan: Fully implemented
/// - hysteria2: Fully implemented
/// - vless: Phase 2 implementation
/// - http: Phase 2 implementation (outbound)
/// - socks5: Phase 2 implementation (outbound)
/// - direct/reject: Built-in
///
/// # Tier 2-3 (Go Fallback - permanent)
/// - snell, mieru, tuic, wireguard, ssh
/// - hysteria (v1), ssr, reality, ech, dns
/// - Any unknown protocol
pub fn classify_protocol(protocol_type: &str) -> ProtocolTier {
    match protocol_type.to_lowercase().as_str() {
        // Tier 1: Rust native (implemented or planned)
        "ss" | "shadowsocks" => ProtocolTier::Rust,
        "vmess" => ProtocolTier::Rust,
        "trojan" => ProtocolTier::Rust,
        "vless" => ProtocolTier::Rust, // Phase 2 implementation
        "hysteria2" | "hy2" => ProtocolTier::Rust,
        "http" => ProtocolTier::Rust,   // Phase 2 implementation (outbound)
        "socks5" | "socks" => ProtocolTier::Rust, // Phase 2 implementation (outbound)
        "direct" => ProtocolTier::Rust,
        "reject" | "reject-drop" => ProtocolTier::Rust,

        // Tier 2-3: Permanent Go fallback (not worth reimplementing)
        _ => ProtocolTier::GoFallback,
    }
}

/// Check if a protocol is supported natively in Rust
pub fn is_rust_supported(protocol_type: &str) -> bool {
    matches!(classify_protocol(protocol_type), ProtocolTier::Rust)
}

/// Check if a protocol requires Go fallback
pub fn requires_go_fallback(protocol_type: &str) -> bool {
    matches!(classify_protocol(protocol_type), ProtocolTier::GoFallback)
}

/// Get list of protocols that will permanently use Go fallback
pub fn get_go_fallback_protocols() -> Vec<&'static str> {
    vec![
        "snell",      // Niche protocol, complex implementation
        "mieru",      // Proprietary protocol
        "tuic",       // QUIC-based, needs quinn work
        "wireguard",  // Kernel integration complexity
        "ssh",        // SSH tunneling
        "hysteria",   // V1, deprecated in favor of hysteria2
        "ssr",        // Legacy shadowsocksr
        "reality",    // XTLS/Reality complexity
        "ech",        // Encrypted Client Hello
        "dns",        // DNS-based proxying
        "vmess-grpc", // gRPC transport variant
        "trojan-grpc",
    ]
}

/// Get list of protocols supported natively in Rust
pub fn get_rust_protocols() -> Vec<&'static str> {
    vec![
        "ss",
        "shadowsocks",
        "vmess",
        "trojan",
        "vless",
        "hysteria2",
        "hy2",
        "http",
        "socks5",
        "socks",
        "direct",
        "reject",
        "reject-drop",
    ]
}

/// Protocol information for UI/debugging
#[derive(Debug, Clone)]
pub struct ProtocolInfo {
    pub name: &'static str,
    pub tier: ProtocolTier,
    pub description: &'static str,
    pub implemented: bool,
}

/// Get detailed info about a protocol
pub fn get_protocol_info(protocol_type: &str) -> ProtocolInfo {
    match protocol_type.to_lowercase().as_str() {
        "ss" | "shadowsocks" => ProtocolInfo {
            name: "Shadowsocks",
            tier: ProtocolTier::Rust,
            description: "Fast and secure SOCKS5 proxy",
            implemented: true,
        },
        "vmess" => ProtocolInfo {
            name: "VMess",
            tier: ProtocolTier::Rust,
            description: "V2Ray protocol with multiple encryption",
            implemented: true,
        },
        "trojan" => ProtocolInfo {
            name: "Trojan",
            tier: ProtocolTier::Rust,
            description: "HTTPS-based proxy protocol",
            implemented: true,
        },
        "vless" => ProtocolInfo {
            name: "VLESS",
            tier: ProtocolTier::Rust,
            description: "Lightweight V2Ray protocol",
            implemented: false, // Phase 2
        },
        "hysteria2" | "hy2" => ProtocolInfo {
            name: "Hysteria2",
            tier: ProtocolTier::Rust,
            description: "QUIC-based high-speed protocol",
            implemented: true,
        },
        "http" => ProtocolInfo {
            name: "HTTP",
            tier: ProtocolTier::Rust,
            description: "HTTP CONNECT proxy",
            implemented: false, // Phase 2
        },
        "socks5" | "socks" => ProtocolInfo {
            name: "SOCKS5",
            tier: ProtocolTier::Rust,
            description: "SOCKS5 proxy protocol",
            implemented: false, // Phase 2
        },
        "snell" => ProtocolInfo {
            name: "Snell",
            tier: ProtocolTier::GoFallback,
            description: "Surge's proprietary protocol",
            implemented: false,
        },
        "tuic" => ProtocolInfo {
            name: "TUIC",
            tier: ProtocolTier::GoFallback,
            description: "QUIC-based multiplexing protocol",
            implemented: false,
        },
        "wireguard" => ProtocolInfo {
            name: "WireGuard",
            tier: ProtocolTier::GoFallback,
            description: "Modern VPN protocol",
            implemented: false,
        },
        _ => ProtocolInfo {
            name: "Unknown",
            tier: ProtocolTier::GoFallback,
            description: "Unknown protocol - using Go fallback",
            implemented: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_protocols() {
        assert_eq!(classify_protocol("ss"), ProtocolTier::Rust);
        assert_eq!(classify_protocol("shadowsocks"), ProtocolTier::Rust);
        assert_eq!(classify_protocol("vmess"), ProtocolTier::Rust);
        assert_eq!(classify_protocol("trojan"), ProtocolTier::Rust);
        assert_eq!(classify_protocol("vless"), ProtocolTier::Rust);
        assert_eq!(classify_protocol("hysteria2"), ProtocolTier::Rust);
        assert_eq!(classify_protocol("hy2"), ProtocolTier::Rust);
        assert_eq!(classify_protocol("direct"), ProtocolTier::Rust);
        assert_eq!(classify_protocol("reject"), ProtocolTier::Rust);
    }

    #[test]
    fn test_case_insensitivity() {
        assert_eq!(classify_protocol("VMESS"), ProtocolTier::Rust);
        assert_eq!(classify_protocol("VMess"), ProtocolTier::Rust);
        assert_eq!(classify_protocol("TROJAN"), ProtocolTier::Rust);
        assert_eq!(classify_protocol("SNELL"), ProtocolTier::GoFallback);
    }

    #[test]
    fn test_go_fallback_protocols() {
        assert_eq!(classify_protocol("snell"), ProtocolTier::GoFallback);
        assert_eq!(classify_protocol("mieru"), ProtocolTier::GoFallback);
        assert_eq!(classify_protocol("tuic"), ProtocolTier::GoFallback);
        assert_eq!(classify_protocol("wireguard"), ProtocolTier::GoFallback);
        assert_eq!(classify_protocol("ssh"), ProtocolTier::GoFallback);
        assert_eq!(classify_protocol("ssr"), ProtocolTier::GoFallback);
    }

    #[test]
    fn test_unknown_defaults_to_go() {
        assert_eq!(classify_protocol("unknown"), ProtocolTier::GoFallback);
        assert_eq!(classify_protocol("future-protocol"), ProtocolTier::GoFallback);
    }

    #[test]
    fn test_is_rust_supported() {
        assert!(is_rust_supported("ss"));
        assert!(is_rust_supported("vmess"));
        assert!(!is_rust_supported("snell"));
        assert!(!is_rust_supported("unknown"));
    }

    #[test]
    fn test_requires_go_fallback() {
        assert!(!requires_go_fallback("ss"));
        assert!(requires_go_fallback("snell"));
        assert!(requires_go_fallback("tuic"));
    }

    #[test]
    fn test_protocol_lists() {
        let rust_protocols = get_rust_protocols();
        assert!(rust_protocols.contains(&"ss"));
        assert!(rust_protocols.contains(&"vmess"));

        let go_protocols = get_go_fallback_protocols();
        assert!(go_protocols.contains(&"snell"));
        assert!(go_protocols.contains(&"tuic"));
    }

    #[test]
    fn test_protocol_info() {
        let ss_info = get_protocol_info("ss");
        assert_eq!(ss_info.name, "Shadowsocks");
        assert_eq!(ss_info.tier, ProtocolTier::Rust);
        assert!(ss_info.implemented);

        let snell_info = get_protocol_info("snell");
        assert_eq!(snell_info.tier, ProtocolTier::GoFallback);
        assert!(!snell_info.implemented);
    }
}
