//! GeoIP lookup using MaxMind database

use maxminddb::{geoip2, Reader};
use std::net::IpAddr;
use std::path::Path;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

/// GeoIP database reader
pub struct GeoIpReader {
    reader: RwLock<Option<Reader<Vec<u8>>>>,
    path: String,
}

impl GeoIpReader {
    /// Create a new GeoIP reader
    pub fn new(path: &str) -> Self {
        let reader = Self::load_database(path);
        if reader.is_some() {
            info!("Loaded GeoIP database from {}", path);
        } else {
            warn!("GeoIP database not found at {}, GEOIP rules will not match", path);
        }

        GeoIpReader {
            reader: RwLock::new(reader),
            path: path.to_string(),
        }
    }

    /// Load database from file
    fn load_database(path: &str) -> Option<Reader<Vec<u8>>> {
        if !Path::new(path).exists() {
            return None;
        }

        match Reader::open_readfile(path) {
            Ok(reader) => Some(reader),
            Err(e) => {
                warn!("Failed to open GeoIP database: {}", e);
                None
            }
        }
    }

    /// Reload the database
    pub fn reload(&self) -> bool {
        if let Some(new_reader) = Self::load_database(&self.path) {
            let mut reader = self.reader.write();
            *reader = Some(new_reader);
            info!("GeoIP database reloaded");
            true
        } else {
            false
        }
    }

    /// Lookup country code for an IP address
    pub fn lookup(&self, ip: IpAddr) -> Option<String> {
        let reader = self.reader.read();
        let reader = reader.as_ref()?;

        match reader.lookup::<geoip2::Country>(ip) {
            Ok(country) => {
                let code = country.country?.iso_code?;
                debug!("GeoIP lookup: {} -> {}", ip, code);
                Some(code.to_uppercase())
            }
            Err(e) => {
                debug!("GeoIP lookup failed for {}: {}", ip, e);
                None
            }
        }
    }

    /// Check if an IP matches a country code
    pub fn matches(&self, ip: IpAddr, country_code: &str) -> bool {
        if let Some(code) = self.lookup(ip) {
            code.eq_ignore_ascii_case(country_code)
        } else {
            false
        }
    }

    /// Check if database is loaded
    pub fn is_loaded(&self) -> bool {
        self.reader.read().is_some()
    }
}

impl Default for GeoIpReader {
    fn default() -> Self {
        // Try common locations
        let paths = [
            "country.mmdb",
            "Country.mmdb",
            "geoip.mmdb",
            "/usr/share/GeoIP/GeoLite2-Country.mmdb",
        ];

        for path in &paths {
            if Path::new(path).exists() {
                return GeoIpReader::new(path);
            }
        }

        GeoIpReader::new("country.mmdb")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_geoip_reader_creation() {
        // Should not panic even if file does not exist
        let reader = GeoIpReader::new("nonexistent.mmdb");
        assert!(!reader.is_loaded());
    }
}
