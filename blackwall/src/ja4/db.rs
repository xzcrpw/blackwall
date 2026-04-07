//! JA4 fingerprint database: known fingerprint matching.
//!
//! Maintains a HashMap of known JA4 fingerprints to tool/client names.
//! Can be populated from a static list or loaded from a config file.

use std::collections::HashMap;

/// Result of matching a JA4 fingerprint against the database.
#[derive(Debug, Clone, PartialEq)]
pub enum Ja4Match {
    /// Known malicious tool.
    Malicious { name: String, confidence: f32 },
    /// Known legitimate client.
    Benign { name: String },
    /// No match in database.
    Unknown,
}

/// Database of known JA4 fingerprints.
pub struct Ja4Database {
    /// Maps JA4 fingerprint prefix (first segment before underscore) → entries.
    entries: HashMap<String, Ja4Entry>,
}

#[derive(Debug, Clone)]
struct Ja4Entry {
    name: String,
    is_malicious: bool,
    confidence: f32,
}

impl Ja4Database {
    /// Create an empty database.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    /// Create a database pre-populated with common known fingerprints.
    pub fn with_defaults() -> Self {
        let mut db = Self::new();

        // Known scanning tools
        db.add_malicious("t13d0103", "nmap", 0.9);
        db.add_malicious("t12i0003", "masscan", 0.85);
        db.add_malicious("t12i0103", "zgrab2", 0.8);
        db.add_malicious("t13d0203", "nuclei", 0.85);
        db.add_malicious("t12d0305", "sqlmap", 0.9);
        db.add_malicious("t13d0105", "gobuster", 0.8);

        // Known legitimate clients
        db.add_benign("t13d1510", "Chrome/modern");
        db.add_benign("t13d1609", "Firefox/modern");
        db.add_benign("t13d0907", "Safari/modern");
        db.add_benign("t13d1208", "Edge/modern");
        db.add_benign("t13d0605", "curl");
        db.add_benign("t13d0404", "python-requests");

        db
    }

    /// Add a known malicious fingerprint.
    pub fn add_malicious(&mut self, prefix: &str, name: &str, confidence: f32) {
        self.entries.insert(
            prefix.to_string(),
            Ja4Entry {
                name: name.to_string(),
                is_malicious: true,
                confidence,
            },
        );
    }

    /// Add a known benign fingerprint.
    pub fn add_benign(&mut self, prefix: &str, name: &str) {
        self.entries.insert(
            prefix.to_string(),
            Ja4Entry {
                name: name.to_string(),
                is_malicious: false,
                confidence: 0.0,
            },
        );
    }

    /// Look up a JA4 fingerprint. Matches on the first segment (before first '_').
    pub fn lookup(&self, fingerprint: &str) -> Ja4Match {
        let prefix = fingerprint
            .split('_')
            .next()
            .unwrap_or(fingerprint);

        match self.entries.get(prefix) {
            Some(entry) if entry.is_malicious => Ja4Match::Malicious {
                name: entry.name.clone(),
                confidence: entry.confidence,
            },
            Some(entry) => Ja4Match::Benign {
                name: entry.name.clone(),
            },
            None => Ja4Match::Unknown,
        }
    }

    /// Number of entries in the database.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the database is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_database_returns_unknown() {
        let db = Ja4Database::new();
        assert_eq!(db.lookup("t13d1510_abc123_def456"), Ja4Match::Unknown);
    }

    #[test]
    fn defaults_include_known_tools() {
        let db = Ja4Database::with_defaults();
        assert!(db.len() > 0);

        match db.lookup("t13d0103_anything_here") {
            Ja4Match::Malicious { name, .. } => assert_eq!(name, "nmap"),
            other => panic!("expected nmap match, got {:?}", other),
        }
    }

    #[test]
    fn benign_lookup() {
        let db = Ja4Database::with_defaults();
        match db.lookup("t13d1510_hash1_hash2") {
            Ja4Match::Benign { name } => assert_eq!(name, "Chrome/modern"),
            other => panic!("expected Chrome match, got {:?}", other),
        }
    }

    #[test]
    fn unknown_fingerprint() {
        let db = Ja4Database::with_defaults();
        assert_eq!(db.lookup("t13d9999_unknown_hash"), Ja4Match::Unknown);
    }

    #[test]
    fn custom_entries() {
        let mut db = Ja4Database::new();
        db.add_malicious("t12i0201", "custom_scanner", 0.75);
        match db.lookup("t12i0201_hash_hash") {
            Ja4Match::Malicious { name, confidence } => {
                assert_eq!(name, "custom_scanner");
                assert!((confidence - 0.75).abs() < 0.01);
            }
            other => panic!("expected custom scanner, got {:?}", other),
        }
    }
}
