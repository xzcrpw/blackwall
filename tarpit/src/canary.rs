//! Canary credential tracker.
//!
//! Tracks credentials captured across deception protocols (WordPress login,
//! MySQL auth, SSH passwords) and detects cross-protocol credential reuse.

#![allow(dead_code)]

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// Maximum number of tracked credential entries.
const MAX_ENTRIES: usize = 1000;

/// A captured credential pair.
#[derive(Clone, Debug)]
pub struct CanaryCredential {
    /// Protocol where the credential was captured.
    pub protocol: &'static str,
    /// Username attempted.
    pub username: String,
    /// Password attempted (stored for correlation, NOT logged in production).
    password_hash: u64,
    /// Source IP that submitted this credential.
    pub source_ip: IpAddr,
    /// When the credential was captured.
    pub captured_at: Instant,
}

/// Tracks canary credentials and detects cross-protocol reuse.
pub struct CredentialTracker {
    /// Credentials indexed by (username_hash, password_hash) for fast lookup.
    entries: HashMap<(u64, u64), Vec<CanaryCredential>>,
    /// Total entry count for capacity management.
    count: usize,
}

impl Default for CredentialTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialTracker {
    /// Create a new empty credential tracker.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            count: 0,
        }
    }

    /// Record a captured credential and return any cross-protocol matches.
    pub fn record(
        &mut self,
        protocol: &'static str,
        username: &str,
        password: &str,
        source_ip: IpAddr,
    ) -> Vec<CanaryCredential> {
        let user_hash = simple_hash(username.as_bytes());
        let pass_hash = simple_hash(password.as_bytes());
        let key = (user_hash, pass_hash);

        let cred = CanaryCredential {
            protocol,
            username: username.to_string(),
            password_hash: pass_hash,
            source_ip,
            captured_at: Instant::now(),
        };

        // Find cross-protocol matches (same creds, different protocol)
        let matches: Vec<CanaryCredential> = self
            .entries
            .get(&key)
            .map(|existing| {
                existing
                    .iter()
                    .filter(|c| c.protocol != protocol)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();

        // Store the new credential
        if self.count < MAX_ENTRIES {
            let list = self.entries.entry(key).or_default();
            list.push(cred);
            self.count += 1;
        }

        matches
    }

    /// Prune credentials older than the given duration.
    pub fn prune_older_than(&mut self, max_age: std::time::Duration) {
        let now = Instant::now();
        self.entries.retain(|_, creds| {
            creds.retain(|c| now.duration_since(c.captured_at) < max_age);
            !creds.is_empty()
        });
        self.count = self.entries.values().map(|v| v.len()).sum();
    }
}

/// Simple non-cryptographic hash for credential correlation.
/// NOT for security — only for in-memory dedup.
fn simple_hash(data: &[u8]) -> u64 {
    let mut hash: u64 = 5381;
    for &b in data {
        hash = hash.wrapping_mul(33).wrapping_add(b as u64);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn no_match_first_credential() {
        let mut tracker = CredentialTracker::new();
        let matches = tracker.record(
            "http",
            "admin",
            "password123",
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        );
        assert!(matches.is_empty());
    }

    #[test]
    fn cross_protocol_match() {
        let mut tracker = CredentialTracker::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        // First: WordPress login
        tracker.record("http", "admin", "secret", ip);

        // Second: MySQL auth with same creds
        let matches = tracker.record("mysql", "admin", "secret", ip);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].protocol, "http");
    }

    #[test]
    fn same_protocol_no_match() {
        let mut tracker = CredentialTracker::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        tracker.record("http", "admin", "pass1", ip);
        let matches = tracker.record("http", "admin", "pass1", ip);
        // Same protocol — no cross-protocol match
        assert!(matches.is_empty());
    }

    #[test]
    fn different_creds_no_match() {
        let mut tracker = CredentialTracker::new();
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));

        tracker.record("http", "admin", "pass1", ip);
        let matches = tracker.record("mysql", "root", "pass2", ip);
        assert!(matches.is_empty());
    }
}
