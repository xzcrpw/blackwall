/// API key management and tier-based access control.
///
/// Manages API keys for the Enterprise Threat Feed. Each key is
/// associated with an `ApiTier` that determines access to SIEM
/// formats, page size limits, and STIX/TAXII endpoints.
///
/// API keys are stored as SHA256 hashes — the raw key is never
/// persisted after initial generation.
use common::hivemind::{self, ApiTier};
use ring::digest;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

/// Thread-safe handle to the license manager.
pub type SharedLicenseManager = Arc<RwLock<LicenseManager>>;

/// Manages API keys and their associated tiers.
pub struct LicenseManager {
    /// Map from SHA256(api_key) hex → tier.
    keys: HashMap<String, ApiTier>,
}

impl Default for LicenseManager {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenseManager {
    /// Create a new empty license manager.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Create a shared (thread-safe) handle to a new license manager.
    pub fn shared() -> SharedLicenseManager {
        Arc::new(RwLock::new(Self::new()))
    }

    /// Register an API key with the given tier.
    ///
    /// The key is immediately hashed — only the hash is stored.
    /// Returns the key hash for logging purposes.
    pub fn register_key(&mut self, raw_key: &str, tier: ApiTier) -> String {
        let hash = hash_api_key(raw_key);
        self.keys.insert(hash.clone(), tier);
        info!(
            key_hash = &hash[..16],
            ?tier,
            total_keys = self.keys.len(),
            "API key registered"
        );
        hash
    }

    /// Validate an API key and return its tier.
    ///
    /// Returns `None` if the key is not registered.
    pub fn validate(&self, raw_key: &str) -> Option<ApiTier> {
        let hash = hash_api_key(raw_key);
        let result = self.keys.get(&hash).copied();
        if result.is_none() {
            warn!(
                key_hash = &hash[..16],
                "API key validation failed — unknown key"
            );
        }
        result
    }

    /// Revoke an API key.
    ///
    /// Returns `true` if the key existed and was removed.
    pub fn revoke_key(&mut self, raw_key: &str) -> bool {
        let hash = hash_api_key(raw_key);
        let removed = self.keys.remove(&hash).is_some();
        if removed {
            info!(key_hash = &hash[..16], "API key revoked");
        }
        removed
    }

    /// Total number of registered API keys.
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

/// Compute SHA256 hash of an API key, returned as lowercase hex.
fn hash_api_key(raw_key: &str) -> String {
    let hash = digest::digest(&digest::SHA256, raw_key.as_bytes());
    hash.as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Extract an API key from an HTTP Authorization header value.
///
/// Expects format: `Bearer <api-key>`
/// Returns `None` if the header is missing or malformed.
pub fn extract_bearer_token(auth_header: Option<&str>) -> Option<&str> {
    let header = auth_header?;
    let stripped = header.strip_prefix("Bearer ")?;
    let token = stripped.trim();
    if token.is_empty() {
        return None;
    }
    // SECURITY: Enforce maximum token length to prevent DoS via huge headers
    if token.len() > hivemind::API_KEY_LENGTH * 2 + 16 {
        return None;
    }
    Some(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_validate() {
        let mut mgr = LicenseManager::new();
        mgr.register_key("test-key-123", ApiTier::Enterprise);

        let tier = mgr.validate("test-key-123");
        assert_eq!(tier, Some(ApiTier::Enterprise));
    }

    #[test]
    fn invalid_key_returns_none() {
        let mgr = LicenseManager::new();
        assert_eq!(mgr.validate("nonexistent"), None);
    }

    #[test]
    fn revoke_key() {
        let mut mgr = LicenseManager::new();
        mgr.register_key("revoke-me", ApiTier::Free);
        assert!(mgr.validate("revoke-me").is_some());

        assert!(mgr.revoke_key("revoke-me"));
        assert!(mgr.validate("revoke-me").is_none());
    }

    #[test]
    fn different_tiers() {
        let mut mgr = LicenseManager::new();
        mgr.register_key("free-key", ApiTier::Free);
        mgr.register_key("enterprise-key", ApiTier::Enterprise);
        mgr.register_key("ns-key", ApiTier::NationalSecurity);

        assert_eq!(mgr.validate("free-key"), Some(ApiTier::Free));
        assert_eq!(mgr.validate("enterprise-key"), Some(ApiTier::Enterprise));
        assert_eq!(
            mgr.validate("ns-key"),
            Some(ApiTier::NationalSecurity)
        );
        assert_eq!(mgr.key_count(), 3);
    }

    #[test]
    fn key_hash_is_deterministic() {
        let h1 = hash_api_key("same-key");
        let h2 = hash_api_key("same-key");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA256 hex = 64 chars
    }

    #[test]
    fn extract_bearer_valid() {
        assert_eq!(
            extract_bearer_token(Some("Bearer my-api-key")),
            Some("my-api-key")
        );
    }

    #[test]
    fn extract_bearer_missing() {
        assert_eq!(extract_bearer_token(None), None);
        assert_eq!(extract_bearer_token(Some("")), None);
        assert_eq!(extract_bearer_token(Some("Basic abc")), None);
        assert_eq!(extract_bearer_token(Some("Bearer ")), None);
    }

    #[test]
    fn tier_access_control() {
        assert!(!ApiTier::Free.can_access_siem());
        assert!(ApiTier::Enterprise.can_access_siem());
        assert!(ApiTier::NationalSecurity.can_access_taxii());

        assert_eq!(ApiTier::Free.max_page_size(), 50);
        assert_eq!(ApiTier::Enterprise.max_page_size(), 1000);
    }
}
