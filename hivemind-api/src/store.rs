/// In-memory store for consensus-verified IoCs.
///
/// The `ThreatFeedStore` holds all IoCs that reached cross-validation
/// consensus in the HiveMind mesh. It supports time-windowed queries,
/// filtering by severity and type, and pagination for API responses.
use common::hivemind::{self, IoC};
use ring::digest;
use std::sync::{Arc, RwLock};
use tracing::info;

/// A consensus-verified IoC with feed metadata.
#[derive(Clone, Debug, serde::Serialize)]
pub struct VerifiedIoC {
    /// The verified IoC data.
    pub ioc: IoC,
    /// Unix timestamp when consensus was reached.
    pub verified_at: u64,
    /// Pre-computed deterministic STIX identifier.
    pub stix_id: String,
}

/// Thread-safe handle to the IoC store.
pub type SharedStore = Arc<RwLock<ThreatFeedStore>>;

/// In-memory storage for verified IoCs, sorted by verification time.
pub struct ThreatFeedStore {
    /// Verified IoCs, ordered by `verified_at` ascending.
    iocs: Vec<VerifiedIoC>,
}

impl Default for ThreatFeedStore {
    fn default() -> Self {
        Self::new()
    }
}

impl ThreatFeedStore {
    /// Create a new empty store.
    pub fn new() -> Self {
        Self { iocs: Vec::new() }
    }

    /// Create a shared (thread-safe) handle to a new store.
    pub fn shared() -> SharedStore {
        Arc::new(RwLock::new(Self::new()))
    }

    /// Insert a verified IoC into the store.
    ///
    /// Computes the deterministic STIX ID from the IoC fields and
    /// inserts in sorted order by verification timestamp.
    pub fn insert(&mut self, ioc: IoC, verified_at: u64) {
        let stix_id = compute_stix_id(&ioc);
        let entry = VerifiedIoC {
            ioc,
            verified_at,
            stix_id,
        };

        // Insert in sorted order (most entries append at the end)
        let pos = self
            .iocs
            .partition_point(|e| e.verified_at <= verified_at);
        self.iocs.insert(pos, entry);

        info!(
            total = self.iocs.len(),
            verified_at,
            "IoC added to threat feed store"
        );
    }

    /// Query IoCs with filtering and pagination.
    pub fn query(&self, params: &QueryParams) -> QueryResult {
        let filtered: Vec<&VerifiedIoC> = self
            .iocs
            .iter()
            .filter(|e| {
                if let Some(since) = params.since {
                    if e.verified_at < since {
                        return false;
                    }
                }
                if let Some(min_sev) = params.min_severity {
                    if e.ioc.severity < min_sev {
                        return false;
                    }
                }
                if let Some(ioc_type) = params.ioc_type {
                    if e.ioc.ioc_type != ioc_type {
                        return false;
                    }
                }
                true
            })
            .collect();

        let total = filtered.len();
        let offset = params.offset.min(total);
        let limit = params.limit.min(hivemind::API_MAX_PAGE_SIZE);
        let end = (offset + limit).min(total);

        let items: Vec<VerifiedIoC> = filtered[offset..end]
            .iter()
            .map(|e| (*e).clone())
            .collect();

        QueryResult {
            items,
            total,
            offset,
            limit,
        }
    }

    /// Total number of verified IoCs in the store.
    pub fn len(&self) -> usize {
        self.iocs.len()
    }

    /// Whether the store is empty.
    pub fn is_empty(&self) -> bool {
        self.iocs.is_empty()
    }

    /// Get all IoCs (for stats/internal use). Returns a slice reference.
    pub fn all(&self) -> &[VerifiedIoC] {
        &self.iocs
    }
}

/// Parameters for querying the threat feed store.
#[derive(Clone, Debug, Default)]
pub struct QueryParams {
    /// Only return IoCs verified after this Unix timestamp.
    pub since: Option<u64>,
    /// Minimum severity level (0-4).
    pub min_severity: Option<u8>,
    /// Filter by IoC type.
    pub ioc_type: Option<u8>,
    /// Maximum items to return.
    pub limit: usize,
    /// Offset for pagination.
    pub offset: usize,
}

impl QueryParams {
    /// Create default query with standard page size.
    pub fn new() -> Self {
        Self {
            since: None,
            min_severity: None,
            ioc_type: None,
            limit: hivemind::API_DEFAULT_PAGE_SIZE,
            offset: 0,
        }
    }
}

/// Result of a store query with pagination metadata.
#[derive(Clone, Debug, serde::Serialize)]
pub struct QueryResult {
    /// Matching IoCs for the current page.
    pub items: Vec<VerifiedIoC>,
    /// Total matching IoCs (before pagination).
    pub total: usize,
    /// Current offset.
    pub offset: usize,
    /// Page size used.
    pub limit: usize,
}

/// Compute a deterministic STIX identifier from IoC fields.
///
/// Format: `indicator--<uuid>` where UUID is derived from
/// SHA256(ioc_type || ip || ja4 || first_seen).
fn compute_stix_id(ioc: &IoC) -> String {
    let mut data = Vec::with_capacity(64);
    data.push(ioc.ioc_type);
    data.extend_from_slice(&ioc.ip.to_be_bytes());
    if let Some(ref ja4) = ioc.ja4 {
        data.extend_from_slice(ja4.as_bytes());
    }
    data.extend_from_slice(&ioc.first_seen.to_be_bytes());

    let hash = digest::digest(&digest::SHA256, &data);
    let h = hash.as_ref();

    // Format as UUID-like identifier (deterministic, reproducible)
    format!(
        "indicator--{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}\
         -{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10],
        h[11], h[12], h[13], h[14], h[15],
    )
}

/// Convert an IPv4 u32 to dotted-decimal string.
pub fn ip_to_string(ip: u32) -> String {
    let a = (ip >> 24) & 0xFF;
    let b = (ip >> 16) & 0xFF;
    let c = (ip >> 8) & 0xFF;
    let d = ip & 0xFF;
    format!("{a}.{b}.{c}.{d}")
}

/// Convert a Unix timestamp to ISO 8601 format (YYYY-MM-DDTHH:MM:SSZ).
///
/// Uses Howard Hinnant's civil_from_days algorithm for calendar conversion.
pub fn unix_to_iso8601(ts: u64) -> String {
    let time_of_day = ts % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    let days = (ts / 86400) as i64;

    // Howard Hinnant's civil_from_days algorithm
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ioc(ip: u32, severity: u8, ioc_type: u8) -> IoC {
        IoC {
            ioc_type,
            severity,
            ip,
            ja4: Some("t13d1516h2_8daaf6152771_e5627efa2ab1".to_string()),
            entropy_score: Some(7500),
            description: format!("Test IoC ip={ip}"),
            first_seen: 1700000000,
            confirmations: 3,
            zkp_proof: Vec::new(),
        }
    }

    #[test]
    fn insert_and_query_all() {
        let mut store = ThreatFeedStore::new();
        store.insert(make_ioc(1, 3, 0), 1000);
        store.insert(make_ioc(2, 2, 1), 2000);
        store.insert(make_ioc(3, 4, 0), 3000);

        let result = store.query(&QueryParams::new());
        assert_eq!(result.total, 3);
        assert_eq!(result.items.len(), 3);
    }

    #[test]
    fn query_by_severity() {
        let mut store = ThreatFeedStore::new();
        store.insert(make_ioc(1, 1, 0), 1000);
        store.insert(make_ioc(2, 3, 0), 2000);
        store.insert(make_ioc(3, 4, 0), 3000);

        let params = QueryParams {
            min_severity: Some(3),
            ..QueryParams::new()
        };
        let result = store.query(&params);
        assert_eq!(result.total, 2);
        assert!(result.items.iter().all(|i| i.ioc.severity >= 3));
    }

    #[test]
    fn query_by_type() {
        let mut store = ThreatFeedStore::new();
        store.insert(make_ioc(1, 3, 0), 1000);
        store.insert(make_ioc(2, 3, 1), 2000);
        store.insert(make_ioc(3, 3, 0), 3000);

        let params = QueryParams {
            ioc_type: Some(1),
            ..QueryParams::new()
        };
        let result = store.query(&params);
        assert_eq!(result.total, 1);
        assert_eq!(result.items[0].ioc.ioc_type, 1);
    }

    #[test]
    fn query_since_timestamp() {
        let mut store = ThreatFeedStore::new();
        store.insert(make_ioc(1, 3, 0), 1000);
        store.insert(make_ioc(2, 3, 0), 2000);
        store.insert(make_ioc(3, 3, 0), 3000);

        let params = QueryParams {
            since: Some(2000),
            ..QueryParams::new()
        };
        let result = store.query(&params);
        assert_eq!(result.total, 2);
    }

    #[test]
    fn pagination() {
        let mut store = ThreatFeedStore::new();
        for i in 0..10 {
            store.insert(make_ioc(i, 3, 0), 1000 + u64::from(i));
        }

        let params = QueryParams {
            limit: 3,
            offset: 2,
            ..QueryParams::new()
        };
        let result = store.query(&params);
        assert_eq!(result.total, 10);
        assert_eq!(result.items.len(), 3);
        assert_eq!(result.offset, 2);
    }

    #[test]
    fn stix_id_deterministic() {
        let ioc = make_ioc(0xC0A80001, 3, 0);
        let id1 = compute_stix_id(&ioc);
        let id2 = compute_stix_id(&ioc);
        assert_eq!(id1, id2);
        assert!(id1.starts_with("indicator--"));
    }

    #[test]
    fn ip_conversion() {
        assert_eq!(ip_to_string(0xC0A80001), "192.168.0.1");
        assert_eq!(ip_to_string(0x0A000001), "10.0.0.1");
        assert_eq!(ip_to_string(0), "0.0.0.0");
    }

    #[test]
    fn timestamp_conversion() {
        // 2023-11-14T22:13:20Z
        assert_eq!(unix_to_iso8601(1700000000), "2023-11-14T22:13:20Z");
        // Unix epoch
        assert_eq!(unix_to_iso8601(0), "1970-01-01T00:00:00Z");
    }
}
