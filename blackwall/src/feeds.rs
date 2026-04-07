//! Threat feed fetcher: downloads IP blocklists and updates eBPF maps.
//!
//! Supports plain-text feeds (one IP per line, # comments).
//! Popular sources: Firehol level1, abuse.ch feodo, Spamhaus DROP.
//! Handles both single IPs and CIDR ranges (e.g., `10.0.0.0/8`).

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use std::net::Ipv4Addr;
use std::time::Duration;

/// Maximum IPs to ingest from a single feed (prevents memory exhaustion).
const MAX_IPS_PER_FEED: usize = 50_000;
/// HTTP request timeout per feed.
const FEED_TIMEOUT_SECS: u64 = 30;
/// Maximum response body size (10 MB) — prevents memory exhaustion from rogue feeds.
const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;

/// A single entry parsed from a threat feed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FeedEntry {
    /// Single IP address.
    Single(Ipv4Addr),
    /// CIDR range (network address + prefix length).
    Cidr(Ipv4Addr, u8),
}

/// A configured threat feed source.
#[derive(Debug, Clone)]
pub struct FeedSource {
    /// Human-readable name for logging.
    pub name: String,
    /// URL to fetch (must return text/plain with one IP per line).
    pub url: String,
    /// Block duration in seconds (0 = permanent until next refresh).
    pub block_duration_secs: u32,
}

/// Fetch a single feed and return parsed entries (single IPs or CIDR ranges).
pub async fn fetch_feed(source: &FeedSource) -> Result<Vec<FeedEntry>> {
    let https = hyper_rustls::HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    let client = Client::builder(TokioExecutor::new()).build(https);
    let req = Request::get(&source.url)
        .header("User-Agent", "Blackwall/0.1")
        .body(Empty::<Bytes>::new())
        .context("invalid feed URL")?;

    let resp = tokio::time::timeout(
        Duration::from_secs(FEED_TIMEOUT_SECS),
        client.request(req),
    )
    .await
    .context("feed request timed out")?
    .context("feed HTTP request failed")?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "feed {} returned HTTP {}",
            source.name,
            resp.status()
        );
    }

    let body_bytes = Limited::new(resp.into_body(), MAX_BODY_BYTES)
        .collect()
        .await
        .map_err(|e| anyhow::anyhow!("failed to read feed body (possibly exceeded 10MB limit): {}", e))?
        .to_bytes();

    let body = String::from_utf8_lossy(&body_bytes);
    let entries = parse_feed_body(&body);

    if entries.len() >= MAX_IPS_PER_FEED {
        tracing::warn!(
            feed = %source.name,
            max = MAX_IPS_PER_FEED,
            "feed truncated at max entries"
        );
    }

    Ok(entries)
}

/// Parse feed body text into entries (reusable for testing).
fn parse_feed_body(body: &str) -> Vec<FeedEntry> {
    let mut entries = Vec::new();

    for line in body.lines() {
        let trimmed = line.trim();
        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        // Some feeds have "IP<tab>info" or "IP # comment" format
        let ip_str = trimmed.split_whitespace().next().unwrap_or("");

        if let Some(entry) = parse_ip_or_cidr(ip_str) {
            entries.push(entry);
            if entries.len() >= MAX_IPS_PER_FEED {
                break;
            }
        }
    }

    entries
}

/// Parse a single token as either `IP/prefix` (CIDR) or plain IP.
fn parse_ip_or_cidr(s: &str) -> Option<FeedEntry> {
    if let Some((ip_part, prefix_part)) = s.split_once('/') {
        let ip: Ipv4Addr = ip_part.parse().ok()?;
        let prefix: u8 = prefix_part.parse().ok()?;
        if prefix > 32 {
            return None;
        }
        Some(FeedEntry::Cidr(ip, prefix))
    } else {
        let ip: Ipv4Addr = s.parse().ok()?;
        Some(FeedEntry::Single(ip))
    }
}

/// Fetch all configured feeds and return combined unique entries with block durations.
pub async fn fetch_all_feeds(sources: &[FeedSource]) -> Vec<(FeedEntry, u32)> {
    let mut all_entries: Vec<(FeedEntry, u32)> = Vec::new();
    let mut seen_ips = std::collections::HashSet::new();
    let mut seen_cidrs = std::collections::HashSet::new();

    for source in sources {
        match fetch_feed(source).await {
            Ok(entries) => {
                let count = entries.len();
                for entry in entries {
                    let is_new = match &entry {
                        FeedEntry::Single(ip) => seen_ips.insert(*ip),
                        FeedEntry::Cidr(ip, prefix) => seen_cidrs.insert((*ip, *prefix)),
                    };
                    if is_new {
                        all_entries.push((entry, source.block_duration_secs));
                    }
                }
                tracing::info!(
                    feed = %source.name,
                    new_entries = count,
                    total = all_entries.len(),
                    "feed fetched successfully"
                );
            }
            Err(e) => {
                tracing::warn!(
                    feed = %source.name,
                    error = %e,
                    "feed fetch failed — skipping"
                );
            }
        }
    }

    all_entries
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_plain_ip_list() {
        let body = "# Comment line\n\
                     192.168.1.1\n\
                     10.0.0.1\n\
                     \n\
                     ; Another comment\n\
                     172.16.0.1\t# with trailing comment\n\
                     invalid-not-ip\n\
                     256.1.1.1\n";

        let entries = parse_feed_body(body);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0], FeedEntry::Single(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(entries[1], FeedEntry::Single(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(entries[2], FeedEntry::Single(Ipv4Addr::new(172, 16, 0, 1)));
    }

    #[test]
    fn parse_cidr_preserves_prefix() {
        let entries = parse_feed_body("10.0.0.0/8\n192.168.0.0/16\n");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], FeedEntry::Cidr(Ipv4Addr::new(10, 0, 0, 0), 8));
        assert_eq!(entries[1], FeedEntry::Cidr(Ipv4Addr::new(192, 168, 0, 0), 16));
    }

    #[test]
    fn parse_mixed_ips_and_cidrs() {
        let body = "# Spamhaus DROP\n\
                     1.2.3.4\n\
                     10.0.0.0/8\n\
                     5.6.7.8\n\
                     192.168.0.0/24\n";
        let entries = parse_feed_body(body);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0], FeedEntry::Single(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(entries[1], FeedEntry::Cidr(Ipv4Addr::new(10, 0, 0, 0), 8));
        assert_eq!(entries[2], FeedEntry::Single(Ipv4Addr::new(5, 6, 7, 8)));
        assert_eq!(entries[3], FeedEntry::Cidr(Ipv4Addr::new(192, 168, 0, 0), 24));
    }

    #[test]
    fn parse_invalid_cidr_prefix_rejected() {
        let entries = parse_feed_body("10.0.0.0/33\n");
        assert!(entries.is_empty());
    }

    #[test]
    fn feed_source_construction() {
        let src = FeedSource {
            name: "test".into(),
            url: "http://example.com/ips.txt".into(),
            block_duration_secs: 3600,
        };
        assert_eq!(src.block_duration_secs, 3600);
    }
}
