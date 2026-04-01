//! Threat feed fetcher: downloads IP blocklists and updates eBPF maps.
//!
//! Supports plain-text feeds (one IP per line, # comments).
//! Popular sources: Firehol level1, abuse.ch feodo, Spamhaus DROP.

use anyhow::{Context, Result};
use http_body_util::{BodyExt, Empty};
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

/// Fetch a single feed and return parsed IPv4 addresses.
pub async fn fetch_feed(source: &FeedSource) -> Result<Vec<Ipv4Addr>> {
    let client = Client::builder(TokioExecutor::new()).build_http();
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

    let body_bytes = resp
        .into_body()
        .collect()
        .await
        .context("failed to read feed body")?
        .to_bytes();

    let body = String::from_utf8_lossy(&body_bytes);
    let mut ips = Vec::new();

    for line in body.lines() {
        let trimmed = line.trim();
        // Skip comments and empty lines
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        // Some feeds have "IP<tab>info" or "IP # comment" format
        let ip_str = trimmed.split_whitespace().next().unwrap_or("");
        // Also handle CIDR notation by taking just the IP part
        let ip_part = ip_str.split('/').next().unwrap_or("");

        if let Ok(ip) = ip_part.parse::<Ipv4Addr>() {
            ips.push(ip);
            if ips.len() >= MAX_IPS_PER_FEED {
                tracing::warn!(
                    feed = %source.name,
                    max = MAX_IPS_PER_FEED,
                    "feed truncated at max IPs"
                );
                break;
            }
        }
    }

    Ok(ips)
}

/// Fetch all configured feeds and return combined unique IPs with their block durations.
pub async fn fetch_all_feeds(sources: &[FeedSource]) -> Vec<(Ipv4Addr, u32)> {
    let mut all_ips: Vec<(Ipv4Addr, u32)> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for source in sources {
        match fetch_feed(source).await {
            Ok(ips) => {
                let count = ips.len();
                for ip in ips {
                    if seen.insert(ip) {
                        all_ips.push((ip, source.block_duration_secs));
                    }
                }
                tracing::info!(
                    feed = %source.name,
                    new_ips = count,
                    total = all_ips.len(),
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

    all_ips
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

        let mut ips = Vec::new();
        for line in body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                continue;
            }
            let ip_str = trimmed.split_whitespace().next().unwrap_or("");
            let ip_part = ip_str.split('/').next().unwrap_or("");
            if let Ok(ip) = ip_part.parse::<Ipv4Addr>() {
                ips.push(ip);
            }
        }

        assert_eq!(ips.len(), 3);
        assert_eq!(ips[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(ips[1], Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(ips[2], Ipv4Addr::new(172, 16, 0, 1));
    }

    #[test]
    fn parse_cidr_strips_prefix() {
        let line = "10.0.0.0/8";
        let ip_str = line.split_whitespace().next().unwrap_or("");
        let ip_part = ip_str.split('/').next().unwrap_or("");
        let ip: Ipv4Addr = ip_part.parse().unwrap();
        assert_eq!(ip, Ipv4Addr::new(10, 0, 0, 0));
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
