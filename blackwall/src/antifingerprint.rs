//! Anti-fingerprinting: evade attacker reconnaissance.
//!
//! Randomizes observable characteristics to prevent attackers from
//! identifying Blackwall's presence through response timing, error
//! messages, or behavior patterns.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::time::Duration;

/// Jitter range for response timing (ms).
const MIN_JITTER_MS: u64 = 10;
const MAX_JITTER_MS: u64 = 500;

/// Pool of fake server banners for HTTP responses.
const HTTP_SERVER_BANNERS: &[&str] = &[
    "Apache/2.4.58 (Ubuntu)",
    "Apache/2.4.57 (Debian)",
    "nginx/1.24.0",
    "nginx/1.26.0 (Ubuntu)",
    "Microsoft-IIS/10.0",
    "LiteSpeed",
    "openresty/1.25.3.1",
    "Caddy",
];

/// Pool of fake SSH banners.
const SSH_BANNERS: &[&str] = &[
    "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.5",
    "SSH-2.0-OpenSSH_9.7p1 Debian-5",
    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10",
    "SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.6",
    "SSH-2.0-dropbear_2022.82",
];

/// Pool of fake MySQL version strings.
const MYSQL_VERSIONS: &[&str] = &[
    "8.0.36-0ubuntu0.24.04.1",
    "8.0.35-0ubuntu0.22.04.1",
    "8.0.37",
    "5.7.44-log",
    "10.11.6-MariaDB",
];

/// Pool of fake operating system identifiers (for SSH comments).
const OS_COMMENTS: &[&str] = &[
    "Ubuntu-3ubuntu13.5",
    "Debian-5+deb12u1",
    "Ubuntu-1ubuntu3.6",
    "FreeBSD-20240806",
];

/// Anti-fingerprinting profile: randomized per-session.
pub struct AntiFingerprintProfile {
    rng: StdRng,
    /// Selected HTTP server banner for this session
    pub http_banner: &'static str,
    /// Selected SSH banner for this session
    pub ssh_banner: &'static str,
    /// Selected MySQL version for this session
    pub mysql_version: &'static str,
    /// Selected OS comment for this session
    pub os_comment: &'static str,
}

impl AntiFingerprintProfile {
    /// Create a new randomized profile.
    pub fn new() -> Self {
        let mut rng = StdRng::from_entropy();
        let http_banner = HTTP_SERVER_BANNERS[rng.gen_range(0..HTTP_SERVER_BANNERS.len())];
        let ssh_banner = SSH_BANNERS[rng.gen_range(0..SSH_BANNERS.len())];
        let mysql_version = MYSQL_VERSIONS[rng.gen_range(0..MYSQL_VERSIONS.len())];
        let os_comment = OS_COMMENTS[rng.gen_range(0..OS_COMMENTS.len())];

        Self {
            rng,
            http_banner,
            ssh_banner,
            mysql_version,
            os_comment,
        }
    }

    /// Generate a random delay to add to a response (anti-timing-analysis).
    pub fn response_jitter(&mut self) -> Duration {
        Duration::from_millis(self.rng.gen_range(MIN_JITTER_MS..=MAX_JITTER_MS))
    }

    /// Randomly decide whether to add a fake header to an HTTP response.
    pub fn should_add_fake_header(&mut self) -> bool {
        self.rng.gen_ratio(1, 3) // 33% chance
    }

    /// Generate a random fake HTTP header.
    pub fn fake_http_header(&mut self) -> (&'static str, String) {
        let headers = [
            ("X-Powered-By", vec!["PHP/8.3.6", "PHP/8.2.18", "ASP.NET", "Express"]),
            ("X-Cache", vec!["HIT", "MISS", "HIT from cdn-edge-01"]),
            ("Via", vec!["1.1 varnish", "1.1 squid", "HTTP/1.1 cloudfront"]),
        ];
        let (name, values) = &headers[self.rng.gen_range(0..headers.len())];
        let value = values[self.rng.gen_range(0..values.len())].to_string();
        (name, value)
    }

    /// Randomly corrupt a timestamp to prevent timing attacks.
    pub fn fuzz_timestamp(&mut self, base_secs: u64) -> u64 {
        let drift = self.rng.gen_range(0..=5);
        base_secs.wrapping_add(drift)
    }
}

impl Default for AntiFingerprintProfile {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn profile_randomization() {
        let p1 = AntiFingerprintProfile::new();
        // Just verify it doesn't panic and produces valid strings
        assert!(!p1.http_banner.is_empty());
        assert!(p1.ssh_banner.starts_with("SSH-2.0-"));
        assert!(!p1.mysql_version.is_empty());
        assert!(!p1.os_comment.is_empty());
    }

    #[test]
    fn jitter_in_range() {
        let mut profile = AntiFingerprintProfile::new();
        for _ in 0..100 {
            let jitter = profile.response_jitter();
            assert!(jitter.as_millis() >= MIN_JITTER_MS as u128);
            assert!(jitter.as_millis() <= MAX_JITTER_MS as u128);
        }
    }

    #[test]
    fn fake_header_generation() {
        let mut profile = AntiFingerprintProfile::new();
        let (name, value) = profile.fake_http_header();
        assert!(!name.is_empty());
        assert!(!value.is_empty());
    }

    #[test]
    fn timestamp_fuzzing() {
        let mut profile = AntiFingerprintProfile::new();
        let base = 1000u64;
        let fuzzed = profile.fuzz_timestamp(base);
        assert!(fuzzed >= base);
        assert!(fuzzed <= base + 5);
    }
}
