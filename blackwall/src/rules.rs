use anyhow::{Context, Result};
use aya::maps::{HashMap, LpmTrie, MapData};
use common::{RuleAction, RuleKey, RuleValue};

/// Manages eBPF maps for IP blocklist, CIDR rules, and expiry.
pub struct RuleManager {
    blocklist: HashMap<MapData, RuleKey, RuleValue>,
    #[allow(dead_code)]
    cidr_rules: LpmTrie<MapData, u32, RuleValue>,
}

impl RuleManager {
    /// Create a new RuleManager from opened eBPF maps.
    pub fn new(
        blocklist: HashMap<MapData, RuleKey, RuleValue>,
        cidr_rules: LpmTrie<MapData, u32, RuleValue>,
    ) -> Self {
        Self {
            blocklist,
            cidr_rules,
        }
    }

    /// Block an IP for `duration_secs` seconds (0 = permanent).
    pub fn block_ip(&mut self, ip: u32, duration_secs: u32) -> Result<()> {
        let key = RuleKey { ip };
        let value = RuleValue {
            action: RuleAction::Drop as u8,
            _pad1: 0,
            _pad2: 0,
            expires_at: if duration_secs == 0 {
                0
            } else {
                current_boot_secs() + duration_secs
            },
        };
        self.blocklist
            .insert(key, value, 0)
            .context("failed to insert blocklist entry")?;
        Ok(())
    }

    /// Explicitly allow an IP (permanent).
    pub fn allow_ip(&mut self, ip: u32) -> Result<()> {
        let key = RuleKey { ip };
        let value = RuleValue {
            action: RuleAction::Pass as u8,
            _pad1: 0,
            _pad2: 0,
            expires_at: 0,
        };
        self.blocklist
            .insert(key, value, 0)
            .context("failed to insert allow entry")?;
        Ok(())
    }

    /// Redirect an IP to the tarpit for `duration_secs`.
    pub fn redirect_to_tarpit(&mut self, ip: u32, duration_secs: u32) -> Result<()> {
        let key = RuleKey { ip };
        let value = RuleValue {
            action: RuleAction::RedirectTarpit as u8,
            _pad1: 0,
            _pad2: 0,
            expires_at: if duration_secs == 0 {
                0
            } else {
                current_boot_secs() + duration_secs
            },
        };
        self.blocklist
            .insert(key, value, 0)
            .context("failed to insert tarpit redirect")?;
        Ok(())
    }

    /// Remove an IP from the blocklist.
    #[allow(dead_code)]
    pub fn remove_ip(&mut self, ip: u32) -> Result<()> {
        let key = RuleKey { ip };
        self.blocklist
            .remove(&key)
            .context("failed to remove blocklist entry")?;
        Ok(())
    }

    /// Add a CIDR rule (e.g., block 10.0.0.0/8).
    #[allow(dead_code)]
    pub fn add_cidr_rule(&mut self, ip: u32, prefix: u32, action: RuleAction) -> Result<()> {
        let lpm_key = aya::maps::lpm_trie::Key::new(prefix, ip);
        let value = RuleValue {
            action: action as u8,
            _pad1: 0,
            _pad2: 0,
            expires_at: 0,
        };
        self.cidr_rules
            .insert(&lpm_key, value, 0)
            .context("failed to insert CIDR rule")?;
        Ok(())
    }

    /// Remove expired rules from the blocklist. Returns count removed.
    pub fn expire_stale_rules(&mut self) -> Result<usize> {
        let now = current_boot_secs();
        let mut expired_keys = Vec::new();

        // Collect keys to expire
        for result in self.blocklist.iter() {
            let (key, value) = result.context("error iterating blocklist")?;
            if value.expires_at != 0 && value.expires_at < now {
                expired_keys.push(key);
            }
        }

        let count = expired_keys.len();
        for key in expired_keys {
            let _ = self.blocklist.remove(&key);
        }

        Ok(count)
    }
}

/// Approximate seconds since boot using CLOCK_BOOTTIME.
fn current_boot_secs() -> u32 {
    let mut ts = nix::libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: valid pointer, CLOCK_BOOTTIME is a valid clock_id
    unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_BOOTTIME, &mut ts) };
    ts.tv_sec as u32
}
