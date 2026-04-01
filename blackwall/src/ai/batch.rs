use common::PacketEvent;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Batches PacketEvents by source IP, with time-window flushing.
pub struct EventBatcher {
    /// Events grouped by src_ip, with timestamp of first event.
    pending: HashMap<u32, BatchEntry>,
    /// Max events per batch before forced flush.
    max_batch_size: usize,
    /// Time window before auto-flush.
    window_duration: Duration,
}

struct BatchEntry {
    events: Vec<PacketEvent>,
    first_seen: Instant,
}

impl EventBatcher {
    /// Create a new batcher with given limits.
    pub fn new(max_batch_size: usize, window_secs: u64) -> Self {
        Self {
            pending: HashMap::new(),
            max_batch_size,
            window_duration: Duration::from_secs(window_secs),
        }
    }

    /// Add an event to the batch. Returns `Some(batch)` if the batch is ready
    /// for classification (hit max size).
    pub fn push(&mut self, event: PacketEvent) -> Option<Vec<PacketEvent>> {
        let ip = event.src_ip;
        let entry = self.pending.entry(ip).or_insert_with(|| BatchEntry {
            events: Vec::new(),
            first_seen: Instant::now(),
        });

        entry.events.push(event);

        if entry.events.len() >= self.max_batch_size {
            let batch = self.pending.remove(&ip).map(|e| e.events);
            return batch;
        }

        None
    }

    /// Flush all batches older than the window duration.
    pub fn flush_expired(&mut self) -> Vec<(u32, Vec<PacketEvent>)> {
        let now = Instant::now();
        let mut flushed = Vec::new();
        let mut expired_keys = Vec::new();

        for (&ip, entry) in &self.pending {
            if now.duration_since(entry.first_seen) >= self.window_duration {
                expired_keys.push(ip);
            }
        }

        for ip in expired_keys {
            if let Some(entry) = self.pending.remove(&ip) {
                flushed.push((ip, entry.events));
            }
        }

        flushed
    }
}
