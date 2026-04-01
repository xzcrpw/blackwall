use common::{
    TARPIT_BASE_DELAY_MS, TARPIT_JITTER_MS, TARPIT_MAX_CHUNK, TARPIT_MAX_DELAY_MS, TARPIT_MIN_CHUNK,
};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Stream a response to the attacker in random-sized chunks with exponential
/// backoff delay, simulating a slow terminal connection.
pub async fn stream_with_tarpit(stream: &mut TcpStream, response: &str) -> anyhow::Result<()> {
    let bytes = response.as_bytes();
    let mut rng = StdRng::from_entropy();
    let mut offset = 0usize;
    let mut chunk_index = 0u32;

    while offset < bytes.len() {
        // Random chunk size: TARPIT_MIN_CHUNK..=TARPIT_MAX_CHUNK bytes
        let chunk_size = rng.gen_range(TARPIT_MIN_CHUNK..=TARPIT_MAX_CHUNK);
        let end = (offset + chunk_size).min(bytes.len());
        let chunk = &bytes[offset..end];

        stream.write_all(chunk).await?;
        stream.flush().await?;

        offset = end;

        // Exponential backoff + jitter between chunks
        if offset < bytes.len() {
            let exp_delay = TARPIT_BASE_DELAY_MS
                .saturating_mul(1u64.checked_shl(chunk_index).unwrap_or(u64::MAX));
            let capped = exp_delay.min(TARPIT_MAX_DELAY_MS);
            let jitter = rng.gen_range(0..=TARPIT_JITTER_MS);
            let total_delay = capped + jitter;

            tokio::time::sleep(Duration::from_millis(total_delay)).await;
        }

        chunk_index = chunk_index.saturating_add(1);
    }
    Ok(())
}
