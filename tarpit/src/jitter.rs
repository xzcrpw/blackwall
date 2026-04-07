use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

/// Simulated network latency range (ms) — mimics real SSH/TCP jitter.
/// Real SSH over decent link: ~5-40ms RTT. Over slow/VPN: up to ~120ms.
const NET_LATENCY_MIN_MS: u64 = 4;
const NET_LATENCY_MAX_MS: u64 = 45;

/// For large outputs, pipe-buffer sized chunks with minimal inter-chunk delay.
const PIPE_BUF_MIN: usize = 512;
const PIPE_BUF_MAX: usize = 4096;
const PIPE_DELAY_MIN_MS: u64 = 1;
const PIPE_DELAY_MAX_MS: u64 = 8;

/// Threshold: outputs smaller than this are "simple commands" (ls, pwd, cat
/// small file) — delivered as a single write after one network-latency pause.
const SMALL_OUTPUT_THRESHOLD: usize = 256;

/// Threshold: outputs larger than this are "pipe/stream" style (grep, find,
/// log tailing) — delivered in pipe-buffer chunks.
const LARGE_OUTPUT_THRESHOLD: usize = 1024;

/// Stream a response to the attacker mimicking realistic terminal behavior.
///
/// Three modes based on response size:
/// - **Small** (<256B): single write after network-latency pause (like `ls`, `pwd`)
/// - **Medium** (256-1024B): line-by-line with network jitter (like `cat /etc/passwd`)
/// - **Large** (>1024B): pipe-buffer chunks with minimal delay (like `grep -r`)
pub async fn stream_with_tarpit(stream: &mut TcpStream, response: &str) -> anyhow::Result<()> {
    let bytes = response.as_bytes();
    let mut rng = StdRng::from_entropy();

    if bytes.is_empty() {
        return Ok(());
    }

    if bytes.len() <= SMALL_OUTPUT_THRESHOLD {
        // Small output: single flush, one realistic latency pause
        let delay = rng.gen_range(NET_LATENCY_MIN_MS..=NET_LATENCY_MAX_MS);
        tokio::time::sleep(Duration::from_millis(delay)).await;
        stream.write_all(bytes).await?;
        stream.flush().await?;
    } else if bytes.len() <= LARGE_OUTPUT_THRESHOLD {
        // Medium output: line-by-line with network jitter between lines
        stream_line_by_line(stream, response, &mut rng).await?;
    } else {
        // Large output: pipe-buffer sized chunks with minimal delay
        stream_pipe_buffer(stream, bytes, &mut rng).await?;
    }

    Ok(())
}

/// Stream line-by-line with realistic inter-line network jitter.
/// Mimics `cat /etc/passwd` or `ls -la` over SSH — each line arrives
/// after a small network-latency delay.
async fn stream_line_by_line(
    stream: &mut TcpStream,
    response: &str,
    rng: &mut StdRng,
) -> anyhow::Result<()> {
    let lines: Vec<&str> = response.split_inclusive('\n').collect();
    let line_count = lines.len();

    for (i, line) in lines.iter().enumerate() {
        stream.write_all(line.as_bytes()).await?;

        // Flush + delay between lines, but not after the last one
        if i + 1 < line_count {
            stream.flush().await?;
            let delay = rng.gen_range(NET_LATENCY_MIN_MS..=NET_LATENCY_MAX_MS);
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }
    stream.flush().await?;
    Ok(())
}

/// Stream in pipe-buffer sized chunks with minimal delay.
/// Mimics large output piped through SSH — kernel sends TCP segments
/// as fast as the congestion window allows, with tiny inter-segment gaps.
async fn stream_pipe_buffer(
    stream: &mut TcpStream,
    bytes: &[u8],
    rng: &mut StdRng,
) -> anyhow::Result<()> {
    let mut offset = 0usize;

    // Initial latency before first chunk (command processing time)
    let initial = rng.gen_range(NET_LATENCY_MIN_MS..=NET_LATENCY_MAX_MS * 2);
    tokio::time::sleep(Duration::from_millis(initial)).await;

    while offset < bytes.len() {
        let chunk_size = rng.gen_range(PIPE_BUF_MIN..=PIPE_BUF_MAX);
        let end = (offset + chunk_size).min(bytes.len());

        stream.write_all(&bytes[offset..end]).await?;
        offset = end;

        if offset < bytes.len() {
            stream.flush().await?;
            let delay = rng.gen_range(PIPE_DELAY_MIN_MS..=PIPE_DELAY_MAX_MS);
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
    }
    stream.flush().await?;
    Ok(())
}
