//! MySQL honeypot: fake database server.
//!
//! Implements enough of the MySQL wire protocol to capture credentials
//! and log attacker queries. Simulates MySQL 8.0 authentication.

use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// MySQL server version string.
const SERVER_VERSION: &[u8] = b"8.0.36-0ubuntu0.24.04.1";
/// Connection ID counter (fake, per-session).
const CONNECTION_ID: u32 = 42;
/// Maximum commands to accept before disconnect.
const MAX_COMMANDS: u32 = 50;
/// Read timeout per command.
const CMD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Handle a MySQL client connection.
pub async fn handle_connection(stream: &mut TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
    // Step 1: Send server greeting (HandshakeV10)
    send_server_greeting(stream).await?;

    // Step 2: Read client auth response
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(CMD_TIMEOUT, stream.read(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("auth timeout"))??;

    if n < 36 {
        // Too short for a real auth packet
        return Ok(());
    }

    // Extract username from auth packet (starts at offset 36 in Handshake Response)
    let username = extract_null_string(&buf[36..n]);
    tracing::info!(
        attacker_ip = %addr.ip(),
        username = %username,
        "MySQL auth attempt captured"
    );

    // Step 3: Send OK (always succeed — capture what they do next)
    send_ok_packet(stream, 2).await?;

    // Step 4: Command loop — capture queries
    let mut cmd_count = 0u32;
    loop {
        if cmd_count >= MAX_COMMANDS {
            tracing::info!(attacker_ip = %addr.ip(), "MySQL max commands reached");
            break;
        }

        let n = match tokio::time::timeout(CMD_TIMEOUT, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => n,
            _ => break,
        };

        if n < 5 {
            continue;
        }

        let cmd_type = buf[4];
        match cmd_type {
            // COM_QUERY (0x03)
            0x03 => {
                let query = String::from_utf8_lossy(&buf[5..n]);
                tracing::info!(
                    attacker_ip = %addr.ip(),
                    query = %query,
                    "MySQL query captured"
                );

                // Send a fake empty result set for all queries
                send_empty_result(stream, buf[3].wrapping_add(1)).await?;
            }
            // COM_QUIT (0x01)
            0x01 => break,
            // COM_INIT_DB (0x02) — database selection
            0x02 => {
                let db_name = String::from_utf8_lossy(&buf[5..n]);
                tracing::info!(
                    attacker_ip = %addr.ip(),
                    database = %db_name,
                    "MySQL database select"
                );
                send_ok_packet(stream, buf[3].wrapping_add(1)).await?;
            }
            // Anything else — OK
            _ => {
                send_ok_packet(stream, buf[3].wrapping_add(1)).await?;
            }
        }

        cmd_count += 1;
    }

    Ok(())
}

/// Send the MySQL server greeting packet (HandshakeV10).
async fn send_server_greeting(stream: &mut TcpStream) -> anyhow::Result<()> {
    let mut payload = Vec::with_capacity(128);

    // Protocol version
    payload.push(10); // HandshakeV10

    // Server version string (null-terminated)
    payload.extend_from_slice(SERVER_VERSION);
    payload.push(0);

    // Connection ID (4 bytes LE)
    payload.extend_from_slice(&CONNECTION_ID.to_le_bytes());

    // Auth plugin data part 1 (8 bytes — scramble)
    payload.extend_from_slice(&[0x3a, 0x23, 0x5c, 0x7d, 0x1e, 0x48, 0x5b, 0x6f]);

    // Filler
    payload.push(0);

    // Capability flags lower 2 bytes (CLIENT_PROTOCOL_41, CLIENT_SECURE_CONNECTION)
    payload.extend_from_slice(&[0xff, 0xf7]);

    // Character set (utf8mb4 = 45)
    payload.push(45);

    // Status flags (SERVER_STATUS_AUTOCOMMIT)
    payload.extend_from_slice(&[0x02, 0x00]);

    // Capability flags upper 2 bytes
    payload.extend_from_slice(&[0xff, 0x81]);

    // Auth plugin data length
    payload.push(21);

    // Reserved (10 zero bytes)
    payload.extend_from_slice(&[0; 10]);

    // Auth plugin data part 2 (12 bytes + null)
    payload.extend_from_slice(&[0x6a, 0x4e, 0x21, 0x30, 0x55, 0x2a, 0x3b, 0x7c, 0x45, 0x19, 0x22, 0x38]);
    payload.push(0);

    // Auth plugin name
    payload.extend_from_slice(b"mysql_native_password");
    payload.push(0);

    // Packet header: length (3 bytes LE) + sequence number (1 byte)
    let len = payload.len() as u32;
    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&len.to_le_bytes()[..3]);
    packet.push(0); // Sequence 0
    packet.extend_from_slice(&payload);

    stream.write_all(&packet).await?;
    stream.flush().await?;

    Ok(())
}

/// Send a MySQL OK packet.
async fn send_ok_packet(stream: &mut TcpStream, seq: u8) -> anyhow::Result<()> {
    let payload = [
        0x00, // OK marker
        0x00, // affected_rows
        0x00, // last_insert_id
        0x02, 0x00, // status flags (SERVER_STATUS_AUTOCOMMIT)
        0x00, 0x00, // warnings
    ];

    let len = payload.len() as u32;
    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&len.to_le_bytes()[..3]);
    packet.push(seq);
    packet.extend_from_slice(&payload);

    stream.write_all(&packet).await?;
    stream.flush().await?;

    Ok(())
}

/// Send an empty result set (column count 0).
async fn send_empty_result(stream: &mut TcpStream, seq: u8) -> anyhow::Result<()> {
    // Column count packet (0 columns = empty result)
    let col_payload = [0x00]; // 0 columns
    let len = col_payload.len() as u32;
    let mut packet = Vec::with_capacity(4 + col_payload.len());
    packet.extend_from_slice(&len.to_le_bytes()[..3]);
    packet.push(seq);
    packet.extend_from_slice(&col_payload);

    // EOF packet
    let eof_payload = [0xfe, 0x00, 0x00, 0x02, 0x00]; // EOF marker + warnings + status
    let eof_len = eof_payload.len() as u32;
    packet.extend_from_slice(&eof_len.to_le_bytes()[..3]);
    packet.push(seq.wrapping_add(1));
    packet.extend_from_slice(&eof_payload);

    stream.write_all(&packet).await?;
    stream.flush().await?;

    Ok(())
}

/// Extract a null-terminated string from a byte slice.
fn extract_null_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len().min(64));
    String::from_utf8_lossy(&data[..end]).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_username() {
        let data = b"admin\x00extra_data";
        assert_eq!(extract_null_string(data), "admin");
    }

    #[test]
    fn extract_empty_string() {
        let data = b"\x00rest";
        assert_eq!(extract_null_string(data), "");
    }

    #[test]
    fn extract_no_null() {
        let data = b"root";
        assert_eq!(extract_null_string(data), "root");
    }
}
