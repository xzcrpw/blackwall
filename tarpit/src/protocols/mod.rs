//! Deception mesh: multi-protocol honeypot handlers.
//!
//! Routes incoming connections to protocol-specific handlers based on
//! the initial bytes received, enabling SSH, HTTP, MySQL, and DNS deception.

#![allow(dead_code)]

pub mod dns;
pub mod http;
pub mod mysql;

use std::net::SocketAddr;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;

/// Trait for deception protocol services.
/// Each protocol handler describes its identity for logging and config.
pub trait DeceptionService {
    /// Protocol name used in logs and config.
    fn protocol_name(&self) -> &'static str;
    /// Default TCP/UDP port for this service.
    fn default_port(&self) -> u16;
}

/// SSH deception service descriptor.
pub struct SshDeception;
impl DeceptionService for SshDeception {
    fn protocol_name(&self) -> &'static str { "ssh" }
    fn default_port(&self) -> u16 { 22 }
}

/// HTTP deception service descriptor.
pub struct HttpDeception;
impl DeceptionService for HttpDeception {
    fn protocol_name(&self) -> &'static str { "http" }
    fn default_port(&self) -> u16 { 80 }
}

/// MySQL deception service descriptor.
pub struct MysqlDeception;
impl DeceptionService for MysqlDeception {
    fn protocol_name(&self) -> &'static str { "mysql" }
    fn default_port(&self) -> u16 { 3306 }
}

/// DNS canary deception service descriptor.
pub struct DnsDeception;
impl DeceptionService for DnsDeception {
    fn protocol_name(&self) -> &'static str { "dns" }
    fn default_port(&self) -> u16 { 53 }
}

/// Detected incoming protocol based on first bytes.
#[derive(Debug)]
pub enum IncomingProtocol {
    /// SSH client sending a version banner
    Ssh,
    /// HTTP request (GET, POST, etc.)
    Http,
    /// MySQL client connection (starts with specific packet)
    Mysql,
    /// Unknown — default to SSH/bash
    Unknown,
}

/// Identify the protocol from the first few bytes (peek without consuming).
pub fn identify_from_peek(peek_buf: &[u8]) -> IncomingProtocol {
    if peek_buf.is_empty() {
        return IncomingProtocol::Unknown;
    }

    // HTTP methods start with ASCII uppercase letters
    if peek_buf.starts_with(b"GET ")
        || peek_buf.starts_with(b"POST ")
        || peek_buf.starts_with(b"PUT ")
        || peek_buf.starts_with(b"HEAD ")
        || peek_buf.starts_with(b"DELETE ")
        || peek_buf.starts_with(b"OPTIONS ")
        || peek_buf.starts_with(b"CONNECT ")
    {
        return IncomingProtocol::Http;
    }

    // SSH banners start with "SSH-"
    if peek_buf.starts_with(b"SSH-") {
        return IncomingProtocol::Ssh;
    }

    // MySQL client greeting: first 4 bytes are packet length + seq number,
    // and typically sees a capabilities+charset payload
    // MySQL wire protocol initial handshake response starts at offset 4 with
    // capability flags. We detect by checking the 5th byte area for login packet markers.
    // A more reliable approach: if it looks like a MySQL capability packet
    if peek_buf.len() >= 4 {
        let pkt_len = u32::from_le_bytes([peek_buf[0], peek_buf[1], peek_buf[2], 0]) as usize;
        if pkt_len > 0 && pkt_len < 10000 && peek_buf[3] == 1 {
            // Sequence number 1 = client response to server greeting
            return IncomingProtocol::Mysql;
        }
    }

    IncomingProtocol::Unknown
}

/// Route a connection to the appropriate protocol handler.
/// Returns the initial bytes that were peeked for protocol detection.
pub async fn detect_and_peek(
    stream: &mut TcpStream,
) -> anyhow::Result<(IncomingProtocol, Vec<u8>)> {
    let mut peek_buf = vec![0u8; 16];
    let n = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        stream.peek(&mut peek_buf),
    )
    .await
    .map_err(|_| anyhow::anyhow!("peek timeout"))??;

    let protocol = identify_from_peek(&peek_buf[..n]);
    Ok((protocol, peek_buf[..n].to_vec()))
}

/// Handle an HTTP connection with a fake web server response.
pub async fn handle_http_session(
    mut stream: TcpStream,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 4096];
    let n = stream.read(&mut buf).await?;
    let request = String::from_utf8_lossy(&buf[..n]);

    tracing::info!(
        attacker_ip = %addr.ip(),
        protocol = "http",
        request_line = %request.lines().next().unwrap_or(""),
        "HTTP honeypot request"
    );

    http::handle_request(&mut stream, &request).await
}

/// Handle a MySQL connection with a fake database server.
pub async fn handle_mysql_session(
    mut stream: TcpStream,
    addr: SocketAddr,
) -> anyhow::Result<()> {
    tracing::info!(
        attacker_ip = %addr.ip(),
        protocol = "mysql",
        "MySQL honeypot connection"
    );

    mysql::handle_connection(&mut stream, addr).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identify_http_get() {
        let buf = b"GET / HTTP/1.1\r\n";
        assert!(matches!(identify_from_peek(buf), IncomingProtocol::Http));
    }

    #[test]
    fn identify_http_post() {
        let buf = b"POST /api HTTP/1.1\r\n";
        assert!(matches!(identify_from_peek(buf), IncomingProtocol::Http));
    }

    #[test]
    fn identify_ssh() {
        let buf = b"SSH-2.0-OpenSSH";
        assert!(matches!(identify_from_peek(buf), IncomingProtocol::Ssh));
    }

    #[test]
    fn identify_unknown() {
        let buf = b"\x00\x01\x02\x03";
        assert!(matches!(
            identify_from_peek(buf),
            IncomingProtocol::Unknown | IncomingProtocol::Mysql
        ));
    }

    #[test]
    fn empty_is_unknown() {
        assert!(matches!(identify_from_peek(b""), IncomingProtocol::Unknown));
    }
}
