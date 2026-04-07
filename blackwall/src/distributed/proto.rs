//! Wire protocol for Blackwall peer-to-peer threat intelligence exchange.
//!
//! Binary protocol with HMAC-SHA256 authentication:
//! - Header: magic(4) + type(1) + payload_len(4) + hmac(32)
//! - Payload: type-specific JSON data
#![allow(dead_code)]
//!
//! The HMAC covers: magic + type + payload_len + payload (everything except
//! the HMAC field itself). A pre-shared key (PSK) must be configured on all
//! peers; connections without valid HMAC are rejected immediately.

use ring::hmac;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Protocol magic bytes: "BWL\x01"
pub const PROTOCOL_MAGIC: [u8; 4] = [0x42, 0x57, 0x4C, 0x01];

/// Size of the HMAC-SHA256 tag appended to the header.
pub const HMAC_SIZE: usize = 32;

/// Total header size: magic(4) + type(1) + payload_len(4) + hmac(32) = 41.
pub const HEADER_SIZE: usize = 4 + 1 + 4 + HMAC_SIZE;

/// Message types exchanged between peers.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Announce presence to peers
    Hello = 0x01,
    /// Share a blocked IP
    BlockedIp = 0x02,
    /// Share a JA4 fingerprint observation
    Ja4Observation = 0x03,
    /// Heartbeat / keepalive
    Heartbeat = 0x04,
    /// Request current threat list
    SyncRequest = 0x05,
    /// Response with threat entries
    SyncResponse = 0x06,
}

impl MessageType {
    /// Convert from u8 to MessageType.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::Hello),
            0x02 => Some(Self::BlockedIp),
            0x03 => Some(Self::Ja4Observation),
            0x04 => Some(Self::Heartbeat),
            0x05 => Some(Self::SyncRequest),
            0x06 => Some(Self::SyncResponse),
            _ => None,
        }
    }
}

/// Hello message payload — node introduces itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HelloPayload {
    /// Node identifier (hostname or UUID)
    pub node_id: String,
    /// Node version
    pub version: String,
    /// Number of currently blocked IPs
    pub blocked_count: u32,
}

/// Blocked IP notification payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockedIpPayload {
    /// The blocked IP address
    pub ip: Ipv4Addr,
    /// Reason for blocking
    pub reason: String,
    /// Block duration in seconds (0 = permanent)
    pub duration_secs: u32,
    /// Confidence score (0-100)
    pub confidence: u8,
}

/// JA4 fingerprint observation payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ja4Payload {
    /// Source IP that sent the TLS ClientHello
    pub src_ip: Ipv4Addr,
    /// JA4 fingerprint string
    pub fingerprint: String,
    /// Classification: "malicious", "benign", "unknown"
    pub classification: String,
}

/// Encode a message to bytes with HMAC-SHA256 authentication.
///
/// Wire format: magic(4) + type(1) + payload_len(4) + hmac(32) + payload
/// HMAC covers: magic + type + payload_len + payload.
pub fn encode_message(msg_type: MessageType, payload: &[u8], key: &hmac::Key) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.extend_from_slice(&PROTOCOL_MAGIC);
    buf.push(msg_type as u8);
    buf.extend_from_slice(&len.to_le_bytes());
    // Compute HMAC over header fields + payload
    let mut signing_ctx = hmac::Context::with_key(key);
    signing_ctx.update(&PROTOCOL_MAGIC);
    signing_ctx.update(&[msg_type as u8]);
    signing_ctx.update(&len.to_le_bytes());
    signing_ctx.update(payload);
    let tag = signing_ctx.sign();
    buf.extend_from_slice(tag.as_ref());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a message header from bytes. Returns (type, payload_length) if valid.
///
/// IMPORTANT: This only validates the header structure and magic bytes.
/// Call `verify_hmac()` after reading the full payload to authenticate.
pub fn decode_header(data: &[u8]) -> Option<(MessageType, usize)> {
    if data.len() < HEADER_SIZE {
        return None;
    }
    if data[..4] != PROTOCOL_MAGIC {
        return None;
    }
    let msg_type = MessageType::from_u8(data[4])?;
    let payload_len = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;
    Some((msg_type, payload_len))
}

/// Extract the HMAC tag from a decoded header.
pub fn extract_hmac(header: &[u8]) -> Option<&[u8]> {
    if header.len() < HEADER_SIZE {
        return None;
    }
    Some(&header[9..9 + HMAC_SIZE])
}

/// Verify HMAC-SHA256 over header fields + payload.
///
/// Returns true if the HMAC is valid, false otherwise.
pub fn verify_hmac(header: &[u8], payload: &[u8], key: &hmac::Key) -> bool {
    if header.len() < HEADER_SIZE {
        return false;
    }
    let tag = &header[9..9 + HMAC_SIZE];
    // Reconstruct signed data: magic + type + payload_len + payload
    let mut verify_data = Vec::with_capacity(9 + payload.len());
    verify_data.extend_from_slice(&header[..9]); // magic + type + payload_len
    verify_data.extend_from_slice(payload);
    hmac::verify(key, &verify_data, tag).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> hmac::Key {
        hmac::Key::new(hmac::HMAC_SHA256, b"test-secret-key-for-blackwall")
    }

    #[test]
    fn roundtrip_message() {
        let key = test_key();
        let payload = b"test data";
        let encoded = encode_message(MessageType::Heartbeat, payload, &key);
        let (msg_type, len) = decode_header(&encoded).expect("decode header");
        assert_eq!(msg_type, MessageType::Heartbeat);
        assert_eq!(len, payload.len());
        assert_eq!(&encoded[HEADER_SIZE..], payload);
        assert!(verify_hmac(&encoded[..HEADER_SIZE], payload, &key));
    }

    #[test]
    fn invalid_magic_rejected() {
        let key = test_key();
        let mut data = encode_message(MessageType::Hello, b"hi", &key);
        data[0] = 0xFF; // Corrupt magic
        assert!(decode_header(&data).is_none());
    }

    #[test]
    fn too_short_rejected() {
        assert!(decode_header(&[0; 5]).is_none());
        assert!(decode_header(&[0; 40]).is_none()); // < HEADER_SIZE (41)
    }

    #[test]
    fn hmac_tamper_detected() {
        let key = test_key();
        let mut encoded = encode_message(MessageType::BlockedIp, b"payload", &key);
        // Tamper with payload
        if let Some(last) = encoded.last_mut() {
            *last ^= 0xFF;
        }
        let (_, len) = decode_header(&encoded).expect("header still valid");
        let payload = &encoded[HEADER_SIZE..HEADER_SIZE + len];
        assert!(!verify_hmac(&encoded[..HEADER_SIZE], payload, &key));
    }

    #[test]
    fn wrong_key_rejected() {
        let key1 = test_key();
        let key2 = hmac::Key::new(hmac::HMAC_SHA256, b"wrong-key");
        let encoded = encode_message(MessageType::Hello, b"data", &key1);
        let (_, len) = decode_header(&encoded).expect("decode");
        let payload = &encoded[HEADER_SIZE..HEADER_SIZE + len];
        assert!(!verify_hmac(&encoded[..HEADER_SIZE], payload, &key2));
    }

    #[test]
    fn all_message_types() {
        for byte in 0x01..=0x06 {
            assert!(MessageType::from_u8(byte).is_some());
        }
        assert!(MessageType::from_u8(0x00).is_none());
        assert!(MessageType::from_u8(0xFF).is_none());
    }

    #[test]
    fn hello_payload_serialization() {
        let hello = HelloPayload {
            node_id: "node-1".into(),
            version: "0.1.0".into(),
            blocked_count: 42,
        };
        let json = serde_json::to_vec(&hello).unwrap();
        let decoded: HelloPayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.node_id, "node-1");
        assert_eq!(decoded.blocked_count, 42);
    }

    #[test]
    fn blocked_ip_payload_serialization() {
        let blocked = BlockedIpPayload {
            ip: Ipv4Addr::new(192, 168, 1, 100),
            reason: "port scan".into(),
            duration_secs: 600,
            confidence: 85,
        };
        let json = serde_json::to_vec(&blocked).unwrap();
        let decoded: BlockedIpPayload = serde_json::from_slice(&json).unwrap();
        assert_eq!(decoded.ip, Ipv4Addr::new(192, 168, 1, 100));
        assert_eq!(decoded.confidence, 85);
    }
}
