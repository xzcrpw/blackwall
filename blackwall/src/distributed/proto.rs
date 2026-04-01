//! Wire protocol for Blackwall peer-to-peer threat intelligence exchange.
//!
//! Simple binary protocol:
//! - Header: magic(4) + type(1) + payload_len(4)
//! - Payload: type-specific data

use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Protocol magic bytes: "BWL\x01"
pub const PROTOCOL_MAGIC: [u8; 4] = [0x42, 0x57, 0x4C, 0x01];

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

/// Encode a message to bytes.
pub fn encode_message(msg_type: MessageType, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(9 + payload.len());
    buf.extend_from_slice(&PROTOCOL_MAGIC);
    buf.push(msg_type as u8);
    buf.extend_from_slice(&len.to_le_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Decode a message header from bytes. Returns (type, payload_length) if valid.
pub fn decode_header(data: &[u8]) -> Option<(MessageType, usize)> {
    if data.len() < 9 {
        return None;
    }
    if data[..4] != PROTOCOL_MAGIC {
        return None;
    }
    let msg_type = MessageType::from_u8(data[4])?;
    let payload_len = u32::from_le_bytes([data[5], data[6], data[7], data[8]]) as usize;
    Some((msg_type, payload_len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_message() {
        let payload = b"test data";
        let encoded = encode_message(MessageType::Heartbeat, payload);
        let (msg_type, len) = decode_header(&encoded).unwrap();
        assert_eq!(msg_type, MessageType::Heartbeat);
        assert_eq!(len, payload.len());
        assert_eq!(&encoded[9..], payload);
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut data = encode_message(MessageType::Hello, b"hi");
        data[0] = 0xFF; // Corrupt magic
        assert!(decode_header(&data).is_none());
    }

    #[test]
    fn too_short_rejected() {
        assert!(decode_header(&[0; 5]).is_none());
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
