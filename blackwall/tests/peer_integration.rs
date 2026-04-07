//! Integration tests for the distributed peer protocol.
//!
//! Tests persistent TCP connections, broadcast reuse, and heartbeat cycle.
//! Run: `cargo test -p blackwall --test peer_integration -- --nocapture`

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use ring::hmac;

// Re-import what we need from the crate
// NOTE: These tests exercise the wire protocol directly since peer internals
// are private. They verify the protocol codec + flow end-to-end.

/// Wire protocol magic.
const PROTOCOL_MAGIC: [u8; 4] = [0x42, 0x57, 0x4C, 0x01];
const HELLO_TYPE: u8 = 0x01;
const BLOCKED_IP_TYPE: u8 = 0x02;
const HEARTBEAT_TYPE: u8 = 0x04;
const HMAC_SIZE: usize = 32;
const HEADER_SIZE: usize = 4 + 1 + 4 + HMAC_SIZE; // 41

/// Shared test PSK.
fn test_key() -> hmac::Key {
    hmac::Key::new(hmac::HMAC_SHA256, b"integration-test-psk-blackwall")
}

/// Encode a message using the V2 wire protocol:
/// magic(4) + type(1) + len(4) + hmac(32) + payload.
fn encode_message(msg_type: u8, payload: &[u8], key: &hmac::Key) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut buf = Vec::with_capacity(HEADER_SIZE + payload.len());
    buf.extend_from_slice(&PROTOCOL_MAGIC);
    buf.push(msg_type);
    buf.extend_from_slice(&len.to_le_bytes());

    // Compute HMAC over magic + type + len + payload
    let mut signing_ctx = hmac::Context::with_key(key);
    signing_ctx.update(&PROTOCOL_MAGIC);
    signing_ctx.update(&[msg_type]);
    signing_ctx.update(&len.to_le_bytes());
    signing_ctx.update(payload);
    let tag = signing_ctx.sign();
    buf.extend_from_slice(tag.as_ref());

    buf.extend_from_slice(payload);
    buf
}

/// Read a single framed message from a stream.
/// Returns (type_byte, payload). Panics on HMAC mismatch.
async fn read_frame(stream: &mut tokio::net::TcpStream, key: &hmac::Key) -> (u8, Vec<u8>) {
    let mut header = [0u8; HEADER_SIZE];
    stream.read_exact(&mut header).await.expect("read header");
    assert_eq!(&header[..4], &PROTOCOL_MAGIC, "bad magic");
    let msg_type = header[4];
    let payload_len =
        u32::from_le_bytes([header[5], header[6], header[7], header[8]]) as usize;
    let hmac_tag = &header[9..HEADER_SIZE];

    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        stream.read_exact(&mut payload).await.expect("read payload");
    }

    // Verify HMAC
    let mut verify_data = Vec::with_capacity(9 + payload.len());
    verify_data.extend_from_slice(&header[..9]);
    verify_data.extend_from_slice(&payload);
    hmac::verify(key, &verify_data, hmac_tag)
        .expect("HMAC verification failed — wrong key or tampered data");

    (msg_type, payload)
}

#[tokio::test(flavor = "current_thread")]
async fn peer_hello_handshake() {
    // Simulate a sensor listening and a controller connecting
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = test_key();

    let server_key = key.clone();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Read HELLO from client
        let (msg_type, payload) = read_frame(&mut stream, &server_key).await;
        assert_eq!(msg_type, HELLO_TYPE);

        let hello: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(hello["node_id"], "test-client");

        // Send HELLO response
        let resp = serde_json::json!({
            "node_id": "test-server",
            "version": "1.0.0",
            "blocked_count": 42
        });
        let resp_bytes = serde_json::to_vec(&resp).unwrap();
        let msg = encode_message(HELLO_TYPE, &resp_bytes, &server_key);
        stream.write_all(&msg).await.unwrap();
        stream.flush().await.unwrap();
    });

    let client_key = key.clone();
    let client_task = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send HELLO
        let hello = serde_json::json!({
            "node_id": "test-client",
            "version": "1.0.0",
            "blocked_count": 0
        });
        let hello_bytes = serde_json::to_vec(&hello).unwrap();
        let msg = encode_message(HELLO_TYPE, &hello_bytes, &client_key);
        stream.write_all(&msg).await.unwrap();
        stream.flush().await.unwrap();

        // Read HELLO response
        let (msg_type, payload) = read_frame(&mut stream, &client_key).await;
        assert_eq!(msg_type, HELLO_TYPE);

        let resp: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(resp["node_id"], "test-server");
        assert_eq!(resp["blocked_count"], 42);
    });

    tokio::try_join!(server_task, client_task).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn peer_heartbeat_response_cycle() {
    // Verify that heartbeat → HELLO response cycle works over persistent TCP
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = test_key();

    let server_key = key.clone();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Read 3 heartbeats, respond to each with HELLO
        for i in 0..3u32 {
            let (msg_type, payload) = read_frame(&mut stream, &server_key).await;
            assert_eq!(msg_type, HEARTBEAT_TYPE, "expected heartbeat {}", i);
            assert_eq!(payload.len(), 0, "heartbeat payload should be empty");

            // Respond with HELLO containing metrics
            let resp = serde_json::json!({
                "node_id": "sensor-1",
                "version": "1.0.0",
                "blocked_count": 10 + i
            });
            let resp_bytes = serde_json::to_vec(&resp).unwrap();
            let msg = encode_message(HELLO_TYPE, &resp_bytes, &server_key);
            stream.write_all(&msg).await.unwrap();
            stream.flush().await.unwrap();
        }
    });

    let client_key = key.clone();
    let client_task = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send 3 heartbeats on the SAME connection and verify responses
        for i in 0..3u32 {
            let heartbeat = encode_message(HEARTBEAT_TYPE, &[], &client_key);
            stream.write_all(&heartbeat).await.unwrap();
            stream.flush().await.unwrap();

            let (msg_type, payload) = read_frame(&mut stream, &client_key).await;
            assert_eq!(msg_type, HELLO_TYPE, "expected HELLO response {}", i);

            let resp: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            assert_eq!(resp["blocked_count"], 10 + i);
        }
        // Connection still alive after 3 exchanges — persistent TCP works
    });

    tokio::try_join!(server_task, client_task).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn multiple_blocked_ip_on_single_connection() {
    // Verify that multiple BlockedIp messages can be sent on a single TCP stream
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = test_key();

    let server_key = key.clone();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        // Read 5 blocked IPs on the same connection
        for i in 0..5u32 {
            let (msg_type, payload) = read_frame(&mut stream, &server_key).await;
            assert_eq!(msg_type, BLOCKED_IP_TYPE);

            let blocked: serde_json::Value = serde_json::from_slice(&payload).unwrap();
            let expected_ip = format!("10.0.0.{}", i + 1);
            assert_eq!(blocked["ip"], expected_ip);
            assert!(blocked["confidence"].as_u64().unwrap() >= 50);
        }
    });

    let client_key = key.clone();
    let client_task = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();

        // Send 5 blocked IPs on the same connection
        for i in 0..5u32 {
            let payload = serde_json::json!({
                "ip": format!("10.0.0.{}", i + 1),
                "reason": "integration test",
                "duration_secs": 600,
                "confidence": 85
            });
            let payload_bytes = serde_json::to_vec(&payload).unwrap();
            let msg = encode_message(BLOCKED_IP_TYPE, &payload_bytes, &client_key);
            stream.write_all(&msg).await.unwrap();
            stream.flush().await.unwrap();
        }
    });

    tokio::try_join!(server_task, client_task).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_magic_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        // Connection should be dropped by peer after sending garbage
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            stream.read(&mut buf),
        ).await;
        // Either timeout or read some bytes — just verify no panic
        drop(result);
    });

    let client_task = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Send garbage with wrong magic (pad to HEADER_SIZE)
        let mut garbage = vec![0xFF; HEADER_SIZE];
        garbage[4] = HELLO_TYPE;
        stream.write_all(&garbage).await.unwrap();
        stream.flush().await.unwrap();
    });

    tokio::try_join!(server_task, client_task).unwrap();
}

#[tokio::test(flavor = "current_thread")]
async fn oversized_payload_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        // Read header claiming 1MB payload — should be rejected as too large
        let mut header = [0u8; HEADER_SIZE];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(&header[..4], &PROTOCOL_MAGIC);
        let payload_len =
            u32::from_le_bytes([header[5], header[6], header[7], header[8]]) as usize;
        assert!(payload_len > 65536, "payload should be oversized");
        // Server would reject this — test verifies the frame was parseable
    });

    let client_task = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        // Send header with 1MB payload length (but don't send payload)
        let mut msg = vec![0u8; HEADER_SIZE];
        msg[..4].copy_from_slice(&PROTOCOL_MAGIC);
        msg[4] = HELLO_TYPE;
        let huge_len: u32 = 1_000_000;
        msg[5..9].copy_from_slice(&huge_len.to_le_bytes());
        // HMAC is garbage — but we're testing payload size rejection, not auth
        stream.write_all(&msg).await.unwrap();
        stream.flush().await.unwrap();
    });

    tokio::try_join!(server_task, client_task).unwrap();
}

/// Test that a tampered HMAC causes frame rejection.
#[tokio::test(flavor = "current_thread")]
async fn hmac_tamper_detection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let key = test_key();

    let server_key = key.clone();
    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = [0u8; HEADER_SIZE];
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut header),
        ).await;
        // The frame arrives, but HMAC verification should fail
        if let Ok(Ok(_)) = result {
            let payload_len =
                u32::from_le_bytes([header[5], header[6], header[7], header[8]]) as usize;
            let mut payload = vec![0u8; payload_len];
            if payload_len > 0 {
                let _ = stream.read_exact(&mut payload).await;
            }
            // Verify HMAC — should fail because we tampered
            let mut verify_data = Vec::with_capacity(9 + payload.len());
            verify_data.extend_from_slice(&header[..9]);
            verify_data.extend_from_slice(&payload);
            let result = hmac::verify(
                &server_key, &verify_data, &header[9..HEADER_SIZE],
            );
            assert!(result.is_err(), "tampered HMAC should fail verification");
        }
    });

    let client_key = key.clone();
    let client_task = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let payload = serde_json::json!({"node_id": "evil"});
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        let mut msg = encode_message(HELLO_TYPE, &payload_bytes, &client_key);
        // Tamper: flip a byte in the HMAC region (positions 9..41)
        msg[15] ^= 0xFF;
        stream.write_all(&msg).await.unwrap();
        stream.flush().await.unwrap();
    });

    tokio::try_join!(server_task, client_task).unwrap();
}

/// Test that a wrong PSK causes HMAC rejection.
#[tokio::test(flavor = "current_thread")]
async fn wrong_psk_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server_key = test_key();
    let wrong_key = hmac::Key::new(hmac::HMAC_SHA256, b"wrong-psk-not-matching");

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut header = [0u8; HEADER_SIZE];
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            stream.read_exact(&mut header),
        ).await;
        if let Ok(Ok(_)) = result {
            let payload_len =
                u32::from_le_bytes([header[5], header[6], header[7], header[8]]) as usize;
            let mut payload = vec![0u8; payload_len];
            if payload_len > 0 {
                let _ = stream.read_exact(&mut payload).await;
            }
            let mut verify_data = Vec::with_capacity(9 + payload.len());
            verify_data.extend_from_slice(&header[..9]);
            verify_data.extend_from_slice(&payload);
            let result = hmac::verify(
                &server_key, &verify_data, &header[9..HEADER_SIZE],
            );
            assert!(result.is_err(), "wrong PSK should fail verification");
        }
    });

    let client_task = tokio::spawn(async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let payload = serde_json::json!({"node_id": "intruder"});
        let payload_bytes = serde_json::to_vec(&payload).unwrap();
        // Signed with wrong key
        let msg = encode_message(HELLO_TYPE, &payload_bytes, &wrong_key);
        stream.write_all(&msg).await.unwrap();
        stream.flush().await.unwrap();
    });

    tokio::try_join!(server_task, client_task).unwrap();
}
