/// GossipSub operations for HiveMind.
///
/// Provides epidemic broadcast of IoC reports across the mesh.
/// All messages are authenticated (Ed25519 signed) and deduplicated
/// via content-hash message IDs.
use common::hivemind::{self, IoC, ThreatReport};
use libp2p::{gossipsub, PeerId, Swarm};
use tracing::{debug, info, warn};

use crate::transport::HiveMindBehaviour;

/// Subscribe to all HiveMind GossipSub topics.
pub fn subscribe_all(swarm: &mut Swarm<HiveMindBehaviour>) -> anyhow::Result<()> {
    let topics = [
        hivemind::topics::IOC_TOPIC,
        hivemind::topics::JA4_TOPIC,
        hivemind::topics::HEARTBEAT_TOPIC,
        hivemind::topics::A2A_VIOLATIONS_TOPIC,
    ];

    for topic_str in &topics {
        let topic = gossipsub::IdentTopic::new(*topic_str);
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&topic)
            .map_err(|e| anyhow::anyhow!("Failed to subscribe to {topic_str}: {e}"))?;
        info!(topic = topic_str, "Subscribed to GossipSub topic");
    }

    Ok(())
}

/// Publish a ThreatReport to the IoC topic.
pub fn publish_threat_report(
    swarm: &mut Swarm<HiveMindBehaviour>,
    report: &ThreatReport,
) -> anyhow::Result<gossipsub::MessageId> {
    let topic = gossipsub::IdentTopic::new(hivemind::topics::IOC_TOPIC);
    let data = serde_json::to_vec(report)
        .map_err(|e| anyhow::anyhow!("Failed to serialize ThreatReport: {e}"))?;

    // SECURITY: Enforce maximum message size
    if data.len() > hivemind::MAX_MESSAGE_SIZE {
        anyhow::bail!(
            "ThreatReport exceeds max message size ({} > {})",
            data.len(),
            hivemind::MAX_MESSAGE_SIZE
        );
    }

    let msg_id = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, data)
        .map_err(|e| anyhow::anyhow!("Failed to publish ThreatReport: {e}"))?;

    debug!(?msg_id, "Published ThreatReport to IoC topic");
    Ok(msg_id)
}

/// Publish a single IoC to the IoC topic as a lightweight message.
pub fn publish_ioc(
    swarm: &mut Swarm<HiveMindBehaviour>,
    ioc: &IoC,
) -> anyhow::Result<gossipsub::MessageId> {
    let topic = gossipsub::IdentTopic::new(hivemind::topics::IOC_TOPIC);
    let data = serde_json::to_vec(ioc)
        .map_err(|e| anyhow::anyhow!("Failed to serialize IoC: {e}"))?;

    if data.len() > hivemind::MAX_MESSAGE_SIZE {
        anyhow::bail!("IoC message exceeds max size");
    }

    let msg_id = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, data)
        .map_err(|e| anyhow::anyhow!("Failed to publish IoC: {e}"))?;

    debug!(?msg_id, "Published IoC");
    Ok(msg_id)
}

/// Publish a JA4 fingerprint to the JA4 topic.
pub fn publish_ja4(
    swarm: &mut Swarm<HiveMindBehaviour>,
    ja4_fingerprint: &str,
    src_ip: u32,
) -> anyhow::Result<gossipsub::MessageId> {
    let topic = gossipsub::IdentTopic::new(hivemind::topics::JA4_TOPIC);

    let payload = serde_json::json!({
        "ja4": ja4_fingerprint,
        "src_ip": src_ip,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    });
    let data = serde_json::to_vec(&payload)
        .map_err(|e| anyhow::anyhow!("Failed to serialize JA4: {e}"))?;

    let msg_id = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, data)
        .map_err(|e| anyhow::anyhow!("Failed to publish JA4: {e}"))?;

    debug!(?msg_id, ja4 = ja4_fingerprint, "Published JA4 fingerprint");
    Ok(msg_id)
}

/// Publish a raw proof envelope to the A2A violations topic.
///
/// Called when proof data is ingested from the local blackwall-enterprise daemon (optional)
/// via the TCP proof ingestion socket. The data is published verbatim —
/// the hivemind node acts as a relay, not a parser.
pub fn publish_proof_envelope(
    swarm: &mut Swarm<HiveMindBehaviour>,
    data: &[u8],
) -> anyhow::Result<gossipsub::MessageId> {
    let topic = gossipsub::IdentTopic::new(hivemind::topics::A2A_VIOLATIONS_TOPIC);

    // SECURITY: Enforce maximum message size
    if data.len() > hivemind::MAX_MESSAGE_SIZE {
        anyhow::bail!(
            "proof envelope exceeds max message size ({} > {})",
            data.len(),
            hivemind::MAX_MESSAGE_SIZE
        );
    }

    let msg_id = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, data.to_vec())
        .map_err(|e| anyhow::anyhow!("Failed to publish proof envelope: {e}"))?;

    debug!(?msg_id, bytes = data.len(), "Published proof envelope to A2A violations topic");
    Ok(msg_id)
}

/// Configure GossipSub topic scoring to penalize invalid messages.
pub fn configure_topic_scoring(swarm: &mut Swarm<HiveMindBehaviour>) {
    let ioc_topic = gossipsub::IdentTopic::new(hivemind::topics::IOC_TOPIC);

    let params = gossipsub::TopicScoreParams {
        topic_weight: 1.0,
        time_in_mesh_weight: 0.5,
        time_in_mesh_quantum: std::time::Duration::from_secs(1),
        first_message_deliveries_weight: 1.0,
        first_message_deliveries_cap: 20.0,
        // Heavy penalty for invalid/poisoned IoC messages
        invalid_message_deliveries_weight: -100.0,
        invalid_message_deliveries_decay: 0.1,
        ..Default::default()
    };

    swarm
        .behaviour_mut()
        .gossipsub
        .set_topic_params(ioc_topic, params)
        .ok(); // set_topic_params can fail if topic not subscribed yet
}

/// Handle an incoming GossipSub message.
///
/// Returns the deserialized IoC if valid, or None if the message is
/// malformed or fails basic validation.
pub fn handle_gossip_message(
    propagation_source: PeerId,
    message: gossipsub::Message,
) -> Option<IoC> {
    let topic = message.topic.as_str();

    match topic {
        t if t == hivemind::topics::IOC_TOPIC => {
            match serde_json::from_slice::<IoC>(&message.data) {
                Ok(ioc) => {
                    info!(
                        %propagation_source,
                        ioc_type = ioc.ioc_type,
                        severity = ioc.severity,
                        "Received IoC from peer"
                    );
                    // SECURITY: Single-peer IoC — track but don't trust yet
                    // Cross-validation happens in consensus module (Phase 1)
                    Some(ioc)
                }
                Err(e) => {
                    warn!(
                        %propagation_source,
                        error = %e,
                        "Failed to deserialize IoC message — potential poisoning"
                    );
                    None
                }
            }
        }
        t if t == hivemind::topics::JA4_TOPIC => {
            debug!(
                %propagation_source,
                data_len = message.data.len(),
                "Received JA4 fingerprint from peer"
            );
            None // JA4 messages are informational, not IoC
        }
        t if t == hivemind::topics::HEARTBEAT_TOPIC => {
            debug!(%propagation_source, "Peer heartbeat received");
            None
        }
        t if t == hivemind::topics::A2A_VIOLATIONS_TOPIC => {
            info!(
                %propagation_source,
                bytes = message.data.len(),
                "Received A2A violation proof from peer"
            );
            // A2A proofs are informational — logged and counted by metrics.
            // Future: store for local policy enforcement or cross-validation.
            None
        }
        _ => {
            warn!(
                %propagation_source,
                topic,
                "Unknown GossipSub topic — ignoring"
            );
            None
        }
    }
}
