/// Gradient sharing via GossipSub for federated learning.
///
/// Publishes FHE-encrypted gradient updates to the gradient topic,
/// and deserializes incoming gradient messages from peers.
///
/// # Privacy Invariant
/// Only FHE-encrypted payloads are transmitted. Raw gradients
/// NEVER leave the node boundary.
use common::hivemind::{self, GradientUpdate};
use libp2p::{gossipsub, PeerId, Swarm};
use tracing::{debug, info, warn};

use crate::transport::HiveMindBehaviour;

/// Publish encrypted gradient update to the federated learning topic.
///
/// # Arguments
/// * `swarm` — The libp2p swarm for message transmission
/// * `peer_pubkey` — This node's 32-byte Ed25519 public key
/// * `round_id` — Current aggregation round number
/// * `encrypted_gradients` — FHE-encrypted gradient payload (from `FheContext`)
pub fn publish_gradients(
    swarm: &mut Swarm<HiveMindBehaviour>,
    peer_pubkey: &[u8; 32],
    round_id: u64,
    encrypted_gradients: Vec<u8>,
) -> anyhow::Result<gossipsub::MessageId> {
    let topic = gossipsub::IdentTopic::new(hivemind::topics::GRADIENT_TOPIC);

    // SECURITY: Enforce maximum gradient payload size
    if encrypted_gradients.len() > hivemind::FL_MAX_GRADIENT_SIZE {
        anyhow::bail!(
            "Encrypted gradient payload too large ({} > {})",
            encrypted_gradients.len(),
            hivemind::FL_MAX_GRADIENT_SIZE
        );
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let update = GradientUpdate {
        peer_pubkey: *peer_pubkey,
        round_id,
        encrypted_gradients,
        timestamp: now,
    };

    let data = serde_json::to_vec(&update)
        .map_err(|e| anyhow::anyhow!("Failed to serialize GradientUpdate: {e}"))?;

    if data.len() > hivemind::MAX_MESSAGE_SIZE {
        anyhow::bail!(
            "Serialized gradient message exceeds max message size ({} > {})",
            data.len(),
            hivemind::MAX_MESSAGE_SIZE
        );
    }

    let msg_id = swarm
        .behaviour_mut()
        .gossipsub
        .publish(topic, data)
        .map_err(|e| anyhow::anyhow!("Failed to publish gradients: {e}"))?;

    info!(
        ?msg_id,
        round_id,
        "Published encrypted gradient update"
    );
    Ok(msg_id)
}

/// Handle an incoming gradient message from GossipSub.
///
/// Deserializes and validates the gradient update. Returns None if
/// the message is malformed or invalid.
pub fn handle_gradient_message(
    propagation_source: PeerId,
    data: &[u8],
) -> Option<GradientUpdate> {
    match serde_json::from_slice::<GradientUpdate>(data) {
        Ok(update) => {
            // Basic validation
            if update.encrypted_gradients.is_empty() {
                warn!(
                    %propagation_source,
                    "Empty gradient payload — ignoring"
                );
                return None;
            }

            if update.encrypted_gradients.len() > hivemind::FL_MAX_GRADIENT_SIZE {
                warn!(
                    %propagation_source,
                    size = update.encrypted_gradients.len(),
                    max = hivemind::FL_MAX_GRADIENT_SIZE,
                    "Gradient payload exceeds maximum size — ignoring"
                );
                return None;
            }

            debug!(
                %propagation_source,
                round_id = update.round_id,
                payload_size = update.encrypted_gradients.len(),
                "Received gradient update from peer"
            );
            Some(update)
        }
        Err(e) => {
            warn!(
                %propagation_source,
                error = %e,
                "Failed to deserialize gradient message"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_valid_gradient_message() {
        let update = GradientUpdate {
            peer_pubkey: [1u8; 32],
            round_id: 42,
            encrypted_gradients: vec![0xDE, 0xAD, 0xBE, 0xEF],
            timestamp: 1700000000,
        };
        let data = serde_json::to_vec(&update).expect("serialize");
        let peer_id = PeerId::random();
        let result = handle_gradient_message(peer_id, &data);
        assert!(result.is_some());
        let parsed = result.expect("should parse");
        assert_eq!(parsed.round_id, 42);
        assert_eq!(parsed.peer_pubkey, [1u8; 32]);
    }

    #[test]
    fn rejects_empty_payload() {
        let update = GradientUpdate {
            peer_pubkey: [1u8; 32],
            round_id: 1,
            encrypted_gradients: Vec::new(),
            timestamp: 1700000000,
        };
        let data = serde_json::to_vec(&update).expect("serialize");
        let peer_id = PeerId::random();
        assert!(handle_gradient_message(peer_id, &data).is_none());
    }

    #[test]
    fn rejects_malformed_json() {
        let peer_id = PeerId::random();
        assert!(handle_gradient_message(peer_id, b"not json").is_none());
    }

    #[test]
    fn rejects_oversized_payload() {
        let update = GradientUpdate {
            peer_pubkey: [1u8; 32],
            round_id: 1,
            encrypted_gradients: vec![0u8; hivemind::FL_MAX_GRADIENT_SIZE + 1],
            timestamp: 1700000000,
        };
        let data = serde_json::to_vec(&update).expect("serialize");
        let peer_id = PeerId::random();
        assert!(handle_gradient_message(peer_id, &data).is_none());
    }
}
