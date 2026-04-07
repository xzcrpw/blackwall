/// Kademlia DHT operations for HiveMind.
///
/// Provides structured peer routing and distributed IoC storage using
/// Kademlia's XOR distance metric. IoC records are stored in the DHT
/// with TTL-based expiry to prevent stale threat data.
use libp2p::{kad, Multiaddr, PeerId, Swarm};
use tracing::{debug, info, warn};

use crate::bootstrap;
use crate::transport::HiveMindBehaviour;

/// Store a threat indicator in the DHT.
///
/// The key is the serialized IoC identifier (e.g., JA4 hash or IP).
/// Record is replicated to the `k` closest peers (Quorum::Majority).
pub fn put_ioc_record(
    swarm: &mut Swarm<HiveMindBehaviour>,
    key_bytes: &[u8],
    value: Vec<u8>,
    local_peer_id: PeerId,
) -> anyhow::Result<kad::QueryId> {
    let key = kad::RecordKey::new(&key_bytes);
    let record = kad::Record {
        key: key.clone(),
        value,
        publisher: Some(local_peer_id),
        expires: None, // Managed by MemoryStore TTL
    };

    let query_id = swarm
        .behaviour_mut()
        .kademlia
        .put_record(record, kad::Quorum::Majority)
        .map_err(|e| anyhow::anyhow!("DHT put failed: {e:?}"))?;

    debug!(?query_id, "DHT PUT initiated for IoC record");
    Ok(query_id)
}

/// Look up a threat indicator in the DHT by key.
pub fn get_ioc_record(
    swarm: &mut Swarm<HiveMindBehaviour>,
    key_bytes: &[u8],
) -> kad::QueryId {
    let key = kad::RecordKey::new(&key_bytes);
    let query_id = swarm.behaviour_mut().kademlia.get_record(key);
    debug!(?query_id, "DHT GET initiated for IoC record");
    query_id
}

/// Add a known peer address to the Kademlia routing table.
///
/// Rejects self-referencing entries (peer pointing to itself).
pub fn add_peer(
    swarm: &mut Swarm<HiveMindBehaviour>,
    peer_id: &PeerId,
    addr: Multiaddr,
    local_peer_id: &PeerId,
) {
    // SECURITY: Reject self-referencing entries
    if peer_id == local_peer_id {
        warn!(%peer_id, "Rejected self-referencing k-bucket entry");
        return;
    }

    // SECURITY: Reject loopback/unspecified addresses
    if !bootstrap::is_routable_addr(&addr) {
        warn!(%peer_id, %addr, "Rejected non-routable address for k-bucket");
        return;
    }

    swarm
        .behaviour_mut()
        .kademlia
        .add_address(peer_id, addr.clone());
    debug!(%peer_id, %addr, "Added peer to Kademlia routing table");
}

/// Initiate a Kademlia bootstrap to populate routing table.
pub fn bootstrap(swarm: &mut Swarm<HiveMindBehaviour>) -> anyhow::Result<kad::QueryId> {
    let query_id = swarm
        .behaviour_mut()
        .kademlia
        .bootstrap()
        .map_err(|e| anyhow::anyhow!("Kademlia bootstrap failed: {e:?}"))?;

    info!(?query_id, "Kademlia bootstrap initiated");
    Ok(query_id)
}

/// Handle a Kademlia event from the swarm event loop.
pub fn handle_kad_event(event: kad::Event) {
    match event {
        kad::Event::OutboundQueryProgressed {
            id, result, step, ..
        } => match result {
            kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(
                kad::PeerRecord { record, .. },
            ))) => {
                info!(
                    ?id,
                    key_len = record.key.as_ref().len(),
                    value_len = record.value.len(),
                    "DHT record found"
                );
            }
            kad::QueryResult::GetRecord(Err(e)) => {
                warn!(?id, ?e, "DHT GET failed");
            }
            kad::QueryResult::PutRecord(Ok(kad::PutRecordOk { key })) => {
                info!(?id, key_len = key.as_ref().len(), "DHT PUT succeeded");
            }
            kad::QueryResult::PutRecord(Err(e)) => {
                warn!(?id, ?e, "DHT PUT failed");
            }
            kad::QueryResult::Bootstrap(Ok(kad::BootstrapOk {
                peer,
                num_remaining,
            })) => {
                info!(
                    ?id,
                    %peer,
                    num_remaining,
                    step = step.count,
                    "Kademlia bootstrap progress"
                );
            }
            kad::QueryResult::Bootstrap(Err(e)) => {
                warn!(?id, ?e, "Kademlia bootstrap failed");
            }
            _ => {
                debug!(?id, "Kademlia query progressed");
            }
        },
        kad::Event::RoutingUpdated {
            peer, addresses, ..
        } => {
            debug!(%peer, addr_count = addresses.len(), "Routing table updated");
        }
        kad::Event::RoutablePeer { peer, address } => {
            debug!(%peer, %address, "New routable peer discovered");
        }
        _ => {}
    }
}
