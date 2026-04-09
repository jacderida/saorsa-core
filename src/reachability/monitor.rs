// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com
//
// Unless required by applicable law or agreed to in writing, software
// distributed under these licenses is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

//! Relayer monitor (ADR-014 item 6).
//!
//! Watches for two conditions that require the private node to rebind to a
//! new relay:
//!
//! 1. **K-closest eviction**: the relayer's PeerId drops out of the
//!    K-closest set in the routing table (detected via
//!    `DhtNetworkEvent::KClosestPeersChanged`).
//! 2. **Relay session death**: the QUIC connection underlying the MASQUE
//!    session to the relay closes (detected by polling
//!    `TransportHandle::is_relay_healthy()` on a short interval).
//!
//! On either trigger the monitor re-runs the reachability classification
//! session, which will attempt to acquire a new relay from the next-closest
//! public peer.
//!
//! The monitor is spawned as a background task from `P2PNode::start()` and
//! cancelled via the node's `CancellationToken` on shutdown.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

use crate::PeerId;
use crate::dht_network_manager::{DhtNetworkEvent, DhtNetworkManager};
use crate::reachability::session::{ReachabilityOutcome, run_classification};
use crate::transport_handle::TransportHandle;

/// How often to send a heartbeat Ping to the relay peer.
///
/// 5 seconds is responsive enough for the ADR-014 "must be reachable at all
/// times" constraint (the accepted failover window is 10–30 s) while being
/// light on bandwidth — a DHT Ping/Pong is ~100 bytes round-trip. The Ping
/// doubles as a keepalive: it flows through the MASQUE tunnel, refreshing
/// NAT bindings and confirming the relay peer is responsive.
const RELAY_HEALTH_POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Spawn the relayer monitor as a background task.
///
/// The task runs until `shutdown` is cancelled. It watches for the two
/// rebinding triggers described in the module docs and re-runs the
/// classification session when either fires.
///
/// `relayer_peer_id` is shared with `P2PNode` — the monitor reads it to
/// check K-closest membership, and updates it after a successful rebind.
pub(crate) fn spawn_relayer_monitor(
    dht: Arc<DhtNetworkManager>,
    transport: Arc<TransportHandle>,
    relayer_peer_id: Arc<RwLock<Option<PeerId>>>,
    shutdown: CancellationToken,
) {
    tokio::spawn(async move {
        let mut events_rx = dht.subscribe_events();
        let mut health_interval = tokio::time::interval(RELAY_HEALTH_POLL_INTERVAL);
        // First tick fires immediately — skip it so we don't probe before
        // the relay session has had time to stabilise.
        health_interval.tick().await;

        loop {
            let should_rebind = tokio::select! {
                biased;
                _ = shutdown.cancelled() => {
                    debug!("ADR-014 monitor: shutdown signal received");
                    return;
                }
                event = events_rx.recv() => {
                    match event {
                        Ok(DhtNetworkEvent::KClosestPeersChanged { ref new, .. }) => {
                            check_relayer_in_k_closest(&relayer_peer_id, new).await
                        }
                        // Other events and channel errors are not actionable.
                        _ => false,
                    }
                }
                _ = health_interval.tick() => {
                    heartbeat_relayer(&relayer_peer_id, &dht).await
                }
            };

            if should_rebind {
                rebind(&dht, &transport, &relayer_peer_id).await;
            }
        }
    });
}

/// Returns `true` if the relayer has dropped out of the K-closest set.
async fn check_relayer_in_k_closest(
    relayer_peer_id: &RwLock<Option<PeerId>>,
    new_k_closest: &[PeerId],
) -> bool {
    let guard = relayer_peer_id.read().await;
    let Some(relayer) = guard.as_ref() else {
        return false; // No relayer — nothing to monitor.
    };
    if new_k_closest.contains(relayer) {
        return false; // Relayer is still in K-closest — all good.
    }
    info!(
        "ADR-014 monitor: relayer {:?} dropped out of K-closest set — triggering rebind",
        relayer
    );
    true
}

/// Heartbeat the relayer with a DHT Ping. Returns `true` if the relay
/// appears dead and we should rebind.
///
/// The Ping flows through the MASQUE tunnel, so a successful round-trip
/// confirms:
/// 1. The QUIC connection to the relay is alive (NAT binding refreshed).
/// 2. The relay peer itself is responsive.
///
/// This replaces QUIC-level keepalive configuration — we don't need to
/// modify transport configs because the Ping IS the keepalive. If the app
/// disables QUIC keepalives for normal connections, the relay still stays
/// alive because this function sends real data on every health-check tick.
async fn heartbeat_relayer(
    relayer_peer_id: &RwLock<Option<PeerId>>,
    dht: &DhtNetworkManager,
) -> bool {
    let guard = relayer_peer_id.read().await;
    let Some(relayer) = guard.as_ref() else {
        return false; // No relayer — nothing to heartbeat.
    };
    let relayer = *relayer;
    // Drop the lock before the async Ping to avoid holding it across .await.
    drop(guard);

    match dht
        .send_request(
            &relayer,
            crate::dht_network_manager::DhtNetworkOperation::Ping,
        )
        .await
    {
        Ok(_) => {
            trace!("ADR-014 monitor: relay heartbeat OK");
            false
        }
        Err(e) => {
            info!(
                "ADR-014 monitor: relay heartbeat failed ({}) — triggering rebind",
                e
            );
            true
        }
    }
}

/// Re-run the classification session and update the relayer peer ID.
async fn rebind(
    dht: &DhtNetworkManager,
    transport: &Arc<TransportHandle>,
    relayer_peer_id: &RwLock<Option<PeerId>>,
) {
    info!("ADR-014 monitor: starting rebind — re-running classification");

    let outcome = run_classification(dht, transport).await;

    match outcome {
        ReachabilityOutcome::Public { direct_addresses } => {
            info!(
                "ADR-014 monitor: reclassified as PUBLIC with {} Direct address(es) — clearing relayer",
                direct_addresses.len()
            );
            *relayer_peer_id.write().await = None;
            transport.set_relay_serving_enabled(true);
        }
        ReachabilityOutcome::PrivateWithRelay { relay } => {
            info!(
                "ADR-014 monitor: rebound to new relay — relayer={:?} allocated={}",
                relay.relayer, relay.allocated_public_addr
            );
            *relayer_peer_id.write().await = Some(relay.relayer);
            transport.set_relay_serving_enabled(false);
        }
        ReachabilityOutcome::PrivateNoRelay { reason } => {
            warn!(
                "ADR-014 monitor: rebind failed — no relay acquired: {}",
                reason
            );
            *relayer_peer_id.write().await = None;
            // Stay private, stay disabled — the periodic re-probe (item 7)
            // will retry later.
        }
        ReachabilityOutcome::NoProbers => {
            warn!("ADR-014 monitor: rebind skipped — no probers available");
        }
    }
}
