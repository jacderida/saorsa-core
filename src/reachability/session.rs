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

//! End-to-end reachability classification session.
//!
//! Orchestrates the ADR-014 flow: after bootstrap, gather own listen
//! addresses, ask close-group peers to dial them back, classify the results
//! with the 2/3 quorum rule, and — if no address is Direct — acquire a
//! proactive MASQUE relay from the closest public peer.
//!
//! The session is a one-shot invocation driven by [`P2PNode::start()`].
//! Periodic re-classification is handled by the re-probe scheduler (item 7,
//! separate follow-up).

use std::sync::Arc;

use tracing::{debug, info, warn};

use crate::MultiAddr;
use crate::dht_network_manager::DhtNetworkManager;
use crate::reachability::acquisition::{AcquiredRelay, RelayAcquisition, RelayCandidate};
use crate::reachability::classifier::{AddressClassification, Classifier};
use crate::reachability::probe::DialBackOutcome;
use crate::transport_handle::TransportHandle;

/// Maximum number of close-group peers to ask for dial-back probes.
/// Per ADR-014: aim for 3, accept fewer if the network is small.
const MAX_PROBERS: usize = 3;

/// Result of a classification session.
#[derive(Debug, Clone)]
pub(crate) enum ReachabilityOutcome {
    /// At least one listen address was classified as Direct.
    /// The node is publicly reachable and should publish these addresses.
    Public { direct_addresses: Vec<MultiAddr> },
    /// No Direct addresses; a relay was acquired successfully.
    /// The relay-allocated address will be published by the existing DHT
    /// bridge (via the `RelayEstablished` event from saorsa-transport).
    PrivateWithRelay { relay: AcquiredRelay },
    /// No Direct addresses and relay acquisition failed.
    PrivateNoRelay { reason: String },
    /// No probers were available to classify (empty routing table after
    /// bootstrap). Cannot determine reachability — caller should retry after
    /// the routing table is further populated.
    NoProbers,
}

/// Run a full reachability classification session.
///
/// This is the ADR-014 orchestrator: it probes, classifies, and acquires a
/// relay if needed. The caller (`P2PNode::start()`) is responsible for:
///
/// - Calling [`TransportHandle::set_relay_serving_enabled`] based on the
///   outcome (disable for private nodes so they don't accept relay
///   reservations they can't honour).
/// - Emitting [`DhtNetworkEvent::BootstrapComplete`] after the session
///   returns (the "fully addressable" signal).
///
/// When `assume_private` is `true`, the dial-back probes are skipped
/// entirely and the node proceeds directly to relay acquisition. This is
/// useful for devnets and test scenarios where you want to force nodes
/// onto the relay path without relying on actual NAT detection.
pub(crate) async fn run_classification(
    dht: &DhtNetworkManager,
    transport: &Arc<TransportHandle>,
    assume_private: bool,
) -> ReachabilityOutcome {
    if !assume_private {
        // Step 1: Gather candidate listen addresses.
        //
        // Use the observed external addresses (from QUIC OBSERVED_ADDRESS
        // frames) rather than raw listen_addrs — the latter may contain
        // wildcard bind addresses (0.0.0.0) that probers cannot dial.
        // This mirrors the fix in local_dht_node() (PR #70).
        //
        // Fall back to listen_addrs filtered to non-wildcard if no
        // observations are available yet (cold start before any peer
        // connected).
        let observed = transport.observed_external_addresses();
        let listen_addrs: Vec<MultiAddr> = if observed.is_empty() {
            transport
                .listen_addrs()
                .await
                .into_iter()
                .filter(|a| {
                    a.dialable_socket_addr()
                        .is_some_and(|sa| !sa.ip().is_unspecified())
                })
                .collect()
        } else {
            observed.into_iter().map(MultiAddr::quic).collect()
        };
        if listen_addrs.is_empty() {
            warn!("ADR-014: no routable listen addresses available — cannot classify reachability");
            return ReachabilityOutcome::NoProbers;
        }
        info!(
            "ADR-014: starting reachability classification for {} candidate address(es)",
            listen_addrs.len()
        );

        // Step 2: Pick up to MAX_PROBERS close-group peers.
        let own_key = *dht.peer_id().to_bytes();
        let probers = dht.find_closest_nodes_local(&own_key, MAX_PROBERS).await;
        if probers.is_empty() {
            warn!(
                "ADR-014: no close-group peers available as probers — routing table may be empty"
            );
            return ReachabilityOutcome::NoProbers;
        }
        let prober_count = probers.len();
        info!("ADR-014: selected {} prober(s) for dial-back", prober_count);

        // Step 3: Send DialBackRequest to each prober concurrently.
        let mut probe_futures = Vec::with_capacity(prober_count);
        for prober in &probers {
            let addrs = listen_addrs.clone();
            probe_futures.push(dht.send_dial_back_request(&prober.peer_id, addrs));
        }
        let replies: Vec<Vec<DialBackOutcome>> = futures::future::join_all(probe_futures).await;

        // Step 4: Run the classifier.
        let classifier = Classifier::new();
        let classifications = classifier.classify(prober_count, replies);

        let direct_addresses: Vec<MultiAddr> = classifications
            .into_iter()
            .filter(|(_, class)| *class == AddressClassification::Direct)
            .map(|(addr, _)| addr)
            .collect();

        if !direct_addresses.is_empty() {
            info!(
                "ADR-014: classified as PUBLIC — {} Direct address(es)",
                direct_addresses.len()
            );
            return ReachabilityOutcome::Public { direct_addresses };
        }

        info!("ADR-014: no Direct addresses — classified as PRIVATE, acquiring relay");
    } else {
        info!("ADR-014: assume_private is set — skipping classification, acquiring relay");
    }

    // Step 5: Build relay candidates from XOR-closest peers.
    // Per the user's design: we try everyone and private peers reject the
    // reservation request themselves (via relay_serving_enabled gate).
    //
    // Use dialable_addresses_from_node to get type-prioritised addresses
    // (Relay first, then Direct) so the first dialable address per
    // candidate is the best available.
    let own_key = *dht.peer_id().to_bytes();
    let closest = dht.find_closest_nodes_local(&own_key, dht.k_value()).await;
    let candidates: Vec<RelayCandidate> = closest
        .iter()
        .filter_map(|node| {
            let sorted = DhtNetworkManager::dialable_addresses_from_node(node);
            let addr = sorted.into_iter().next()?;
            Some(RelayCandidate::new(node.peer_id, addr))
        })
        .collect();

    if candidates.is_empty() {
        warn!("ADR-014: no dialable relay candidates in routing table");
        return ReachabilityOutcome::PrivateNoRelay {
            reason: "no dialable relay candidates available".to_string(),
        };
    }

    debug!(
        "ADR-014: trying {} relay candidate(s) in XOR order",
        candidates.len()
    );

    // Step 6: Walk candidates using the acquisition coordinator.
    let coordinator = RelayAcquisition::new(Arc::clone(transport));
    match coordinator.acquire(candidates).await {
        Ok(relay) => {
            info!(
                "ADR-014: relay acquired — relayer={:?} allocated={}",
                relay.relayer, relay.allocated_public_addr
            );
            ReachabilityOutcome::PrivateWithRelay { relay }
        }
        Err(e) => {
            warn!("ADR-014: relay acquisition failed: {}", e);
            ReachabilityOutcome::PrivateNoRelay {
                reason: e.to_string(),
            }
        }
    }
}
