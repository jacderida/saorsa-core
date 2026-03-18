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

//! Integration test: stale QUIC session recovery.
//!
//! Verifies that `send_message` transparently reconnects when the underlying
//! QUIC connection is dead but the channel bookkeeping still considers it
//! alive.  This exercises the reconnect-and-retry path added in
//! `TransportHandle::send_on_channel`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_core::{NodeConfig, P2PNode, PeerId};
use std::time::Duration;
use tokio::time::timeout;

/// Helper: local loopback, ephemeral port, IPv4-only config.
fn test_config() -> NodeConfig {
    NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

/// Helper: start two nodes and connect node_a → node_b.
/// Returns (node_a, node_b, peer_id_of_b).
async fn connected_pair() -> (P2PNode, P2PNode, PeerId) {
    let node_a = P2PNode::new(test_config()).await.unwrap();
    let node_b = P2PNode::new(test_config()).await.unwrap();

    node_a.start().await.unwrap();
    node_b.start().await.unwrap();

    // Brief wait for listeners to bind
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Get node_b's listen address (IPv4)
    let node_b_addr = node_b
        .listen_addrs()
        .await
        .into_iter()
        .find(|a| a.is_ipv4())
        .expect("node_b should have an IPv4 listen address");

    // Connect node_a → node_b
    let channel_id = timeout(Duration::from_secs(2), node_a.connect_peer(&node_b_addr))
        .await
        .expect("connect should not timeout")
        .expect("connect should succeed");

    // Wait for identity exchange to complete
    let peer_b = timeout(
        Duration::from_secs(2),
        node_a.wait_for_peer_identity(&channel_id, Duration::from_secs(2)),
    )
    .await
    .expect("identity exchange should not timeout")
    .expect("identity exchange should succeed");

    assert_eq!(
        &peer_b,
        node_b.peer_id(),
        "Identity exchange should reveal node_b's peer ID"
    );

    (node_a, node_b, peer_b)
}

// ---------------------------------------------------------------------------
// Stale session recovery
// ---------------------------------------------------------------------------

/// After the QUIC session is poisoned, `send_message` should still succeed
/// because `send_on_channel` reconnects transparently.
#[tokio::test]
async fn send_message_recovers_from_stale_quic_session() {
    let (node_a, node_b, peer_b) = connected_pair().await;

    // Sanity: a normal send works before poisoning.
    let pre_result = timeout(
        Duration::from_millis(500),
        node_a.send_message(&peer_b, "test/echo", b"before poison".to_vec()),
    )
    .await
    .expect("pre-poison send should not timeout");
    assert!(
        pre_result.is_ok(),
        "pre-poison send should succeed: {:?}",
        pre_result.unwrap_err()
    );

    // Poison: kill the QUIC connection without touching channel bookkeeping.
    node_a.poison_quic_for_peer(&peer_b).await;

    // Brief pause so the QUIC teardown completes on both sides.
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The next send should trigger reconnect-and-retry inside send_on_channel.
    let post_result = timeout(
        Duration::from_secs(10),
        node_a.send_message(&peer_b, "test/echo", b"after poison".to_vec()),
    )
    .await
    .expect("post-poison send should not timeout");
    assert!(
        post_result.is_ok(),
        "send_message should recover from stale QUIC session: {:?}",
        post_result.unwrap_err()
    );

    node_a.stop().await.unwrap();
    node_b.stop().await.unwrap();
}
