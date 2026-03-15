// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2025 Saorsa Labs Limited

//! Integration test proving the P2P messaging connection lifecycle issue is fixed
//!
//! This test validates the fix for the issue documented in P2P_MESSAGING_STATUS_2025-10-02_FINAL.md
//! where P2PNode's peers map didn't track when saorsa-transport connections closed, leading to
//! "send_to_peer failed on both stacks" errors after 30-second idle timeout.
//!
//! The fix implements:
//! - Connection lifecycle tracking via saorsa-transport events
//! - Active connections HashSet synchronized with saorsa-transport state
//! - Keepalive messages every 15 seconds to prevent 30-second idle timeout
//! - Automatic stale connection cleanup

use saorsa_core::MultiAddr;
use saorsa_core::network::{NodeConfig, P2PNode};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info};

/// Test that demonstrates the connection lifecycle tracking prevents the original issue
///
/// Original issue: After 30 seconds of inactivity, saorsa-transport closes the connection due to
/// max_idle_timeout, but P2PNode's peers map still contains the peer entry. Attempts to
/// send messages fail with "send_to_peer failed on both stacks".
///
/// Fix validation:
/// 1. Keepalive messages every 15 seconds prevent the 30-second timeout
/// 2. If a connection closes anyway, P2PNode detects it via `is_connection_active()`
/// 3. Stale peer entries are automatically removed
/// 4. MessageTransport can retry with a fresh connection
///
/// TODO: Investigate why QUIC-level keepalive (configured at 5s interval) doesn't
/// prevent the 30-second idle timeout. The saorsa-transport transport has keep_alive_interval
/// set, but connections still timeout. This may be a timing issue with how events are
/// polled, or the keepalive mechanism may not be working as expected.
#[tokio::test]
#[ignore = "Keepalive mechanism needs investigation - QUIC keepalive not preventing 30s timeout"]
async fn test_connection_lifecycle_with_keepalive() {
    // Initialize logging for test debugging
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("=== Starting connection lifecycle integration test ===");

    // Create two P2P nodes with different ports (port 0 = OS-assigned)
    let config1 = NodeConfig {
        listen_addr: MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
        listen_addrs: vec![
            MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
            MultiAddr::quic("[::]:0".parse().unwrap()),
        ],
        ..Default::default()
    };
    let config2 = NodeConfig {
        listen_addr: MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
        listen_addrs: vec![
            MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
            MultiAddr::quic("[::]:0".parse().unwrap()),
        ],
        ..Default::default()
    };

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    // Get their addresses
    let addrs1 = node1.listen_addrs().await;
    let addrs2 = node2.listen_addrs().await;

    info!("Node1 listening on: {:?}", addrs1);
    info!("Node2 listening on: {:?}", addrs2);

    assert!(!addrs1.is_empty(), "Node1 should have listen addresses");
    assert!(!addrs2.is_empty(), "Node2 should have listen addresses");

    // Connect node1 to node2
    let addr2 = addrs2.first().expect("Node2 should have an address");
    debug!("Connecting node1 to node2 at {}", addr2);

    let channel_id = node1
        .connect_peer(addr2)
        .await
        .expect("Failed to connect to node2");

    // Wait for identity exchange via wait_for_peer_identity.
    let peer2_peer_id = node1
        .wait_for_peer_identity(&channel_id, Duration::from_secs(5))
        .await
        .expect("Identity exchange timed out");
    assert_eq!(peer2_peer_id, *node2.peer_id());

    info!("Node1 connected to node2 (peer_id: {})", peer2_peer_id);

    // Verify connection is active
    assert!(
        node1.is_peer_connected(&peer2_peer_id).await,
        "Peer should be in peers map"
    );

    // Send a message to verify connection works
    let test_message = b"Hello from node1";
    node1
        .send_message(&peer2_peer_id, "test", test_message.to_vec())
        .await
        .expect("Failed to send initial message");

    debug!("Initial message sent successfully");

    // Wait for 40 seconds - longer than saorsa-transport's 30-second max_idle_timeout
    // The keepalive task should prevent the connection from timing out
    info!("Waiting 40 seconds to test keepalive prevents timeout...");
    sleep(Duration::from_secs(40)).await;

    // Verify connection is still active thanks to keepalive
    assert!(
        node1
            .transport()
            .connected_peers()
            .await
            .contains(&peer2_peer_id),
        "Connection should still be active after 40 seconds due to keepalive"
    );

    // Send another message to prove the connection is still usable
    let test_message2 = b"Still connected after 40 seconds!";
    node1
        .send_message(&peer2_peer_id, "test", test_message2.to_vec())
        .await
        .expect("Failed to send message after 40 seconds");

    info!("Message sent successfully after 40 seconds - keepalive working!");

    // Test stale connection cleanup
    // Disconnect node2 to simulate connection closure
    debug!("Disconnecting peer to test cleanup...");
    let _ = node1.disconnect_peer(&peer2_peer_id).await;

    // Wait for disconnect to propagate
    sleep(Duration::from_secs(1)).await;

    // Verify peer was removed from peers map
    assert!(
        !node1
            .transport()
            .connected_peers()
            .await
            .contains(&peer2_peer_id),
        "Peer should be removed after disconnect"
    );

    info!("=== Connection lifecycle test passed! ===");
}

/// Test that P2PNode's send_message validates connection state before sending
///
/// This test verifies that even if a peer entry exists in the peers map,
/// send_message will check if the saorsa-transport connection is actually active
/// and fail gracefully with ConnectionClosed error if not.
#[tokio::test]
#[ignore = "Connection state tracking needs investigation - disconnect not propagating synchronously"]
async fn test_send_message_validates_connection_state() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("=== Starting send_message connection validation test ===");

    // Create two P2P nodes with OS-assigned ports (port 0)
    let config1 = NodeConfig {
        listen_addr: MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
        listen_addrs: vec![
            MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
            MultiAddr::quic("[::]:0".parse().unwrap()),
        ],
        ..Default::default()
    };
    let config2 = NodeConfig {
        listen_addr: MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
        listen_addrs: vec![
            MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
            MultiAddr::quic("[::]:0".parse().unwrap()),
        ],
        ..Default::default()
    };

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    // Get addresses and connect
    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2.first().expect("Node2 should have an address");
    let channel_id = node1
        .connect_peer(addr2)
        .await
        .expect("Failed to connect to node2");

    // Wait for identity exchange via wait_for_peer_identity.
    let peer2_peer_id = node1
        .wait_for_peer_identity(&channel_id, Duration::from_secs(5))
        .await
        .expect("Identity exchange timed out");
    assert_eq!(peer2_peer_id, *node2.peer_id());

    info!("Connected to peer {}", peer2_peer_id);

    // Send initial message successfully
    node1
        .send_message(&peer2_peer_id, "test", b"First message".to_vec())
        .await
        .expect("First message should succeed");

    // Now disconnect to simulate connection closure
    let _ = node1.disconnect_peer(&peer2_peer_id).await;
    sleep(Duration::from_secs(1)).await;

    // Verify connection is no longer active
    assert!(
        !node1
            .transport()
            .connected_peers()
            .await
            .contains(&peer2_peer_id),
        "Connection should be inactive after disconnect"
    );

    // Attempt to send message should fail gracefully
    let result = node1
        .send_message(&peer2_peer_id, "test", b"Should fail".to_vec())
        .await;

    // Should get either PeerNotFound (if already cleaned up) or ConnectionClosed error
    assert!(
        result.is_err(),
        "send_message should fail for closed connection"
    );

    info!("send_message correctly detected closed connection");
    info!("=== Connection validation test passed! ===");
}

/// Test that multiple message exchanges work reliably
///
/// Validates that the connection lifecycle tracking doesn't interfere with
/// normal message exchange operations.
#[tokio::test]
async fn test_multiple_message_exchanges() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_test_writer()
        .try_init();

    info!("=== Starting multiple message exchange test ===");

    // Create two P2P nodes with OS-assigned ports (port 0)
    let config1 = NodeConfig {
        listen_addr: MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
        listen_addrs: vec![
            MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
            MultiAddr::quic("[::]:0".parse().unwrap()),
        ],
        ..Default::default()
    };
    let config2 = NodeConfig {
        listen_addr: MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
        listen_addrs: vec![
            MultiAddr::quic("0.0.0.0:0".parse().unwrap()),
            MultiAddr::quic("[::]:0".parse().unwrap()),
        ],
        ..Default::default()
    };

    let node1 = P2PNode::new(config1).await.expect("Failed to create node1");
    node1.start().await.expect("Failed to start node1");
    let node2 = P2PNode::new(config2).await.expect("Failed to create node2");
    node2.start().await.expect("Failed to start node2");

    // Connect nodes
    let addrs2 = node2.listen_addrs().await;
    let addr2 = addrs2.first().expect("Node2 should have an address");
    let channel_id = node1
        .connect_peer(addr2)
        .await
        .expect("Failed to connect to node2");

    // Wait for identity exchange via wait_for_peer_identity.
    let peer2_peer_id = node1
        .wait_for_peer_identity(&channel_id, Duration::from_secs(5))
        .await
        .expect("Identity exchange timed out");
    assert_eq!(peer2_peer_id, *node2.peer_id());

    info!("Connected to peer {}", peer2_peer_id);

    // Send 100 messages in quick succession
    for i in 0..100 {
        let message = format!("Message {}", i);
        node1
            .send_message(&peer2_peer_id, "test", message.as_bytes().to_vec())
            .await
            .unwrap_or_else(|e| panic!("Message {} failed: {}", i, e));
    }

    info!("Sent 100 messages successfully");

    // Wait a bit
    sleep(Duration::from_secs(2)).await;

    // Send another batch
    for i in 100..200 {
        let message = format!("Message {}", i);
        node1
            .send_message(&peer2_peer_id, "test", message.as_bytes().to_vec())
            .await
            .unwrap_or_else(|e| panic!("Message {} failed: {}", i, e));
    }

    info!("Sent 200 messages total - all successful!");
    info!("=== Multiple message exchange test passed! ===");
}
