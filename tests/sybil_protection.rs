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

//! Integration tests for trust-based blocking as part of the sybil protection story.
//!
//! These tests verify that `send_request` correctly refuses to communicate with
//! peers whose trust has dropped below the block threshold, and that the
//! blocking integrates with the full P2PNode stack.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_core::{AdaptiveDhtConfig, NodeConfig, P2PNode, PeerId, TrustEvent};
use std::time::Duration;

/// Default block threshold.
const BLOCK_THRESHOLD: f64 = 0.15;

/// Helper: local test config.
fn test_config() -> NodeConfig {
    NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

// ---------------------------------------------------------------------------
// Trust-based blocking via send_request
// ---------------------------------------------------------------------------

/// `send_request` to a blocked peer returns a "PeerBlocked" error immediately
/// without actually attempting to connect.
#[tokio::test]
async fn send_request_blocked_for_low_trust_peer() {
    let node = P2PNode::new(test_config()).await.unwrap();
    node.start().await.unwrap();

    let bad_peer = PeerId::random();

    // Tank the peer's trust below block threshold
    for _ in 0..100 {
        node.report_trust_event(&bad_peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let score = node.peer_trust(&bad_peer);
    assert!(
        score < BLOCK_THRESHOLD,
        "Peer score {score} should be below threshold {BLOCK_THRESHOLD}"
    );

    // send_request should fail-fast with a blocking error
    let result = node
        .send_request(
            &bad_peer,
            "test/echo",
            vec![1, 2, 3],
            Duration::from_secs(1),
        )
        .await;

    assert!(result.is_err(), "send_request to blocked peer should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("blocked") || err_msg.contains("Blocked"),
        "Error should mention blocking, got: {err_msg}"
    );

    node.stop().await.unwrap();
}

/// `send_request` to a peer with neutral trust should NOT be blocked
/// (it will fail for other reasons since the peer doesn't exist, but the
/// error should not be "blocked").
#[tokio::test]
async fn send_request_not_blocked_for_neutral_peer() {
    let node = P2PNode::new(test_config()).await.unwrap();
    node.start().await.unwrap();

    let unknown_peer = PeerId::random();

    let result = node
        .send_request(
            &unknown_peer,
            "test/echo",
            vec![1, 2, 3],
            Duration::from_secs(1),
        )
        .await;

    // It will fail (peer not connected) but NOT because of blocking
    assert!(result.is_err(), "Request to unknown peer should fail");
    let err_msg = result.unwrap_err().to_string();
    assert!(
        !err_msg.contains("blocked") && !err_msg.contains("Blocked"),
        "Unknown peer should not be blocked, got: {err_msg}"
    );

    node.stop().await.unwrap();
}

/// A peer right at the block threshold (>= 0.15) is NOT blocked.
#[tokio::test]
async fn peer_at_threshold_is_not_blocked() {
    let node = P2PNode::new(test_config()).await.unwrap();
    node.start().await.unwrap();

    let peer = PeerId::random();

    // Push score down partway but not below threshold
    // From 0.5, ~5 failures gives approximately 0.5 * 0.9^5 ≈ 0.295 (well above 0.15)
    for _ in 0..5 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let score = node.peer_trust(&peer);
    assert!(
        score >= BLOCK_THRESHOLD,
        "Score {score} should still be above threshold {BLOCK_THRESHOLD}"
    );

    let result = node
        .send_request(&peer, "test/echo", vec![], Duration::from_secs(1))
        .await;

    // Will fail (not connected) but should NOT mention "blocked"
    if let Err(e) = &result {
        let msg = e.to_string();
        assert!(
            !msg.contains("blocked") && !msg.contains("Blocked"),
            "Peer above threshold should not be blocked, got: {msg}"
        );
    }

    node.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Custom threshold changes blocking boundary
// ---------------------------------------------------------------------------

/// With a higher threshold (e.g. 0.4), fewer failures are needed to block.
#[tokio::test]
async fn custom_high_threshold_blocks_sooner() {
    let custom_threshold = 0.4;
    let config = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .adaptive_dht_config(AdaptiveDhtConfig {
            block_threshold: custom_threshold,
        })
        .build()
        .unwrap();

    let node = P2PNode::new(config).await.unwrap();
    node.start().await.unwrap();

    let peer = PeerId::random();

    // With threshold 0.4 and EMA weight 0.1, from neutral (0.5):
    // After ~5 failures: 0.5 * 0.9^5 ≈ 0.295, below 0.4
    for _ in 0..10 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let score = node.peer_trust(&peer);
    assert!(
        score < custom_threshold,
        "Score {score} should be below custom threshold {custom_threshold}"
    );

    let result = node
        .send_request(&peer, "test/echo", vec![], Duration::from_secs(1))
        .await;
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("blocked") || err_msg.contains("Blocked"),
        "Should be blocked with custom threshold, got: {err_msg}"
    );

    node.stop().await.unwrap();
}

/// With trust enforcement disabled (threshold 0.0), even a zero-trust peer is
/// not blocked.
#[tokio::test]
async fn enforcement_disabled_never_blocks() {
    let config = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .trust_enforcement(false)
        .build()
        .unwrap();

    let node = P2PNode::new(config).await.unwrap();
    node.start().await.unwrap();

    let peer = PeerId::random();

    // Tank trust completely
    for _ in 0..100 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }

    let score = node.peer_trust(&peer);
    assert!(score < 0.01, "Score should be near zero: {score}");

    let result = node
        .send_request(&peer, "test/echo", vec![], Duration::from_secs(1))
        .await;

    // Should fail for "not connected" but NOT for "blocked"
    let err_msg = result.unwrap_err().to_string();
    assert!(
        !err_msg.contains("blocked") && !err_msg.contains("Blocked"),
        "With enforcement disabled, should not block: {err_msg}"
    );

    node.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Blocking is per-peer, not global
// ---------------------------------------------------------------------------

/// Blocking one peer does not affect requests to other peers.
#[tokio::test]
async fn blocking_is_per_peer() {
    let node = P2PNode::new(test_config()).await.unwrap();
    node.start().await.unwrap();

    let blocked_peer = PeerId::random();
    let clean_peer = PeerId::random();

    // Block one peer
    for _ in 0..100 {
        node.report_trust_event(&blocked_peer, TrustEvent::ConnectionFailed)
            .await;
    }

    assert!(node.peer_trust(&blocked_peer) < BLOCK_THRESHOLD);
    assert!((node.peer_trust(&clean_peer) - 0.5).abs() < f64::EPSILON);

    // Blocked peer should be rejected
    let blocked_result = node
        .send_request(&blocked_peer, "test/echo", vec![], Duration::from_secs(1))
        .await;
    let err_msg = blocked_result.unwrap_err().to_string();
    assert!(
        err_msg.contains("blocked") || err_msg.contains("Blocked"),
        "Blocked peer error should mention 'blocked', got: {err_msg}"
    );

    // Clean peer should NOT be blocked (will fail for not-connected, but
    // the error should not mention blocking)
    let clean_result = node
        .send_request(&clean_peer, "test/echo", vec![], Duration::from_secs(1))
        .await;
    if let Err(e) = &clean_result {
        let msg = e.to_string();
        assert!(
            !msg.contains("blocked") && !msg.contains("Blocked"),
            "Clean peer should not be blocked, got: {msg}"
        );
    }

    node.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Trust recovery unblocks send_request
// ---------------------------------------------------------------------------

/// After removing a blocked peer from the trust engine, `send_request` no
/// longer returns a "blocked" error.
#[tokio::test]
async fn trust_removal_unblocks_peer() {
    let node = P2PNode::new(test_config()).await.unwrap();
    node.start().await.unwrap();

    let peer = PeerId::random();

    // Block the peer
    for _ in 0..100 {
        node.report_trust_event(&peer, TrustEvent::ConnectionFailed)
            .await;
    }
    assert!(node.peer_trust(&peer) < BLOCK_THRESHOLD);

    // Verify blocked
    let blocked = node
        .send_request(&peer, "test/echo", vec![], Duration::from_secs(1))
        .await;
    let err_msg = blocked.unwrap_err().to_string();
    assert!(
        err_msg.contains("blocked") || err_msg.contains("Blocked"),
        "Blocked peer error should mention 'blocked', got: {err_msg}"
    );

    // Remove from trust engine → reset to neutral
    node.trust_engine().remove_node(&peer).await;
    assert!((node.peer_trust(&peer) - 0.5).abs() < f64::EPSILON);

    // Should no longer be blocked
    let unblocked = node
        .send_request(&peer, "test/echo", vec![], Duration::from_secs(1))
        .await;
    if let Err(e) = &unblocked {
        let msg = e.to_string();
        assert!(
            !msg.contains("blocked") && !msg.contains("Blocked"),
            "After removal, peer should not be blocked: {msg}"
        );
    }

    node.stop().await.unwrap();
}
