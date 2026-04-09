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

//! End-to-end integration tests for MASQUE relay establishment and
//! communication through a relay.
//!
//! Three-node topology:
//! ```text
//!   R (relay)  ←──bootstrap──  P (private, relayed through R)
//!       ↑                            ↑
//!       └──bootstrap──  S (sender) ──┘ (via relay)
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_core::{MultiAddr, NodeConfig, P2PEvent, P2PNode};
use std::time::Duration;
use tokio::time::{sleep, timeout};

/// Maximum time for the sender to reach the private node through the relay.
const RELAY_SEND_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time for a message to be delivered through the relay.
const MESSAGE_RECV_TIMEOUT: Duration = Duration::from_secs(10);

/// Polling interval when waiting for peer connectivity.
const CONNECT_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Timeout for waiting for bilateral peer visibility.
const BILATERAL_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Helper: local loopback, ephemeral port, IPv4-only config.
fn test_config() -> NodeConfig {
    NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

/// Initialize tracing subscriber for test diagnostics (idempotent).
fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                "saorsa_core::reachability=info,saorsa_core::network=info"
                    .parse()
                    .unwrap()
            }),
        )
        .with_test_writer()
        .try_init();
}

/// Extract the IPv4 listen address from a node.
async fn ipv4_addr(node: &P2PNode) -> MultiAddr {
    node.listen_addrs()
        .await
        .into_iter()
        .find(|a| a.is_ipv4())
        .expect("node should have an IPv4 listen address")
}

/// Start the relay node (R) and return it along with its listen address.
///
/// R uses default config — relay_serving_enabled stays `true` because the
/// loopback environment produces a `NoProbers` reachability outcome, which
/// does not disable relay serving.
async fn start_relay_node() -> (P2PNode, MultiAddr) {
    let node_r = P2PNode::new(test_config()).await.unwrap();
    node_r.start().await.unwrap();
    let addr = ipv4_addr(&node_r).await;
    (node_r, addr)
}

/// Start a private node that acquires a MASQUE relay through R.
///
/// Returns the node and its relay-allocated address. Panics if the relay
/// was not established.
async fn start_private_node(relay_node_addr: &MultiAddr) -> (P2PNode, MultiAddr) {
    let config = NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .assume_private(true)
        .bootstrap_peer(relay_node_addr.clone())
        .build()
        .unwrap();
    let node = P2PNode::new(config).await.unwrap();
    node.start().await.unwrap();

    let relay_sock = node
        .relay_address()
        .await
        .expect("private node should have acquired a MASQUE relay during start()");
    let relay_multi = MultiAddr::quic(relay_sock);
    (node, relay_multi)
}

// ---------------------------------------------------------------------------
// Relay establishment (works on loopback)
// ---------------------------------------------------------------------------

/// A private node with `assume_private` successfully acquires a MASQUE relay
/// through a reachable bootstrap peer.
///
/// Verifies:
/// - The relay session is established (relay address allocated)
/// - The relay address is on the relay node's host (different port than P's bind port)
/// - P's direct listen address becomes unreachable after endpoint rebind
/// - P is connected to R after bootstrap
#[tokio::test]
async fn assume_private_node_acquires_relay_through_bootstrap_peer() {
    init_tracing();

    let (node_r, node_r_addr) = start_relay_node().await;
    let peer_r = *node_r.peer_id();

    let (node_p, relay_addr) = start_private_node(&node_r_addr).await;
    let peer_p = *node_p.peer_id();

    // The relay address should be allocated.
    let relay_sock = relay_addr
        .dialable_socket_addr()
        .expect("relay address should be dialable");
    let direct_addr = ipv4_addr(&node_p).await;
    let direct_sock = direct_addr
        .dialable_socket_addr()
        .expect("direct address should be dialable");

    // Relay address is on a different port than P's direct bind.
    assert_ne!(
        relay_sock.port(),
        direct_sock.port(),
        "relay port should differ from P's direct bind port"
    );
    // Relay IP matches (both loopback on same host).
    assert_eq!(relay_sock.ip(), direct_sock.ip());

    // P should be connected to R after bootstrap.
    assert!(
        node_p.is_peer_connected(&peer_r).await,
        "P should be connected to R after bootstrap + relay acquisition"
    );

    // R should know about P.
    assert!(
        node_r.is_peer_connected(&peer_p).await,
        "R should be connected to P"
    );

    // P's direct address should be unreachable after endpoint rebind.
    // A fresh node trying to connect to P's direct address should fail.
    let probe = P2PNode::new(test_config()).await.unwrap();
    probe.start().await.unwrap();

    let direct_connect = timeout(Duration::from_secs(3), probe.connect_peer(&direct_addr)).await;
    assert!(
        direct_connect.is_err() || direct_connect.unwrap().is_err(),
        "P's direct address should be unreachable after relay rebind"
    );

    probe.stop().await.unwrap();
    node_p.stop().await.unwrap();
    node_r.stop().await.unwrap();
}

// ---------------------------------------------------------------------------
// Relay data-plane tests
// ---------------------------------------------------------------------------

/// A private node receives messages through its MASQUE relay.
#[tokio::test]
async fn private_node_receives_messages_through_masque_relay() {
    init_tracing();

    let (node_r, node_r_addr) = start_relay_node().await;
    let (node_p, relay_addr) = start_private_node(&node_r_addr).await;
    let mut events_p = node_p.subscribe_events();
    let peer_p = *node_p.peer_id();

    let node_s = P2PNode::new(test_config()).await.unwrap();
    node_s.start().await.unwrap();
    let peer_s = *node_s.peer_id();

    // Send message from S to P through the relay address.
    let payload = b"hello through masque relay".to_vec();
    timeout(
        RELAY_SEND_TIMEOUT,
        node_s.send_message(
            &peer_p,
            "test/relay-msg",
            payload.clone(),
            std::slice::from_ref(&relay_addr),
        ),
    )
    .await
    .expect("send through relay should not timeout")
    .expect("send_message through relay should succeed");

    // Verify P received the message.
    let (received_source, received_data) = timeout(MESSAGE_RECV_TIMEOUT, async {
        loop {
            match events_p.recv().await {
                Ok(P2PEvent::Message {
                    topic,
                    source,
                    data,
                }) if topic == "test/relay-msg" => {
                    return (source, data);
                }
                Ok(_) => continue,
                Err(e) => panic!("P's event channel closed unexpectedly: {e:?}"),
            }
        }
    })
    .await
    .expect("P should receive message through relay");

    assert_eq!(received_data, payload);
    assert_eq!(received_source, Some(peer_s));

    // Verify identity exchange completed through the relay.
    assert!(
        node_s.is_peer_connected(&peer_p).await,
        "S should see P as connected"
    );
    let p_sees_s = timeout(BILATERAL_CONNECT_TIMEOUT, async {
        loop {
            if node_p.is_peer_connected(&peer_s).await {
                break;
            }
            sleep(CONNECT_POLL_INTERVAL).await;
        }
    })
    .await;
    assert!(p_sees_s.is_ok(), "P should see S as connected");

    // Second message proves sustained relay connectivity.
    let second_payload = b"relay still works".to_vec();
    timeout(
        Duration::from_secs(5),
        node_s.send_message(&peer_p, "test/relay-sustained", second_payload.clone(), &[]),
    )
    .await
    .expect("second send should not timeout")
    .expect("second send should succeed");

    let (source2, data2) = timeout(MESSAGE_RECV_TIMEOUT, async {
        loop {
            match events_p.recv().await {
                Ok(P2PEvent::Message {
                    topic,
                    source,
                    data,
                }) if topic == "test/relay-sustained" => {
                    return (source, data);
                }
                Ok(_) => continue,
                Err(e) => panic!("P's event channel closed: {e:?}"),
            }
        }
    })
    .await
    .expect("P should receive second message");

    assert_eq!(data2, second_payload);
    assert_eq!(source2, Some(peer_s));

    node_s.stop().await.unwrap();
    node_p.stop().await.unwrap();
    node_r.stop().await.unwrap();
}

/// Peer identity exchange through a MASQUE relay yields the correct
/// cryptographic peer IDs on both sides.
#[tokio::test]
async fn identity_exchange_through_relay_produces_correct_peer_ids() {
    init_tracing();

    let (node_r, node_r_addr) = start_relay_node().await;
    let (node_p, relay_addr) = start_private_node(&node_r_addr).await;
    let mut events_p = node_p.subscribe_events();
    let peer_p = *node_p.peer_id();

    let node_s = P2PNode::new(test_config()).await.unwrap();
    let mut events_s = node_s.subscribe_events();
    let peer_s = *node_s.peer_id();
    node_s.start().await.unwrap();

    // Connect S → P through the relay address.
    let channel_id = timeout(Duration::from_secs(10), node_s.connect_peer(&relay_addr))
        .await
        .expect("connect through relay should not timeout")
        .expect("connect through relay should succeed");

    let authenticated_p = timeout(
        Duration::from_secs(5),
        node_s.wait_for_peer_identity(&channel_id, Duration::from_secs(5)),
    )
    .await
    .expect("identity exchange should not timeout")
    .expect("identity exchange should succeed");

    assert_eq!(authenticated_p, peer_p);

    // PeerConnected on S for P.
    let s_connected = timeout(BILATERAL_CONNECT_TIMEOUT, async {
        loop {
            match events_s.recv().await {
                Ok(P2PEvent::PeerConnected(pid, _)) if pid == peer_p => return pid,
                Ok(_) => continue,
                Err(e) => panic!("event error: {e:?}"),
            }
        }
    })
    .await
    .expect("S should emit PeerConnected for P");
    assert_eq!(s_connected, peer_p);

    // PeerConnected on P for S.
    let p_connected = timeout(BILATERAL_CONNECT_TIMEOUT, async {
        loop {
            match events_p.recv().await {
                Ok(P2PEvent::PeerConnected(pid, _)) if pid == peer_s => return pid,
                Ok(_) => continue,
                Err(e) => panic!("event error: {e:?}"),
            }
        }
    })
    .await
    .expect("P should emit PeerConnected for S");
    assert_eq!(p_connected, peer_s);

    // Bidirectional connectivity.
    assert!(node_s.is_peer_connected(&peer_p).await);
    let p_sees_s = timeout(BILATERAL_CONNECT_TIMEOUT, async {
        loop {
            if node_p.is_peer_connected(&peer_s).await {
                break;
            }
            sleep(CONNECT_POLL_INTERVAL).await;
        }
    })
    .await;
    assert!(p_sees_s.is_ok());

    node_s.stop().await.unwrap();
    node_p.stop().await.unwrap();
    node_r.stop().await.unwrap();
}
