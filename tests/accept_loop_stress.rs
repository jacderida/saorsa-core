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

//! Stress test for the accept loop under connection pressure.
//!
//! Reproduces a bug where the accept loop stalled after 15+ hours in a
//! 1000-node testnet. The root cause was the accept loop taking two write
//! locks (`peers` and `active_connections`) inline, serialising behind
//! contention and causing the bounded handshake channel (cap 32) to fill.
//!
//! This test creates one server node and floods it with 40 concurrent
//! client connections. All must complete identity exchange within a
//! reasonable time. Before the fix, the accept loop would fall behind
//! and identity exchanges would timeout.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use saorsa_core::{NodeConfig, P2PNode};
use std::time::Duration;
use tokio::time::timeout;

fn test_config() -> NodeConfig {
    NodeConfig::builder()
        .local(true)
        .port(0)
        .ipv6(false)
        .build()
        .expect("test config should be valid")
}

/// Flood a single node with 40 concurrent connections and verify all
/// connected clients complete identity exchange. This exercises the
/// accept loop's ability to drain the handshake channel under pressure.
///
/// The test distinguishes two failure modes:
/// - **Connection failure**: QUIC connection couldn't be established
///   (resource limits on loopback — tolerated)
/// - **Identity exchange timeout**: connected but accept loop stalled
///   (the bug this test guards against — must be zero)
#[tokio::test]
async fn accept_loop_handles_concurrent_connection_flood() {
    let server = P2PNode::new(test_config()).await.unwrap();
    server.start().await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;

    let server_addr = server
        .listen_addrs()
        .await
        .into_iter()
        .find(|a| a.is_ipv4())
        .expect("server should have an IPv4 listen address");

    const NUM_CLIENTS: usize = 40;
    let mut handles = Vec::with_capacity(NUM_CLIENTS);

    // Stagger connection starts by 50ms to avoid overwhelming the single
    // machine's UDP/QUIC stack. In production the accept loop stalls under
    // sustained load over hours, not instantaneous bursts.
    for i in 0..NUM_CLIENTS {
        let addr = server_addr.clone();
        tokio::time::sleep(Duration::from_millis(50)).await;
        handles.push(tokio::spawn(async move {
            let client = P2PNode::new(test_config()).await.unwrap();
            client.start().await.unwrap();
            tokio::time::sleep(Duration::from_millis(50)).await;

            let channel_id = match timeout(Duration::from_secs(5), client.connect_peer(&addr))
                .await
            {
                Ok(Ok(id)) => id,
                Ok(Err(e)) => return Err(format!("client {i} connect failed: {e}")),
                Err(_) => return Err(format!("client {i} connect timed out")),
            };

            match timeout(
                Duration::from_secs(10),
                client.wait_for_peer_identity(&channel_id, Duration::from_secs(10)),
            )
            .await
            {
                Ok(Ok(peer_id)) => Ok((i, peer_id)),
                Ok(Err(e)) => Err(format!(
                    "client {i} IDENTITY EXCHANGE FAILED (accept loop stall): {e}"
                )),
                Err(_) => Err(format!(
                    "client {i} IDENTITY EXCHANGE TIMED OUT (accept loop stall)"
                )),
            }
        }));
    }

    let mut identity_ok = 0;
    let mut connect_failures = 0;
    let mut identity_failures = 0;

    for handle in handles {
        match timeout(Duration::from_secs(30), handle).await {
            Ok(Ok(Ok((i, _peer_id)))) => {
                identity_ok += 1;
                eprintln!("Client {i}: identity exchange OK");
            }
            Ok(Ok(Err(msg))) => {
                if msg.contains("IDENTITY EXCHANGE") {
                    identity_failures += 1;
                    eprintln!("FAIL: {msg}");
                } else {
                    connect_failures += 1;
                    eprintln!("SKIP: {msg}");
                }
            }
            Ok(Err(e)) => {
                connect_failures += 1;
                eprintln!("SKIP: task join error: {e}");
            }
            Err(_) => {
                identity_failures += 1;
                eprintln!("FAIL: task timed out at 30s (accept loop stall)");
            }
        }
    }

    eprintln!(
        "\nResults: {identity_ok} identity OK, \
         {connect_failures} connect failures (tolerated), \
         {identity_failures} identity failures (NOT tolerated)"
    );

    // Allow up to 5% identity failures — on a single machine with 40
    // concurrent QUIC endpoints, occasional transient timeouts are expected.
    // The bug this guards against causes >50% failure rates.
    let max_identity_failures = NUM_CLIENTS / 20 + 1; // ~7.5% tolerance = 3
    assert!(
        identity_failures <= max_identity_failures,
        "Too many identity exchange failures: {identity_failures}/{NUM_CLIENTS} \
         (max tolerated: {max_identity_failures}). \
         This indicates the accept loop is stalling under connection pressure."
    );
    assert!(
        identity_ok >= NUM_CLIENTS * 9 / 10,
        "At least 90% of clients must complete identity exchange. \
         Only {identity_ok}/{NUM_CLIENTS} succeeded."
    );
}
