// Copyright 2024 Saorsa Labs Limited
//
// This software is dual-licensed under:
// - GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later)
// - Commercial License
//
// For AGPL-3.0 license, see LICENSE-AGPL-3.0
// For commercial licensing, contact: david@saorsalabs.com

//! DHT Peer Address Population Test
//!
//! This test verifies that the DHT manager correctly populates peer addresses
//! from the P2P layer when nodes connect and communicate.
//!
//! ## Problem Statement
//!
//! The DHT layer needs to know the network addresses of peers for routing and
//! replication. These addresses should be automatically populated from the P2P
//! connection layer, but we need to verify this happens correctly.
//!
//! ## Test Coverage
//!
//! 1. **Direct Connection Address Propagation**: Verifies that when two nodes
//!    connect directly, both nodes populate each other's addresses in their
//!    DHT peer info.
//!
//! 2. **Find Closest Nodes Returns Addresses**: Verifies that when querying
//!    for closest nodes, the returned nodes have non-empty address fields.
//!
//! 3. **Address Consistency Between Layers**: Verifies that addresses stored
//!    in the DHT layer match the addresses from the P2P layer.
//!
//! ## Authentication Requirement
//!
//! Peers must exchange signed messages to be recognized as authenticated peers.
//! The DHT layer only tracks authenticated peers (identified by their ML-DSA-65
//! node IDs), not raw transport-level channel IDs.

use anyhow::Result;
use saorsa_core::dht::{DHTConfig, Key};
use saorsa_core::dht_network_manager::{DhtNetworkConfig, DhtNetworkManager};
use saorsa_core::identity::node_identity::NodeIdentity;
use saorsa_core::network::NodeConfig;
use saorsa_core::transport_handle::{TransportConfig, TransportHandle};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;
use tracing::{debug, info, warn};

const NODE_STARTUP_DELAY: Duration = Duration::from_millis(500);
const AUTH_PROPAGATION_DELAY: Duration = Duration::from_millis(500);

/// Helper to create a unique 32-byte key from a string
fn key_from_str(s: &str) -> Key {
    let bytes = s.as_bytes();
    let mut key = [0u8; 32];
    let len = bytes.len().min(32);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

/// Creates a DhtNetworkConfig and TransportHandle for testing with automatic port allocation.
///
/// Returns the transport handle, config, and the generated node identity (needed for
/// determining the app-level peer ID that other nodes will see after authentication).
async fn create_test_dht_config(
    peer_id: &str,
) -> Result<(Arc<TransportHandle>, DhtNetworkConfig, Arc<NodeIdentity>)> {
    let identity = Arc::new(
        NodeIdentity::generate().map_err(|e| anyhow::anyhow!("identity generation failed: {e}"))?,
    );

    let node_config = NodeConfig::builder()
        .peer_id(peer_id.to_string())
        .listen_port(0) // Random port
        .ipv6(false)
        .build()?;

    let transport = Arc::new(
        TransportHandle::new(TransportConfig {
            peer_id: peer_id.to_string(),
            listen_addr: node_config.listen_addr,
            enable_ipv6: node_config.enable_ipv6,
            connection_timeout: node_config.connection_timeout,
            stale_peer_threshold: node_config.stale_peer_threshold,
            max_connections: node_config.max_connections,
            production_config: node_config.production_config.clone(),
            event_channel_capacity: saorsa_core::DEFAULT_EVENT_CHANNEL_CAPACITY,
            max_message_size: node_config.max_message_size,
            node_identity: Some(identity.clone()),
        })
        .await?,
    );

    let config = DhtNetworkConfig {
        peer_id: peer_id.to_string(),
        dht_config: DHTConfig::default(),
        node_config,
        request_timeout: Duration::from_secs(10),
        max_concurrent_operations: 10,
        replication_factor: 3,
        enable_security: false,
    };

    Ok((transport, config, identity))
}

/// Creates and starts a DhtNetworkManager for testing.
///
/// Returns the manager and the node identity (needed for determining the
/// app-level peer ID that remote nodes will use to identify this node).
async fn create_test_manager(name: &str) -> Result<(Arc<DhtNetworkManager>, Arc<NodeIdentity>)> {
    let (transport, config, identity) = create_test_dht_config(name).await?;
    transport.start_network_listeners().await?;
    let manager = Arc::new(DhtNetworkManager::new(transport, None, config).await?);
    manager.start().await?;
    sleep(NODE_STARTUP_DELAY).await;
    Ok((manager, identity))
}

/// Perform bidirectional authentication between two managers.
///
/// PeerConnected events (and thus DHT peer tracking) only fire when an
/// authenticated (signed) message is received. This helper:
/// 1. Connects A to B at the transport level
/// 2. Sends a signed message A→B to authenticate A on B's side
/// 3. Sends a signed message B→A to authenticate B on A's side
/// 4. Waits for authentication to propagate through event handling
///
/// Returns the channel ID from the initial connection.
async fn authenticate_bidirectional(
    manager_a: &DhtNetworkManager,
    manager_b: &DhtNetworkManager,
    identity_a: &NodeIdentity,
    addr_b: &str,
) -> Result<String> {
    // Step 1: transport-level connection (returns channel ID)
    let channel_id_b = manager_a.connect_to_peer(addr_b).await?;

    // Step 2: A sends signed message to B → B authenticates A
    manager_a
        .transport()
        .send_message(&channel_id_b, "auth", b"hello".to_vec())
        .await?;

    // Wait for B to process the message, authenticate A, and emit PeerConnected
    sleep(AUTH_PROPAGATION_DELAY).await;

    // Step 3: B now knows A's node_id via peer_to_channel.
    // B sends signed message back to A → A authenticates B.
    let a_node_id = identity_a.node_id().to_hex();
    manager_b
        .transport()
        .send_message(&a_node_id, "auth", b"hello_back".to_vec())
        .await?;

    // Wait for A to process the message, authenticate B, and emit PeerConnected
    sleep(AUTH_PROPAGATION_DELAY).await;

    Ok(channel_id_b)
}

// =============================================================================
// TEST 1: Direct Connection Address Propagation
// =============================================================================

/// Test that when two nodes connect and authenticate, both populate each other's
/// addresses in their DHT peer info.
///
/// ## Topology
/// ```text
/// Node A ←→ Node B
/// ```
///
/// ## Expected Behavior
/// - After bidirectional authentication, Node A's get_connected_peers() should show Node B
/// - After bidirectional authentication, Node B's get_connected_peers() should show Node A
/// - Peers are identified by app-level node IDs (ML-DSA-65), not channel IDs
/// - Addresses should be valid network addresses (not empty strings)
#[tokio::test]
async fn test_direct_connection_address_propagation() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug,saorsa_core::dht_network_manager=trace")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Direct Connection Address Propagation ===");

    // Create two nodes (each with its own ML-DSA-65 identity)
    let (manager_a, identity_a) = create_test_manager("address_test_a").await?;
    let (manager_b, identity_b) = create_test_manager("address_test_b").await?;

    let a_node_id = identity_a.node_id().to_hex();
    let b_node_id = identity_b.node_id().to_hex();
    info!(
        "Created nodes A (node_id={}) and B (node_id={})",
        a_node_id, b_node_id
    );

    // Get Node B's listen address
    let addr_b = manager_b
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node B has no listen address"))?;

    // Connect and authenticate bidirectionally
    info!("Connecting and authenticating A ←→ B");
    authenticate_bidirectional(&manager_a, &manager_b, &identity_a, &addr_b).await?;

    // Check Node A's view of Node B (look up by B's app-level node_id)
    info!("Checking Node A's view of connected peers...");
    let peers_from_a = manager_a.get_connected_peers().await;
    info!("Node A sees {} connected peers", peers_from_a.len());

    let peer_b_in_a = peers_from_a.iter().find(|p| p.peer_id == b_node_id);

    match peer_b_in_a {
        Some(peer_info) => {
            info!(
                "Node A sees peer B with {} addresses",
                peer_info.addresses.len()
            );
            for (i, addr) in peer_info.addresses.iter().enumerate() {
                info!("  Address {}: {}", i, addr);
            }

            if peer_info.addresses.is_empty() {
                warn!(
                    "TEST FAILED: Node A sees peer B but has ZERO addresses.\n\
                    \n\
                    Expected behavior:\n\
                    - When Node A authenticates Node B, the DHT layer should populate peer B's addresses\n\
                    - Addresses should come from the P2P layer's PeerInfo\n\
                    \n\
                    Actual behavior:\n\
                    - peer_info.addresses is empty\n\
                    \n\
                    Implementation needed:\n\
                    - Populate addresses from P2P layer when peers authenticate\n\
                    - Update addresses in DHT peer info on PeerConnected events"
                );
                return Err(anyhow::anyhow!(
                    "Address propagation failed: Node A has no addresses for Node B"
                ));
            }

            info!("Node A successfully populated addresses for Node B");
        }
        None => {
            warn!("Node A does not see peer B in connected peers at all!");
            return Err(anyhow::anyhow!("Node B not in Node A's connected peers"));
        }
    }

    // Check Node B's view of Node A (look up by A's app-level node_id)
    info!("Checking Node B's view of connected peers...");
    let peers_from_b = manager_b.get_connected_peers().await;
    info!("Node B sees {} connected peers", peers_from_b.len());

    let peer_a_in_b = peers_from_b.iter().find(|p| p.peer_id == a_node_id);

    match peer_a_in_b {
        Some(peer_info) => {
            info!(
                "Node B sees peer A with {} addresses",
                peer_info.addresses.len()
            );
            for (i, addr) in peer_info.addresses.iter().enumerate() {
                info!("  Address {}: {}", i, addr);
            }

            if peer_info.addresses.is_empty() {
                warn!(
                    "TEST FAILED: Node B sees peer A but has ZERO addresses.\n\
                    This indicates address population is not working correctly."
                );
                return Err(anyhow::anyhow!(
                    "Address propagation failed: Node B has no addresses for Node A"
                ));
            }

            info!("Node B successfully populated addresses for Node A");
        }
        None => {
            warn!("Node B does not see peer A in connected peers at all!");
            return Err(anyhow::anyhow!("Node A not in Node B's connected peers"));
        }
    }

    // Cleanup
    let _ = manager_a.stop().await;
    let _ = manager_b.stop().await;

    info!("TEST PASSED: Both nodes correctly populated peer addresses!");
    Ok(())
}

// =============================================================================
// TEST 2: Find Closest Nodes Returns Addresses
// =============================================================================

/// Test that find_closest_nodes returns nodes with populated address fields.
///
/// ## Topology
/// ```text
/// Node A ←→ Node B ←→ Node C
/// (Chain topology)
/// ```
///
/// ## Expected Behavior
/// - When Node B calls find_closest_nodes(), the returned nodes should have addresses
/// - Addresses should be usable for making connections
#[tokio::test]
async fn test_find_closest_nodes_returns_addresses() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug,saorsa_core::dht_network_manager=trace")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Find Closest Nodes Returns Addresses ===");

    // Create three nodes (each with its own ML-DSA-65 identity)
    let (manager_a, identity_a) = create_test_manager("find_nodes_a").await?;
    let (manager_b, identity_b) = create_test_manager("find_nodes_b").await?;
    let (manager_c, _identity_c) = create_test_manager("find_nodes_c").await?;

    info!("Created nodes A, B, and C");

    // Get listen addresses
    let addr_b = manager_b
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node B has no listen address"))?;
    let addr_c = manager_c
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node C has no listen address"))?;

    // Connect and authenticate A ←→ B
    info!("Connecting and authenticating A ←→ B");
    authenticate_bidirectional(&manager_a, &manager_b, &identity_a, &addr_b).await?;

    // Connect and authenticate B ←→ C
    info!("Connecting and authenticating B ←→ C");
    authenticate_bidirectional(&manager_b, &manager_c, &identity_b, &addr_c).await?;

    // Node B calls find_closest_nodes for a test key
    let test_key = key_from_str("test_find_nodes_key");
    info!(
        "Node B finding closest nodes to key: {}",
        hex::encode(test_key)
    );

    let closest_nodes = manager_b.find_closest_nodes_local(&test_key, 5).await;

    info!("find_closest_nodes returned {} nodes", closest_nodes.len());

    if closest_nodes.is_empty() {
        warn!("TEST FAILED: find_closest_nodes returned ZERO nodes");
        return Err(anyhow::anyhow!("No nodes returned from find_closest_nodes"));
    }

    // Check each returned node for addresses
    let mut nodes_with_addresses = 0;
    let mut nodes_without_addresses = 0;

    for (i, node) in closest_nodes.iter().enumerate() {
        debug!("Node {}: peer_id={}", i, node.peer_id);
        debug!("  address: '{}'", node.address);
        debug!("  reliability: {}", node.reliability);

        if node.address.is_empty() {
            warn!("  Node {} has EMPTY address field", i);
            nodes_without_addresses += 1;
        } else {
            debug!("  Node {} has address: {}", i, node.address);
            nodes_with_addresses += 1;
        }
    }

    info!(
        "Address population results: {} with addresses, {} without",
        nodes_with_addresses, nodes_without_addresses
    );

    if nodes_without_addresses > 0 {
        warn!(
            "TEST FAILED: {}/{} nodes returned by find_closest_nodes have NO addresses.\n\
            \n\
            Expected behavior:\n\
            - find_closest_nodes should return nodes with populated address fields\n\
            - These addresses should be usable for connecting to the nodes\n\
            \n\
            Actual behavior:\n\
            - {} nodes have empty address fields\n\
            \n\
            Implementation needed:\n\
            - Ensure DHTNode.address is populated from peer connection info\n\
            - Address should be the socket address or multiaddr of the peer",
            nodes_without_addresses,
            closest_nodes.len(),
            nodes_without_addresses
        );
        return Err(anyhow::anyhow!(
            "{} nodes missing addresses",
            nodes_without_addresses
        ));
    }

    // Cleanup
    let _ = manager_a.stop().await;
    let _ = manager_b.stop().await;
    let _ = manager_c.stop().await;

    info!("TEST PASSED: All returned nodes have populated addresses!");
    Ok(())
}

// =============================================================================
// TEST 3: Address Consistency Between P2P and DHT Layers
// =============================================================================

/// Test that addresses in DHT peer info match addresses from the P2P layer.
///
/// ## Topology
/// ```text
/// Node A ←→ Node B
/// ```
///
/// ## Expected Behavior
/// - When Node A authenticates Node B:
///   - P2P layer stores peer info with addresses (keyed by app-level node ID)
///   - DHT layer should have matching addresses
/// - Addresses should be consistent between both layers
#[tokio::test]
async fn test_address_consistency_with_p2p_layer() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("debug,saorsa_core::dht_network_manager=trace")
        .with_test_writer()
        .try_init();

    info!("=== TEST: Address Consistency Between P2P and DHT Layers ===");

    // Create two nodes (each with its own ML-DSA-65 identity)
    let (manager_a, identity_a) = create_test_manager("consistency_a").await?;
    let (manager_b, identity_b) = create_test_manager("consistency_b").await?;

    let b_node_id = identity_b.node_id().to_hex();
    info!("Created nodes A and B (B's node_id={})", b_node_id);

    // Connect and authenticate bidirectionally
    let addr_b = manager_b
        .local_addr()
        .ok_or_else(|| anyhow::anyhow!("Node B has no listen address"))?;

    info!("Connecting and authenticating A ←→ B");
    authenticate_bidirectional(&manager_a, &manager_b, &identity_a, &addr_b).await?;

    // Query P2P layer for peer B's info (using B's app-level node ID)
    info!(
        "Querying P2P layer for peer B's info (node_id={})...",
        b_node_id
    );
    let p2p_peer_info = manager_a.transport().peer_info(&b_node_id).await;

    let p2p_addresses = match p2p_peer_info {
        Some(info) => {
            info!(
                "P2P layer has {} addresses for peer B",
                info.addresses.len()
            );
            for (i, addr) in info.addresses.iter().enumerate() {
                info!("  P2P Address {}: {}", i, addr);
            }
            info.addresses
        }
        None => {
            warn!("P2P layer has NO peer info for peer B!");
            return Err(anyhow::anyhow!("P2P layer missing peer info"));
        }
    };

    // Query DHT layer for peer B's info (using B's app-level node ID)
    info!("Querying DHT layer for peer B's info...");
    let dht_peers = manager_a.get_connected_peers().await;
    let dht_peer_info = dht_peers.iter().find(|p| p.peer_id == b_node_id);

    let dht_addresses = match dht_peer_info {
        Some(info) => {
            info!(
                "DHT layer has {} addresses for peer B",
                info.addresses.len()
            );
            for (i, addr) in info.addresses.iter().enumerate() {
                info!("  DHT Address {}: {}", i, addr);
            }
            info.addresses.clone()
        }
        None => {
            warn!("DHT layer has NO peer info for peer B!");
            return Err(anyhow::anyhow!("DHT layer missing peer info"));
        }
    };

    // Compare address counts
    if p2p_addresses.len() != dht_addresses.len() {
        warn!(
            "TEST FAILED: Address count mismatch!\n\
            P2P layer has {} addresses\n\
            DHT layer has {} addresses",
            p2p_addresses.len(),
            dht_addresses.len()
        );
        return Err(anyhow::anyhow!(
            "Address count mismatch: P2P={} vs DHT={}",
            p2p_addresses.len(),
            dht_addresses.len()
        ));
    }

    // Check if addresses are consistent (convert both to strings for comparison)
    let p2p_addr_strings: Vec<String> = p2p_addresses.clone();
    let dht_addr_strings: Vec<String> = dht_addresses.iter().map(|ma| ma.to_string()).collect();

    info!("Comparing addresses for consistency...");
    let mut mismatches = 0;

    for (i, p2p_addr) in p2p_addr_strings.iter().enumerate() {
        if let Some(dht_addr) = dht_addr_strings.get(i) {
            // Check if addresses match (exact or contain each other)
            let match_found =
                p2p_addr == dht_addr || p2p_addr.contains(dht_addr) || dht_addr.contains(p2p_addr);

            if !match_found {
                warn!(
                    "  Address mismatch at index {}:\n    P2P: {}\n    DHT: {}",
                    i, p2p_addr, dht_addr
                );
                mismatches += 1;
            } else {
                debug!("  Address {} matches: {}", i, p2p_addr);
            }
        }
    }

    if mismatches > 0 {
        warn!(
            "TEST FAILED: Found {} address mismatches between P2P and DHT layers.\n\
            \n\
            Expected behavior:\n\
            - DHT layer should store the same addresses as P2P layer\n\
            - Addresses should be synchronized when peers authenticate\n\
            \n\
            Actual behavior:\n\
            - {} addresses differ between layers\n\
            \n\
            Implementation needed:\n\
            - Properly propagate addresses from P2P PeerInfo to DHT DhtPeerInfo\n\
            - Ensure address format is consistent",
            mismatches, mismatches
        );
        return Err(anyhow::anyhow!("{} address mismatches", mismatches));
    }

    // Cleanup
    let _ = manager_a.stop().await;
    let _ = manager_b.stop().await;

    info!("TEST PASSED: Addresses are consistent between P2P and DHT layers!");
    Ok(())
}
