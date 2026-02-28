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

//! Transport handle module
//!
//! Encapsulates transport-level concerns (QUIC connections, peer registry,
//! message I/O, events) extracted from [`P2PNode`] to enable sharing between
//! `P2PNode` and [`DhtNetworkManager`] without coupling to the full node.

use crate::NetworkAddress;
use crate::PeerId;
use crate::bgp_geo_provider::BgpGeoProvider;
use crate::error::{NetworkError, P2PError, P2pResult as Result};
use crate::identity::node_identity::NodeIdentity;
use crate::network::{
    ConnectionStatus, KEEPALIVE_PAYLOAD, MAX_ACTIVE_REQUESTS, MAX_REQUEST_TIMEOUT,
    MESSAGE_RECV_CHANNEL_CAPACITY, NetworkSender, P2PEvent, ParsedMessage, PeerInfo, PeerResponse,
    PendingRequest, RequestResponseEnvelope, WireMessage, broadcast_event,
    normalize_wildcard_to_loopback, parse_protocol_message, register_new_channel,
};
use crate::production::{ProductionConfig, ResourceManager};
use crate::security::GeoProvider;
use crate::transport::ant_quic_adapter::{
    ConnectionEvent, DualStackNetworkNode, ant_peer_id_to_string,
};
use crate::validation::{RateLimitConfig, RateLimiter};

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock, broadcast};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

/// Background task maintenance interval in milliseconds.
const MAINTENANCE_INTERVAL_MS: u64 = 100;

/// Stale peer cleanup uses this multiplier on the stale threshold.
const CLEANUP_THRESHOLD_MULTIPLIER: u32 = 2;

/// Interval between keepalive pings to prevent idle connection timeout.
const KEEPALIVE_INTERVAL_SECS: u64 = 15;

// Test configuration defaults (used by `new_for_tests()` which is available in all builds)
const TEST_EVENT_CHANNEL_CAPACITY: usize = 16;
const TEST_MAX_REQUESTS: u32 = 100;
const TEST_BURST_SIZE: u32 = 100;
const TEST_RATE_LIMIT_WINDOW_SECS: u64 = 1;
const TEST_CONNECTION_TIMEOUT_SECS: u64 = 30;
const TEST_STALE_PEER_THRESHOLD_SECS: u64 = 60;

/// Internal protocol for automatic identity announcement on connect.
/// Filtered from P2PEvent::Message emission — not visible to applications.
const IDENTITY_ANNOUNCE_PROTOCOL: &str = "/saorsa/identity/1.0";

/// Touch a channel's `last_seen` timestamp to prove it is still alive.
///
/// Acquires a write lock on the peer map, so callers should not already
/// hold a lock on `peers`.
async fn touch_channel_last_seen(peers: &RwLock<HashMap<String, PeerInfo>>, channel_id: &str) {
    if let Some(peer_info) = peers.write().await.get_mut(channel_id) {
        peer_info.last_seen = Instant::now();
    }
}

/// Configuration for transport initialization, derived from [`NodeConfig`](crate::network::NodeConfig).
pub struct TransportConfig {
    /// Primary listen address.
    pub listen_addr: SocketAddr,
    /// Whether IPv6 dual-stack is enabled.
    pub enable_ipv6: bool,
    /// Connection timeout for outbound dials and sends.
    pub connection_timeout: Duration,
    /// Stale peer threshold for maintenance sweeps.
    pub stale_peer_threshold: Duration,
    /// Maximum concurrent connections.
    pub max_connections: usize,
    /// Optional production hardening config.
    pub production_config: Option<ProductionConfig>,
    /// Broadcast channel capacity for P2P events.
    pub event_channel_capacity: usize,
    /// Optional override for the maximum application-layer message size.
    ///
    /// When `None`, ant-quic's built-in default is used. Set this to tune
    /// the QUIC stream receive window and the
    /// per-stream read buffer for larger or smaller payloads.
    pub max_message_size: Option<usize>,
    /// Cryptographic node identity (ML-DSA-65). The canonical peer ID is
    /// derived from this identity's public key hash.
    pub node_identity: Arc<NodeIdentity>,
}

/// Encapsulates transport-level concerns: QUIC connections, peer registry,
/// message I/O, and network events.
///
/// Both [`P2PNode`](crate::network::P2PNode) and
/// [`DhtNetworkManager`](crate::dht_network_manager::DhtNetworkManager)
/// hold `Arc<TransportHandle>` so they share the same transport state.
pub struct TransportHandle {
    dual_node: Arc<DualStackNetworkNode>,
    peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
    active_connections: Arc<RwLock<HashSet<String>>>,
    event_tx: broadcast::Sender<P2PEvent>,
    listen_addrs: RwLock<Vec<SocketAddr>>,
    rate_limiter: Arc<RateLimiter>,
    active_requests: Arc<RwLock<HashMap<String, PendingRequest>>>,
    // Held to keep the Arc alive for background tasks that captured a clone.
    #[allow(dead_code)]
    geo_provider: Arc<BgpGeoProvider>,
    shutdown: CancellationToken,
    resource_manager: Option<Arc<ResourceManager>>,
    connection_timeout: Duration,
    stale_peer_threshold: Duration,
    connection_monitor_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    keepalive_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    periodic_tasks_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    recv_handles: Arc<RwLock<Vec<JoinHandle<()>>>>,
    listener_handle: Arc<RwLock<Option<JoinHandle<()>>>>,
    /// Cryptographic node identity for signing outgoing messages.
    node_identity: Arc<NodeIdentity>,
    /// Maps app-level [`PeerId`] → set of channel IDs (QUIC, Bluetooth, …).
    ///
    /// A single peer may communicate over multiple channels simultaneously.
    peer_to_channel: Arc<RwLock<HashMap<PeerId, HashSet<String>>>>,
    /// Reverse index: channel ID → set of app-level [`PeerId`]s on that channel.
    channel_to_peers: Arc<RwLock<HashMap<String, HashSet<PeerId>>>>,
}

// ============================================================================
// Construction
// ============================================================================

impl TransportHandle {
    /// Create a new transport handle with the given configuration.
    ///
    /// This performs the transport-level initialization that was previously
    /// embedded in `P2PNode::new()`: dual-stack QUIC binding, rate limiter,
    /// GeoIP provider, and background tasks (connection monitor, keepalive,
    /// periodic maintenance).
    pub async fn new(config: TransportConfig) -> Result<Self> {
        let (event_tx, _) = broadcast::channel(config.event_channel_capacity);

        // Initialize dual-stack ant-quic nodes
        let (v6_opt, v4_opt) = {
            let port = config.listen_addr.port();
            let ip = config.listen_addr.ip();

            let v4_addr = if ip.is_ipv4() {
                Some(SocketAddr::new(ip, port))
            } else {
                Some(SocketAddr::new(
                    std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                    port,
                ))
            };

            let v6_addr = if config.enable_ipv6 {
                if ip.is_ipv6() {
                    Some(SocketAddr::new(ip, port))
                } else {
                    Some(SocketAddr::new(
                        std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
                        port,
                    ))
                }
            } else {
                None
            };
            (v6_addr, v4_addr)
        };

        let dual_node = Arc::new(
            DualStackNetworkNode::new_with_max_connections(
                v6_opt,
                v4_opt,
                config.max_connections,
                config.max_message_size,
            )
            .await
            .map_err(|e| {
                P2PError::Transport(crate::error::TransportError::SetupFailed(
                    format!("Failed to create dual-stack network nodes: {}", e).into(),
                ))
            })?,
        );

        let rate_limiter = Arc::new(RateLimiter::new(RateLimitConfig::default()));
        let active_connections = Arc::new(RwLock::new(HashSet::new()));
        let geo_provider = Arc::new(BgpGeoProvider::new());
        let peers = Arc::new(RwLock::new(HashMap::new()));

        // Initialize production resource manager if configured
        let resource_manager = config
            .production_config
            .map(|prod_config| Arc::new(ResourceManager::new(prod_config)));

        let shutdown = CancellationToken::new();

        // Subscribe to connection events BEFORE spawning the monitor task
        let connection_event_rx = dual_node.subscribe_connection_events();

        let peer_to_channel = Arc::new(RwLock::new(HashMap::new()));
        let channel_to_peers = Arc::new(RwLock::new(HashMap::new()));

        let connection_monitor_handle = {
            let active_conns = Arc::clone(&active_connections);
            let peers_map = Arc::clone(&peers);
            let event_tx_clone = event_tx.clone();
            let dual_node_clone = Arc::clone(&dual_node);
            let geo_provider_clone = Arc::clone(&geo_provider);
            let shutdown_token = shutdown.clone();
            let p2c = Arc::clone(&peer_to_channel);
            let c2p = Arc::clone(&channel_to_peers);
            let identity_clone = config.node_identity.clone();

            let handle = tokio::spawn(async move {
                Self::connection_lifecycle_monitor_with_rx(
                    dual_node_clone,
                    connection_event_rx,
                    active_conns,
                    peers_map,
                    event_tx_clone,
                    geo_provider_clone,
                    shutdown_token,
                    p2c,
                    c2p,
                    identity_clone,
                )
                .await;
            });
            Arc::new(RwLock::new(Some(handle)))
        };

        let keepalive_handle = {
            let active_conns = Arc::clone(&active_connections);
            let dual_node_clone = Arc::clone(&dual_node);
            let token = shutdown.clone();

            let handle = tokio::spawn(async move {
                Self::keepalive_task(active_conns, dual_node_clone, token).await;
            });
            Arc::new(RwLock::new(Some(handle)))
        };

        let periodic_tasks_handle = {
            let peers_clone = Arc::clone(&peers);
            let active_conns_clone = Arc::clone(&active_connections);
            let event_tx_clone = event_tx.clone();
            let stale_threshold = config.stale_peer_threshold;
            let token = shutdown.clone();
            let p2c = Arc::clone(&peer_to_channel);
            let c2p = Arc::clone(&channel_to_peers);

            let handle = tokio::spawn(async move {
                Self::periodic_maintenance_task(
                    peers_clone,
                    active_conns_clone,
                    event_tx_clone,
                    stale_threshold,
                    token,
                    p2c,
                    c2p,
                )
                .await;
            });
            Arc::new(RwLock::new(Some(handle)))
        };

        Ok(Self {
            dual_node,
            peers,
            active_connections,
            event_tx,
            listen_addrs: RwLock::new(Vec::new()),
            rate_limiter,
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            geo_provider,
            shutdown,
            resource_manager,
            connection_timeout: config.connection_timeout,
            stale_peer_threshold: config.stale_peer_threshold,
            connection_monitor_handle,
            keepalive_handle,
            periodic_tasks_handle,
            recv_handles: Arc::new(RwLock::new(Vec::new())),
            listener_handle: Arc::new(RwLock::new(None)),
            node_identity: config.node_identity,
            peer_to_channel,
            channel_to_peers,
        })
    }

    /// Minimal constructor for tests that avoids real networking.
    pub fn new_for_tests() -> Result<Self> {
        let identity = Arc::new(NodeIdentity::generate().map_err(|e| {
            P2PError::Network(NetworkError::BindError(
                format!("Failed to generate test node identity: {}", e).into(),
            ))
        })?);
        let (event_tx, _) = broadcast::channel(TEST_EVENT_CHANNEL_CAPACITY);
        let dual_node = {
            let v6: Option<SocketAddr> = "[::1]:0"
                .parse()
                .ok()
                .or(Some(SocketAddr::from(([0, 0, 0, 0], 0))));
            let v4: Option<SocketAddr> = "127.0.0.1:0".parse().ok();
            let handle = tokio::runtime::Handle::current();
            let dual_attempt = handle.block_on(DualStackNetworkNode::new(v6, v4));
            let dual = match dual_attempt {
                Ok(d) => d,
                Err(_e1) => {
                    let fallback = handle
                        .block_on(DualStackNetworkNode::new(None, "127.0.0.1:0".parse().ok()));
                    match fallback {
                        Ok(d) => d,
                        Err(e2) => {
                            return Err(P2PError::Network(NetworkError::BindError(
                                format!("Failed to create dual-stack network node: {}", e2).into(),
                            )));
                        }
                    }
                }
            };
            Arc::new(dual)
        };

        Ok(Self {
            dual_node,
            peers: Arc::new(RwLock::new(HashMap::new())),
            active_connections: Arc::new(RwLock::new(HashSet::new())),
            event_tx,
            listen_addrs: RwLock::new(Vec::new()),
            rate_limiter: Arc::new(RateLimiter::new(RateLimitConfig {
                max_requests: TEST_MAX_REQUESTS,
                burst_size: TEST_BURST_SIZE,
                window: std::time::Duration::from_secs(TEST_RATE_LIMIT_WINDOW_SECS),
                ..Default::default()
            })),
            active_requests: Arc::new(RwLock::new(HashMap::new())),
            geo_provider: Arc::new(BgpGeoProvider::new()),
            shutdown: CancellationToken::new(),
            resource_manager: None,
            connection_timeout: Duration::from_secs(TEST_CONNECTION_TIMEOUT_SECS),
            stale_peer_threshold: Duration::from_secs(TEST_STALE_PEER_THRESHOLD_SECS),
            connection_monitor_handle: Arc::new(RwLock::new(None)),
            keepalive_handle: Arc::new(RwLock::new(None)),
            periodic_tasks_handle: Arc::new(RwLock::new(None)),
            recv_handles: Arc::new(RwLock::new(Vec::new())),
            listener_handle: Arc::new(RwLock::new(None)),
            node_identity: identity,
            peer_to_channel: Arc::new(RwLock::new(HashMap::new())),
            channel_to_peers: Arc::new(RwLock::new(HashMap::new())),
        })
    }
}

// ============================================================================
// Identity & Address Accessors
// ============================================================================

impl TransportHandle {
    /// Get the application-level peer ID (cryptographic identity).
    pub fn peer_id(&self) -> PeerId {
        self.node_identity.peer_id().clone()
    }

    /// Get the cryptographic node identity.
    pub fn node_identity(&self) -> &Arc<NodeIdentity> {
        &self.node_identity
    }

    /// Get the hex-encoded channel ID (QUIC connection identifier).
    ///
    /// This is the transport-level connection identifier. It differs from
    /// `peer_id()` which is the app-level cryptographic identity.
    pub fn channel_id(&self) -> Option<String> {
        if let Some(ref v4) = self.dual_node.v4 {
            return Some(ant_peer_id_to_string(&v4.our_peer_id()));
        }
        if let Some(ref v6) = self.dual_node.v6 {
            return Some(ant_peer_id_to_string(&v6.our_peer_id()));
        }
        None
    }

    /// Get the first listen address as a string.
    pub fn local_addr(&self) -> Option<String> {
        self.listen_addrs
            .try_read()
            .ok()
            .and_then(|addrs| addrs.first().map(|a| a.to_string()))
    }

    /// Get all current listen addresses.
    pub async fn listen_addrs(&self) -> Vec<SocketAddr> {
        self.listen_addrs.read().await.clone()
    }

    /// Get the connection timeout duration.
    pub fn connection_timeout(&self) -> Duration {
        self.connection_timeout
    }

    /// Get a reference to the resource manager, if configured.
    pub fn resource_manager(&self) -> Option<&Arc<ResourceManager>> {
        self.resource_manager.as_ref()
    }
}

// ============================================================================
// Peer Management
// ============================================================================

impl TransportHandle {
    /// Get list of authenticated app-level peer IDs.
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        self.peer_to_channel.read().await.keys().cloned().collect()
    }

    /// Get count of authenticated app-level peers.
    pub async fn peer_count(&self) -> usize {
        self.peer_to_channel.read().await.len()
    }

    /// Get all active transport-level channel IDs (internal bookkeeping).
    #[allow(dead_code)]
    pub(crate) async fn active_channels(&self) -> Vec<String> {
        self.active_connections
            .read()
            .await
            .iter()
            .cloned()
            .collect()
    }

    /// Get info for a specific peer.
    ///
    /// Accepts either a channel ID (direct lookup) or an app-level peer ID
    /// hex string (resolved via `peer_to_channel` mapping). This allows DHT
    /// code to pass app-level peer IDs without manual channel resolution.
    pub async fn peer_info(&self, peer_id: &str) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        if let Some(info) = peers.get(peer_id) {
            return Some(info.clone());
        }
        // Try parsing as app-level PeerId hex → resolve to any channel ID
        let app_id = PeerId::from_hex(peer_id).ok()?;
        let p2c = self.peer_to_channel.read().await;
        let channel = p2c.get(&app_id).and_then(|chs| chs.iter().next())?;
        peers.get(channel).cloned()
    }

    /// Get the channel ID for a given socket address, if connected (internal only).
    #[allow(dead_code)]
    pub(crate) async fn get_channel_id_by_address(&self, addr: &str) -> Option<String> {
        let socket_addr: SocketAddr = addr.parse().ok()?;
        let peers = self.peers.read().await;

        for (channel_id, peer_info) in peers.iter() {
            for peer_addr in &peer_info.addresses {
                if let Ok(peer_socket) = peer_addr.parse::<SocketAddr>()
                    && peer_socket == socket_addr
                {
                    return Some(channel_id.clone());
                }
            }
        }
        None
    }

    /// List all active connections with peer IDs and addresses (internal only).
    #[allow(dead_code)]
    pub(crate) async fn list_active_connections(&self) -> Vec<(String, Vec<String>)> {
        let active = self.active_connections.read().await;
        let peers = self.peers.read().await;

        active
            .iter()
            .map(|peer_id| {
                let addresses = peers
                    .get(peer_id)
                    .map(|info| info.addresses.clone())
                    .unwrap_or_default();
                (peer_id.clone(), addresses)
            })
            .collect()
    }

    /// Remove a channel from the tracking maps (internal only).
    pub(crate) async fn remove_channel(&self, channel_id: &str) -> bool {
        self.active_connections.write().await.remove(channel_id);
        self.remove_channel_mappings(channel_id).await;
        self.peers.write().await.remove(channel_id).is_some()
    }

    /// Check if a peer exists in the peers map.
    pub async fn is_peer_connected(&self, peer_id: &str) -> bool {
        self.peers.read().await.contains_key(peer_id)
    }

    /// Check if a connection to a peer is active at the transport layer (internal only).
    pub(crate) async fn is_connection_active(&self, channel_id: &str) -> bool {
        self.active_connections.read().await.contains(channel_id)
    }

    /// Remove channel mappings for a disconnected channel.
    ///
    /// Removes the channel from `channel_to_peers` and scrubs it from every
    /// affected peer's channel set in `peer_to_channel`. When a peer's last
    /// channel is removed, emits `PeerDisconnected`.
    async fn remove_channel_mappings(&self, channel_id: &str) {
        Self::remove_channel_mappings_static(
            channel_id,
            &self.peer_to_channel,
            &self.channel_to_peers,
            &self.event_tx,
        )
        .await;
    }

    /// Static version of channel mapping removal — usable from background tasks
    /// that don't have `&self`.
    async fn remove_channel_mappings_static(
        channel_id: &str,
        peer_to_channel: &RwLock<HashMap<PeerId, HashSet<String>>>,
        channel_to_peers: &RwLock<HashMap<String, HashSet<PeerId>>>,
        event_tx: &broadcast::Sender<P2PEvent>,
    ) {
        let mut p2c = peer_to_channel.write().await;
        let mut c2p = channel_to_peers.write().await;
        if let Some(app_peers) = c2p.remove(channel_id) {
            for app_peer in &app_peers {
                if let Some(channels) = p2c.get_mut(app_peer) {
                    channels.remove(channel_id);
                    if channels.is_empty() {
                        p2c.remove(app_peer);
                        let _ = event_tx.send(P2PEvent::PeerDisconnected(app_peer.clone()));
                    }
                }
            }
        }
    }
}

// ============================================================================
// Connection Management
// ============================================================================

impl TransportHandle {
    /// Connect to a peer at the given address.
    pub async fn connect_peer(&self, address: &str) -> Result<String> {
        // Check production limits if resource manager is enabled
        let _connection_guard = if let Some(ref resource_manager) = self.resource_manager {
            Some(resource_manager.acquire_connection().await?)
        } else {
            None
        };

        let socket_addr: SocketAddr = address.parse().map_err(|e| {
            P2PError::Network(NetworkError::InvalidAddress(
                format!("{}: {}", address, e).into(),
            ))
        })?;

        let normalized_addr = normalize_wildcard_to_loopback(socket_addr);
        let addr_list = vec![normalized_addr];

        let peer_id = match tokio::time::timeout(
            self.connection_timeout,
            self.dual_node.connect_happy_eyeballs(&addr_list),
        )
        .await
        {
            Ok(Ok(peer)) => {
                let connected_peer_id = ant_peer_id_to_string(&peer);

                // Prevent self-connections
                if connected_peer_id == self.node_identity.peer_id().to_hex() {
                    warn!(
                        "Detected self-connection to own address {} (peer_id: {}), rejecting",
                        address, connected_peer_id
                    );
                    self.dual_node.disconnect_peer(&peer).await;
                    return Err(P2PError::Network(NetworkError::InvalidAddress(
                        format!("Cannot connect to self ({})", address).into(),
                    )));
                }

                info!("Successfully connected to peer: {}", connected_peer_id);
                connected_peer_id
            }
            Ok(Err(e)) => {
                warn!("connect_happy_eyeballs failed for {}: {}", address, e);
                return Err(P2PError::Transport(
                    crate::error::TransportError::ConnectionFailed {
                        addr: normalized_addr,
                        reason: e.to_string().into(),
                    },
                ));
            }
            Err(_) => {
                warn!(
                    "connect_happy_eyeballs timed out for {} after {:?}",
                    address, self.connection_timeout
                );
                return Err(P2PError::Timeout(self.connection_timeout));
            }
        };

        let peer_info = PeerInfo {
            channel_id: peer_id.clone(),
            addresses: vec![address.to_string()],
            connected_at: Instant::now(),
            last_seen: Instant::now(),
            status: ConnectionStatus::Connected,
            protocols: vec!["p2p-foundation/1.0".to_string()],
            heartbeat_count: 0,
        };

        self.peers.write().await.insert(peer_id.clone(), peer_info);
        self.active_connections
            .write()
            .await
            .insert(peer_id.clone());

        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.record_bandwidth(0, 0);
        }

        // PeerConnected is emitted later when the peer's identity is
        // authenticated via a signed message — not at transport level.
        info!("Successfully connected to peer: {}", peer_id);
        Ok(peer_id)
    }

    /// Disconnect from a peer, closing the underlying QUIC connection.
    pub async fn disconnect_peer(&self, peer_id: &str) -> Result<()> {
        info!("Disconnecting from peer: {}", peer_id);

        self.dual_node.disconnect_peer_string(peer_id).await.ok();
        self.active_connections.write().await.remove(peer_id);
        // remove_channel_mappings emits PeerDisconnected when the peer's
        // last channel is removed.
        self.remove_channel_mappings(peer_id).await;

        if let Some(mut peer_info) = self.peers.write().await.remove(peer_id) {
            peer_info.status = ConnectionStatus::Disconnected;
            info!("Disconnected from peer: {}", peer_id);
        }

        Ok(())
    }

    /// Disconnect from all peers.
    async fn disconnect_all_peers(&self) -> Result<()> {
        let peer_ids: Vec<String> = self.peers.read().await.keys().cloned().collect();
        for peer_id in peer_ids {
            self.disconnect_peer(&peer_id).await?;
        }
        Ok(())
    }
}

// ============================================================================
// Messaging
// ============================================================================

impl TransportHandle {
    /// Send a message to an authenticated peer (raw, no trust reporting).
    ///
    /// Resolves the app-level [`PeerId`] to a transport channel via the
    /// `peer_to_channel` mapping and sends over that channel.
    pub async fn send_message(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        let peer_hex = peer_id.to_hex();
        let channel = {
            self.peer_to_channel
                .read()
                .await
                .get(peer_id)
                .and_then(|channels| channels.iter().next().cloned())
        };
        let channel_id = channel.ok_or_else(|| {
            P2PError::Network(NetworkError::PeerNotFound(peer_hex.clone().into()))
        })?;
        self.send_on_channel(&channel_id, protocol, data).await
    }

    /// Send a message on a specific transport channel (raw, no trust reporting).
    ///
    /// `channel_id` is the transport-level QUIC connection identifier. Internal
    /// callers (publish, keepalive, etc.) that already have a channel ID use
    /// this method directly to avoid an extra PeerId → channel lookup.
    pub(crate) async fn send_on_channel(
        &self,
        channel_id: &str,
        protocol: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        debug!(
            "Sending message to channel {} on protocol {}",
            channel_id, protocol
        );

        // Check rate limits if resource manager is enabled
        if let Some(ref resource_manager) = self.resource_manager
            && !resource_manager
                .check_rate_limit(channel_id, "message")
                .await?
        {
            return Err(P2PError::ResourceExhausted(
                format!("Rate limit exceeded for channel {}", channel_id).into(),
            ));
        }

        if !self.peers.read().await.contains_key(channel_id) {
            return Err(P2PError::Network(NetworkError::PeerNotFound(
                channel_id.to_string().into(),
            )));
        }

        if !self.is_connection_active(channel_id).await {
            self.remove_channel(channel_id).await;
            return Err(P2PError::Network(NetworkError::ConnectionClosed {
                peer_id: channel_id.to_string().into(),
            }));
        }

        if let Some(ref resource_manager) = self.resource_manager {
            resource_manager.record_bandwidth(data.len() as u64, 0);
        }

        let raw_data_len = data.len();
        let message_data = self.create_protocol_message(protocol, data)?;
        info!(
            "Sending {} bytes to channel {} on protocol {} (raw data: {} bytes)",
            message_data.len(),
            channel_id,
            protocol,
            raw_data_len
        );

        let send_fut = self
            .dual_node
            .send_to_peer_string_optimized(channel_id, &message_data);
        let result = tokio::time::timeout(self.connection_timeout, send_fut)
            .await
            .map_err(|_| {
                P2PError::Transport(crate::error::TransportError::StreamError(
                    "Timed out sending message".into(),
                ))
            })?
            .map_err(|e| {
                P2PError::Transport(crate::error::TransportError::StreamError(
                    e.to_string().into(),
                ))
            });

        if result.is_ok() {
            info!(
                "Successfully sent {} bytes to channel {}",
                message_data.len(),
                channel_id
            );
        } else {
            warn!("Failed to send message to channel {}", channel_id);
        }

        result
    }

    /// Return all channel IDs for an app-level peer, if known.
    pub async fn channels_for_peer(&self, app_peer_id: &PeerId) -> Vec<String> {
        self.peer_to_channel
            .read()
            .await
            .get(app_peer_id)
            .map(|channels| channels.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Get all authenticated app-level peer IDs communicating over a channel.
    pub async fn peers_on_channel(&self, channel_id: &str) -> Vec<PeerId> {
        self.channel_to_peers
            .read()
            .await
            .get(channel_id)
            .map(|set| set.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Return true if `peer_id` is a known authenticated app-level peer ID.
    pub async fn is_known_app_peer_id(&self, peer_id: &PeerId) -> bool {
        self.peer_to_channel.read().await.contains_key(peer_id)
    }

    /// Send a request and wait for a response (no trust reporting).
    ///
    /// This is the raw request-response correlation mechanism. Callers that
    /// need trust feedback should wrap this method (as `P2PNode` does).
    pub async fn send_request(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        data: Vec<u8>,
        timeout: Duration,
    ) -> Result<PeerResponse> {
        let timeout = timeout.min(MAX_REQUEST_TIMEOUT);

        validate_protocol_name(protocol)?;

        let message_id = uuid::Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::oneshot::channel();
        let started_at = Instant::now();

        {
            let mut reqs = self.active_requests.write().await;
            if reqs.len() >= MAX_ACTIVE_REQUESTS {
                return Err(P2PError::Transport(
                    crate::error::TransportError::StreamError(
                        format!(
                            "Too many active requests ({MAX_ACTIVE_REQUESTS}); try again later"
                        )
                        .into(),
                    ),
                ));
            }
            reqs.insert(
                message_id.clone(),
                PendingRequest {
                    response_tx: tx,
                    expected_peer: peer_id.clone(),
                },
            );
        }

        let envelope = RequestResponseEnvelope {
            message_id: message_id.clone(),
            is_response: false,
            payload: data,
        };
        let envelope_bytes = match postcard::to_allocvec(&envelope) {
            Ok(bytes) => bytes,
            Err(e) => {
                self.active_requests.write().await.remove(&message_id);
                return Err(P2PError::Serialization(
                    format!("Failed to serialize request envelope: {e}").into(),
                ));
            }
        };

        let wire_protocol = format!("/rr/{}", protocol);
        if let Err(e) = self
            .send_message(peer_id, &wire_protocol, envelope_bytes)
            .await
        {
            self.active_requests.write().await.remove(&message_id);
            return Err(e);
        }

        let result = match tokio::time::timeout(timeout, rx).await {
            Ok(Ok(response_bytes)) => {
                let latency = started_at.elapsed();
                Ok(PeerResponse {
                    peer_id: peer_id.clone(),
                    data: response_bytes,
                    latency,
                })
            }
            Ok(Err(_)) => Err(P2PError::Network(NetworkError::ConnectionClosed {
                peer_id: peer_id.to_hex().into(),
            })),
            Err(_) => Err(P2PError::Transport(
                crate::error::TransportError::StreamError(
                    format!(
                        "Request to {} on {} timed out after {:?}",
                        peer_id, protocol, timeout
                    )
                    .into(),
                ),
            )),
        };

        self.active_requests.write().await.remove(&message_id);
        result
    }

    /// Send a response to a previously received request.
    pub async fn send_response(
        &self,
        peer_id: &PeerId,
        protocol: &str,
        message_id: &str,
        data: Vec<u8>,
    ) -> Result<()> {
        validate_protocol_name(protocol)?;

        let envelope = RequestResponseEnvelope {
            message_id: message_id.to_string(),
            is_response: true,
            payload: data,
        };
        let envelope_bytes = postcard::to_allocvec(&envelope).map_err(|e| {
            P2PError::Serialization(format!("Failed to serialize response envelope: {e}").into())
        })?;

        let wire_protocol = format!("/rr/{}", protocol);
        self.send_message(peer_id, &wire_protocol, envelope_bytes)
            .await
    }

    /// Parse a request/response envelope from incoming message bytes.
    pub fn parse_request_envelope(data: &[u8]) -> Option<(String, bool, Vec<u8>)> {
        let envelope: RequestResponseEnvelope = postcard::from_bytes(data).ok()?;
        Some((envelope.message_id, envelope.is_response, envelope.payload))
    }

    /// Create a protocol message wrapper (WireMessage serialized with postcard).
    ///
    /// Signs the message with the node's ML-DSA-65 key.
    fn create_protocol_message(&self, protocol: &str, data: Vec<u8>) -> Result<Vec<u8>> {
        let mut message = WireMessage {
            protocol: protocol.to_string(),
            data,
            from: self.node_identity.peer_id().to_hex().clone(),
            timestamp: Self::current_timestamp_secs()?,
            public_key: Vec::new(),
            signature: Vec::new(),
        };

        Self::sign_wire_message(&mut message, &self.node_identity)?;

        Self::serialize_wire_message(&message)
    }

    /// Build a signed identity announce as serialized bytes (static — no `&self`).
    ///
    /// Used by the lifecycle monitor to send an announce immediately after a
    /// transport connection is established, before the full `TransportHandle`
    /// is available in that context.
    fn create_identity_announce_bytes(identity: &NodeIdentity) -> Result<Vec<u8>> {
        let mut message = WireMessage {
            protocol: IDENTITY_ANNOUNCE_PROTOCOL.to_string(),
            data: vec![],
            from: identity.peer_id().to_hex(),
            timestamp: Self::current_timestamp_secs()?,
            public_key: Vec::new(),
            signature: Vec::new(),
        };

        Self::sign_wire_message(&mut message, identity)?;
        Self::serialize_wire_message(&message)
    }

    /// Get the current Unix timestamp in seconds.
    fn current_timestamp_secs() -> Result<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .map_err(|e| {
                P2PError::Network(NetworkError::ProtocolError(
                    format!("System time error: {e}").into(),
                ))
            })
    }

    /// Sign a `WireMessage` in place using the given identity.
    fn sign_wire_message(message: &mut WireMessage, identity: &NodeIdentity) -> Result<()> {
        let signable = Self::compute_signable_bytes(
            &message.protocol,
            &message.data,
            &message.from,
            message.timestamp,
        )?;
        let sig = identity.sign(&signable).map_err(|e| {
            P2PError::Network(NetworkError::ProtocolError(
                format!("Failed to sign message: {e}").into(),
            ))
        })?;
        message.public_key = identity.public_key().as_bytes().to_vec();
        message.signature = sig.as_bytes().to_vec();
        Ok(())
    }

    /// Serialize a `WireMessage` to postcard bytes.
    fn serialize_wire_message(message: &WireMessage) -> Result<Vec<u8>> {
        postcard::to_stdvec(message).map_err(|e| {
            P2PError::Transport(crate::error::TransportError::StreamError(
                format!("Failed to serialize wire message: {e}").into(),
            ))
        })
    }

    /// Compute the canonical bytes to sign/verify for a WireMessage.
    fn compute_signable_bytes(
        protocol: &str,
        data: &[u8],
        from: &str,
        timestamp: u64,
    ) -> Result<Vec<u8>> {
        postcard::to_stdvec(&(protocol, data, from, timestamp)).map_err(|e| {
            P2PError::Network(NetworkError::ProtocolError(
                format!("Failed to serialize signable bytes: {e}").into(),
            ))
        })
    }
}

// ============================================================================
// Pub/Sub
// ============================================================================

impl TransportHandle {
    /// Subscribe to a topic (currently a no-op stub).
    pub async fn subscribe(&self, topic: &str) -> Result<()> {
        info!("Subscribed to topic: {}", topic);
        Ok(())
    }

    /// Publish a message to all connected peers on the given topic.
    pub async fn publish(&self, topic: &str, data: &[u8]) -> Result<()> {
        info!(
            "Publishing message to topic: {} ({} bytes)",
            topic,
            data.len()
        );

        let peer_list: Vec<String> = {
            let peers_guard = self.peers.read().await;
            peers_guard.keys().cloned().collect()
        };

        if peer_list.is_empty() {
            debug!("No peers connected, message will only be sent to local subscribers");
        } else {
            let mut send_count = 0;
            for channel_id in &peer_list {
                match self.send_on_channel(channel_id, topic, data.to_vec()).await {
                    Ok(()) => {
                        send_count += 1;
                        debug!("Sent message to channel: {}", channel_id);
                    }
                    Err(e) => {
                        warn!("Failed to send message to channel {}: {}", channel_id, e);
                    }
                }
            }
            info!(
                "Published message to {}/{} connected peers",
                send_count,
                peer_list.len()
            );
        }

        self.send_event(P2PEvent::Message {
            topic: topic.to_string(),
            source: Some(self.node_identity.peer_id().clone()),
            data: data.to_vec(),
        });

        Ok(())
    }
}

// ============================================================================
// Events
// ============================================================================

impl TransportHandle {
    /// Subscribe to network events.
    pub fn subscribe_events(&self) -> broadcast::Receiver<P2PEvent> {
        self.event_tx.subscribe()
    }

    /// Send an event to all subscribers.
    pub(crate) fn send_event(&self, event: P2PEvent) {
        if let Err(e) = self.event_tx.send(event) {
            tracing::trace!("Event broadcast has no receivers: {e}");
        }
    }
}

// ============================================================================
// Network Listeners & Receive System
// ============================================================================

impl TransportHandle {
    /// Start network listeners on the dual-stack transport.
    pub async fn start_network_listeners(&self) -> Result<()> {
        info!("Starting dual-stack listeners (ant-quic)...");
        let addrs = self.dual_node.local_addrs().await.map_err(|e| {
            P2PError::Transport(crate::error::TransportError::SetupFailed(
                format!("Failed to get local addresses: {}", e).into(),
            ))
        })?;
        {
            let mut la = self.listen_addrs.write().await;
            *la = addrs.clone();
        }

        let peers = self.peers.clone();
        let active_connections = self.active_connections.clone();
        let rate_limiter = self.rate_limiter.clone();
        let dual = self.dual_node.clone();

        let handle = tokio::spawn(async move {
            loop {
                let Some((ant_peer_id, remote_sock)) = dual.accept_any().await else {
                    break;
                };

                if let Err(e) = rate_limiter.check_ip(&remote_sock.ip()) {
                    warn!(
                        "Rate-limited incoming connection from {}: {}",
                        remote_sock, e
                    );
                    continue;
                }

                let channel_id = ant_peer_id_to_string(&ant_peer_id);
                let remote_addr = NetworkAddress::from(remote_sock);
                // PeerConnected is emitted later when the peer's identity is
                // authenticated via a signed message — not at transport level.
                register_new_channel(&peers, &channel_id, &remote_addr).await;
                active_connections.write().await.insert(channel_id);
            }
        });
        *self.listener_handle.write().await = Some(handle);

        self.start_message_receiving_system().await?;

        info!("Dual-stack listeners active on: {:?}", addrs);
        Ok(())
    }

    /// Spawns per-stack recv tasks and a dispatcher that routes incoming messages.
    async fn start_message_receiving_system(&self) -> Result<()> {
        info!("Starting message receiving system");

        let (tx, mut rx) = tokio::sync::mpsc::channel(MESSAGE_RECV_CHANNEL_CAPACITY);

        let mut handles = Vec::new();

        if let Some(v6) = self.dual_node.v6.as_ref() {
            handles.push(v6.spawn_recv_task(tx.clone(), self.shutdown.clone()));
        }
        if let Some(v4) = self.dual_node.v4.as_ref() {
            handles.push(v4.spawn_recv_task(tx.clone(), self.shutdown.clone()));
        }
        drop(tx);

        let event_tx = self.event_tx.clone();
        let active_requests = Arc::clone(&self.active_requests);
        let peers_for_recv = Arc::clone(&self.peers);
        let peer_to_channel = Arc::clone(&self.peer_to_channel);
        let channel_to_peers = Arc::clone(&self.channel_to_peers);
        handles.push(tokio::spawn(async move {
            info!("Message receive loop started");
            while let Some((ant_id, bytes)) = rx.recv().await {
                let channel_id = ant_peer_id_to_string(&ant_id);
                trace!("Received {} bytes from channel {}", bytes.len(), channel_id);

                // Any incoming data (keepalive or protocol message) proves the peer
                // is alive — update last_seen so the stale-peer reaper doesn't
                // disconnect active peers.
                touch_channel_last_seen(&peers_for_recv, &channel_id).await;

                if bytes == KEEPALIVE_PAYLOAD {
                    trace!("Received keepalive from {}", channel_id);
                    continue;
                }

                match parse_protocol_message(&bytes, &channel_id) {
                    Some(ParsedMessage {
                        event,
                        authenticated_node_id,
                    }) => {
                        // If the message was signed, record the app↔channel mapping.
                        // A peer may be reachable over multiple channels simultaneously
                        // (e.g. QUIC + Bluetooth), so we add to the set — never replace.
                        if let Some(ref app_id) = authenticated_node_id {
                            let mut p2c = peer_to_channel.write().await;
                            let is_new_peer = !p2c.contains_key(app_id);
                            let channels = p2c.entry(app_id.clone()).or_default();
                            let inserted = channels.insert(channel_id.clone());
                            if inserted {
                                channel_to_peers
                                    .write()
                                    .await
                                    .entry(channel_id.clone())
                                    .or_default()
                                    .insert(app_id.clone());
                            }
                            // Drop the lock before emitting events.
                            drop(p2c);

                            if is_new_peer {
                                broadcast_event(&event_tx, P2PEvent::PeerConnected(app_id.clone()));
                            }
                        }

                        // Identity announces are internal plumbing — don't
                        // emit as app-level messages.
                        if let P2PEvent::Message { ref topic, .. } = event
                            && topic == IDENTITY_ANNOUNCE_PROTOCOL
                        {
                            continue;
                        }

                        if let P2PEvent::Message {
                            ref topic,
                            ref data,
                            ..
                        } = event
                            && topic.starts_with("/rr/")
                            && let Ok(envelope) =
                                postcard::from_bytes::<RequestResponseEnvelope>(data)
                            && envelope.is_response
                        {
                            let mut reqs = active_requests.write().await;
                            let expected_peer = match reqs.get(&envelope.message_id) {
                                Some(pending) => pending.expected_peer.clone(),
                                None => {
                                    trace!(
                                        message_id = %envelope.message_id,
                                        "Unmatched /rr/ response (likely timed out) — suppressing"
                                    );
                                    continue;
                                }
                            };
                            // Accept response only if the authenticated app-level
                            // identity matches. Channel IDs identify connections,
                            // not peers, so they are not checked here.
                            if authenticated_node_id.as_ref() != Some(&expected_peer) {
                                warn!(
                                    message_id = %envelope.message_id,
                                    expected = %expected_peer,
                                    actual_channel = %channel_id,
                                    authenticated = ?authenticated_node_id,
                                    "Response origin mismatch — ignoring"
                                );
                                continue;
                            }
                            if let Some(pending) = reqs.remove(&envelope.message_id) {
                                if pending.response_tx.send(envelope.payload).is_err() {
                                    warn!(
                                        message_id = %envelope.message_id,
                                        "Response receiver dropped before delivery"
                                    );
                                }
                                continue;
                            }
                            trace!(
                                message_id = %envelope.message_id,
                                "Unmatched /rr/ response (likely timed out) — suppressing"
                            );
                            continue;
                        }
                        broadcast_event(&event_tx, event);
                    }
                    None => {
                        warn!("Failed to parse protocol message ({} bytes)", bytes.len());
                    }
                }
            }
            info!("Message receive loop ended — channel closed");
        }));

        *self.recv_handles.write().await = handles;
        Ok(())
    }
}

// ============================================================================
// Shutdown
// ============================================================================

impl TransportHandle {
    /// Stop the transport layer: shutdown endpoints, join tasks, disconnect peers.
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping transport...");

        self.shutdown.cancel();
        self.dual_node.shutdown_endpoints().await;

        // Await recv system tasks
        let handles: Vec<_> = self.recv_handles.write().await.drain(..).collect();
        Self::join_task_handles(handles, "recv").await;
        Self::join_task_slot(&self.listener_handle, "listener").await;
        Self::join_task_slot(&self.connection_monitor_handle, "connection monitor").await;
        Self::join_task_slot(&self.keepalive_handle, "keepalive").await;
        Self::join_task_slot(&self.periodic_tasks_handle, "periodic maintenance").await;

        self.disconnect_all_peers().await?;

        info!("Transport stopped");
        Ok(())
    }

    async fn join_task_slot(handle_slot: &RwLock<Option<JoinHandle<()>>>, task_name: &str) {
        let handle = handle_slot.write().await.take();
        if let Some(handle) = handle {
            Self::join_task_handle(handle, task_name).await;
        }
    }

    async fn join_task_handles(handles: Vec<JoinHandle<()>>, task_name: &str) {
        for handle in handles {
            Self::join_task_handle(handle, task_name).await;
        }
    }

    async fn join_task_handle(handle: JoinHandle<()>, task_name: &str) {
        match handle.await {
            Ok(()) => {}
            Err(e) if e.is_cancelled() => {
                tracing::debug!("{task_name} task was cancelled during shutdown");
            }
            Err(e) if e.is_panic() => {
                tracing::error!("{task_name} task panicked during shutdown: {:?}", e);
            }
            Err(e) => {
                tracing::warn!("{task_name} task join error during shutdown: {:?}", e);
            }
        }
    }

    /// Run periodic maintenance: detect stale peers and clean up.
    ///
    /// Called from `P2PNode::run()` and `P2PNode::periodic_tasks()`.
    pub async fn maintenance_tick(&self) -> Result<()> {
        let stale_threshold = self.stale_peer_threshold;
        let cleanup_threshold = stale_threshold * CLEANUP_THRESHOLD_MULTIPLIER;

        let (peers_to_remove, peers_to_mark_disconnected) = {
            let peers = self.peers.read().await;
            categorize_stale_peers(&peers, Instant::now(), stale_threshold, cleanup_threshold)
        };

        if !peers_to_mark_disconnected.is_empty() {
            let mut peers = self.peers.write().await;
            for peer_id in &peers_to_mark_disconnected {
                if let Some(peer_info) = peers.get_mut(peer_id) {
                    peer_info.status = ConnectionStatus::Disconnected;
                }
            }
        }

        for peer_id in &peers_to_mark_disconnected {
            self.active_connections.write().await.remove(peer_id);
            // remove_channel_mappings emits PeerDisconnected when the peer's
            // last channel is removed.
            self.remove_channel_mappings(peer_id).await;
            info!(peer_id = %peer_id, "Stale peer disconnected");
        }

        if !peers_to_remove.is_empty() {
            let mut peers = self.peers.write().await;
            for peer_id in &peers_to_remove {
                peers.remove(peer_id);
                trace!(peer_id = %peer_id, "Peer removed from tracking");
            }
        }

        Ok(())
    }
}

// ============================================================================
// Background Tasks (static)
// ============================================================================

impl TransportHandle {
    /// Connection lifecycle monitor — processes ant-quic connection events.
    #[allow(clippy::too_many_arguments)]
    async fn connection_lifecycle_monitor_with_rx(
        dual_node: Arc<DualStackNetworkNode>,
        mut event_rx: broadcast::Receiver<crate::transport::ant_quic_adapter::ConnectionEvent>,
        active_connections: Arc<RwLock<HashSet<String>>>,
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        event_tx: broadcast::Sender<P2PEvent>,
        geo_provider: Arc<BgpGeoProvider>,
        shutdown: CancellationToken,
        peer_to_channel: Arc<RwLock<HashMap<PeerId, HashSet<String>>>>,
        channel_to_peers: Arc<RwLock<HashMap<String, HashSet<PeerId>>>>,
        node_identity: Arc<NodeIdentity>,
    ) {
        info!("Connection lifecycle monitor started (pre-subscribed receiver)");

        loop {
            tokio::select! {
                () = shutdown.cancelled() => {
                    info!("Connection lifecycle monitor shutting down");
                    break;
                }
                recv = event_rx.recv() => {
                    match recv {
                        Ok(event) => match event {
                            ConnectionEvent::Established {
                                peer_id,
                                remote_address,
                            } => {
                                let channel_id = ant_peer_id_to_string(&peer_id);
                                debug!(
                                    "Connection established: channel={}, addr={}",
                                    channel_id, remote_address
                                );

                                let ip = remote_address.ip();
                                let is_rejected = match ip {
                                    std::net::IpAddr::V4(v4) => {
                                        if let Some(asn) = geo_provider.lookup_ipv4_asn(v4) {
                                            geo_provider.is_hosting_asn(asn) || geo_provider.is_vpn_asn(asn)
                                        } else {
                                            false
                                        }
                                    }
                                    std::net::IpAddr::V6(v6) => {
                                        let info = geo_provider.lookup(v6);
                                        info.is_hosting_provider || info.is_vpn_provider
                                    }
                                };

                                if is_rejected {
                                    info!(
                                        "Rejecting connection from {} ({}) due to GeoIP policy",
                                        channel_id, remote_address
                                    );
                                    dual_node.disconnect_peer(&peer_id).await;
                                    continue;
                                }

                                active_connections.write().await.insert(channel_id.clone());

                                let mut peers_lock = peers.write().await;
                                if let Some(peer_info) = peers_lock.get_mut(&channel_id) {
                                    peer_info.status = ConnectionStatus::Connected;
                                    peer_info.connected_at = Instant::now();
                                } else {
                                    debug!("Registering new incoming channel: {}", channel_id);
                                    peers_lock.insert(
                                        channel_id.clone(),
                                        PeerInfo {
                                            channel_id: channel_id.clone(),
                                            addresses: vec![remote_address.to_string()],
                                            status: ConnectionStatus::Connected,
                                            last_seen: Instant::now(),
                                            connected_at: Instant::now(),
                                            protocols: Vec::new(),
                                            heartbeat_count: 0,
                                        },
                                    );
                                }

                                // Send identity announce so the remote peer can authenticate us.
                                match Self::create_identity_announce_bytes(&node_identity) {
                                    Ok(announce_bytes) => {
                                        if let Err(e) = dual_node
                                            .send_to_peer_string_optimized(&channel_id, &announce_bytes)
                                            .await
                                        {
                                            warn!("Failed to send identity announce to {channel_id}: {e}");
                                        }
                                    }
                                    Err(e) => {
                                        warn!("Failed to create identity announce: {e}");
                                    }
                                }

                                // PeerConnected is emitted when the remote receives and
                                // verifies our identity announce — not at transport level.
                            }
                            ConnectionEvent::Lost { peer_id, reason }
                            | ConnectionEvent::Failed { peer_id, reason } => {
                                let channel_id = ant_peer_id_to_string(&peer_id);
                                debug!("Connection lost/failed: channel={channel_id}, reason={reason}");

                                active_connections.write().await.remove(&channel_id);
                                if let Some(peer_info) = peers.write().await.get_mut(&channel_id) {
                                    peer_info.status = ConnectionStatus::Disconnected;
                                    peer_info.last_seen = Instant::now();
                                }
                                // Remove channel mappings and emit PeerDisconnected
                                // when the peer's last channel is closed.
                                Self::remove_channel_mappings_static(
                                    &channel_id,
                                    &peer_to_channel,
                                    &channel_to_peers,
                                    &event_tx,
                                ).await;
                            }
                        },
                        Err(broadcast::error::RecvError::Lagged(skipped)) => {
                            warn!(
                                "Connection event receiver lagged, skipped {} events",
                                skipped
                            );
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            info!("Connection event channel closed, stopping lifecycle monitor");
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Keepalive task — sends periodic pings to prevent idle timeout.
    async fn keepalive_task(
        active_connections: Arc<RwLock<HashSet<String>>>,
        dual_node: Arc<DualStackNetworkNode>,
        shutdown: CancellationToken,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(KEEPALIVE_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            "Keepalive task started (interval: {}s)",
            KEEPALIVE_INTERVAL_SECS
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                () = shutdown.cancelled() => {
                    info!("Keepalive task shutting down");
                    break;
                }
            }

            let peers: Vec<String> = { active_connections.read().await.iter().cloned().collect() };

            if peers.is_empty() {
                trace!("Keepalive: no active connections");
                continue;
            }

            debug!("Sending keepalive to {} active connections", peers.len());

            let futs: Vec<_> = peers
                .into_iter()
                .map(|peer_id| {
                    let node = Arc::clone(&dual_node);
                    async move {
                        if let Err(e) = node
                            .send_to_peer_string_optimized(&peer_id, KEEPALIVE_PAYLOAD)
                            .await
                        {
                            debug!(
                                "Failed to send keepalive to peer {}: {} (connection may have closed)",
                                peer_id, e
                            );
                        } else {
                            trace!("Keepalive sent to peer: {}", peer_id);
                        }
                    }
                })
                .collect();
            futures::future::join_all(futs).await;
        }

        info!("Keepalive task stopped");
    }

    /// Periodic maintenance task — detects stale peers and removes them.
    async fn periodic_maintenance_task(
        peers: Arc<RwLock<HashMap<String, PeerInfo>>>,
        active_connections: Arc<RwLock<HashSet<String>>>,
        event_tx: broadcast::Sender<P2PEvent>,
        stale_threshold: Duration,
        shutdown: CancellationToken,
        peer_to_channel: Arc<RwLock<HashMap<PeerId, HashSet<String>>>>,
        channel_to_peers: Arc<RwLock<HashMap<String, HashSet<PeerId>>>>,
    ) {
        let cleanup_threshold = stale_threshold * CLEANUP_THRESHOLD_MULTIPLIER;
        let mut interval = tokio::time::interval(Duration::from_millis(MAINTENANCE_INTERVAL_MS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        info!(
            "Periodic maintenance task started (stale threshold: {:?})",
            stale_threshold
        );

        loop {
            tokio::select! {
                _ = interval.tick() => {}
                () = shutdown.cancelled() => break,
            }

            let (peers_to_remove, peers_to_mark_disconnected) = {
                let peers_lock = peers.read().await;
                categorize_stale_peers(
                    &peers_lock,
                    Instant::now(),
                    stale_threshold,
                    cleanup_threshold,
                )
            };

            if !peers_to_mark_disconnected.is_empty() {
                let mut peers_lock = peers.write().await;
                for peer_id in &peers_to_mark_disconnected {
                    if let Some(peer_info) = peers_lock.get_mut(peer_id) {
                        peer_info.status = ConnectionStatus::Disconnected;
                    }
                }
            }

            for peer_id in &peers_to_mark_disconnected {
                active_connections.write().await.remove(peer_id);
                // remove_channel_mappings_static emits PeerDisconnected when
                // the peer's last channel is removed.
                Self::remove_channel_mappings_static(
                    peer_id,
                    &peer_to_channel,
                    &channel_to_peers,
                    &event_tx,
                )
                .await;
                info!(peer_id = %peer_id, "Stale peer disconnected");
            }

            if !peers_to_remove.is_empty() {
                let mut peers_lock = peers.write().await;
                for peer_id in &peers_to_remove {
                    peers_lock.remove(peer_id);
                    trace!(peer_id = %peer_id, "Peer removed from tracking");
                }
            }
        }

        info!("Periodic maintenance task stopped");
    }
}

// ============================================================================
// Free helper functions
// ============================================================================

/// Validate that a protocol name is non-empty and contains no path separators or null bytes.
fn validate_protocol_name(protocol: &str) -> Result<()> {
    if protocol.is_empty() || protocol.contains(&['/', '\\', '\0'][..]) {
        return Err(P2PError::Transport(
            crate::error::TransportError::StreamError(
                format!("Invalid protocol name: {:?}", protocol).into(),
            ),
        ));
    }
    Ok(())
}

/// Categorize peers into those needing removal vs disconnection based on staleness.
///
/// Returns `(peers_to_remove, peers_to_mark_disconnected)`.
fn categorize_stale_peers(
    peers: &HashMap<String, PeerInfo>,
    now: Instant,
    stale_threshold: Duration,
    cleanup_threshold: Duration,
) -> (Vec<String>, Vec<String>) {
    let mut peers_to_remove = Vec::new();
    let mut peers_to_mark_disconnected = Vec::new();

    for (peer_id, peer_info) in peers.iter() {
        let elapsed = now.duration_since(peer_info.last_seen);

        match &peer_info.status {
            ConnectionStatus::Connected => {
                if elapsed > stale_threshold {
                    debug!(
                        peer_id = %peer_id,
                        elapsed_secs = elapsed.as_secs(),
                        "Peer went stale - marking for disconnection"
                    );
                    peers_to_mark_disconnected.push(peer_id.clone());
                }
            }
            ConnectionStatus::Disconnected | ConnectionStatus::Failed(_) => {
                if elapsed > cleanup_threshold {
                    trace!(
                        peer_id = %peer_id,
                        elapsed_secs = elapsed.as_secs(),
                        "Removing disconnected peer from tracking"
                    );
                    peers_to_remove.push(peer_id.clone());
                }
            }
            ConnectionStatus::Connecting | ConnectionStatus::Disconnecting => {
                if elapsed > stale_threshold {
                    debug!(
                        peer_id = %peer_id,
                        status = ?peer_info.status,
                        "Connection timed out in transitional state"
                    );
                    peers_to_mark_disconnected.push(peer_id.clone());
                }
            }
        }
    }

    (peers_to_remove, peers_to_mark_disconnected)
}

// ============================================================================
// NetworkSender impl
// ============================================================================

#[async_trait::async_trait]
impl NetworkSender for TransportHandle {
    async fn send_message(&self, peer_id: &PeerId, protocol: &str, data: Vec<u8>) -> Result<()> {
        TransportHandle::send_message(self, peer_id, protocol, data).await
    }

    fn local_peer_id(&self) -> PeerId {
        self.peer_id()
    }
}

// Test-only helpers for injecting state
#[cfg(test)]
impl TransportHandle {
    /// Insert a peer into the peers map (test helper)
    pub(crate) async fn inject_peer(&self, peer_id: String, info: PeerInfo) {
        self.peers.write().await.insert(peer_id, info);
    }

    /// Insert a channel ID into the active_connections set (test helper)
    pub(crate) async fn inject_active_connection(&self, channel_id: String) {
        self.active_connections.write().await.insert(channel_id);
    }
}
