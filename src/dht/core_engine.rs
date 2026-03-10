//! Enhanced DHT Core Engine with Kademlia routing and intelligent data distribution
//!
//! Provides the main DHT functionality with k=8 replication, load balancing, and fault tolerance.

use crate::PeerId;
use crate::adaptive::EigenTrustEngine;
use crate::dht::geographic_routing::GeographicRegion;
use crate::dht::metrics::SecurityMetricsCollector;
use crate::dht::network_integration::{DhtMessage, DhtResponse};
use crate::dht::routing_maintenance::close_group_validator::{
    CloseGroupEnforcementMode, CloseGroupFailure, CloseGroupValidator, CloseGroupValidatorConfig,
};
use crate::dht::routing_maintenance::{
    BucketRefreshManager, EvictionManager, EvictionReason, MaintenanceConfig,
};
use crate::dht::trust_peer_selector::{TrustAwarePeerSelector, TrustSelectionConfig};
use crate::network::NetworkSender;
use crate::security::IPDiversityConfig;
use anyhow::{Context, Result, anyhow};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::{RwLock, oneshot};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// DHT key type — now a direct alias for [`PeerId`].
///
/// Both types are `[u8; 32]` wrappers with identity conversions between them.
/// Using a single type eliminates keyspace mismatch bugs where BLAKE3-hashing
/// a PeerId into a second "DHT key" space caused nodes to land in wrong
/// Kademlia buckets.
pub type DhtKey = PeerId;

#[inline]
fn xor_distance_bytes(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (idx, byte) in out.iter_mut().enumerate() {
        *byte = a[idx] ^ b[idx];
    }
    out
}

/// Node information for routing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: PeerId,
    pub address: String,
    pub last_seen: SystemTime,
    pub capacity: NodeCapacity,
}

/// Node capacity metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapacity {
    pub storage_available: u64,
    pub bandwidth_available: u64,
    pub reliability_score: f64,
}

impl Default for NodeCapacity {
    fn default() -> Self {
        Self {
            storage_available: 1_000_000_000, // 1GB
            bandwidth_available: 10_000_000,  // 10MB/s
            reliability_score: 1.0,
        }
    }
}

/// K-bucket for Kademlia routing
struct KBucket {
    nodes: Vec<NodeInfo>,
    max_size: usize,
}

impl KBucket {
    fn new(max_size: usize) -> Self {
        Self {
            nodes: Vec::new(),
            max_size,
        }
    }

    fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        // If the node is already in this bucket, replace it fully and move to
        // tail (most-recently-seen) per standard Kademlia protocol.
        if let Some(pos) = self.nodes.iter().position(|n| n.id == node.id) {
            self.nodes.remove(pos);
            self.nodes.push(node);
            return Ok(());
        }

        if self.nodes.len() < self.max_size {
            self.nodes.push(node);
            Ok(())
        } else {
            Err(anyhow!(
                "K-bucket at capacity ({}/{})",
                self.nodes.len(),
                self.max_size
            ))
        }
    }

    fn remove_node(&mut self, node_id: &PeerId) {
        self.nodes.retain(|n| &n.id != node_id);
    }

    /// Update `last_seen` (and optionally the address) for a node, then move
    /// it to the tail of the bucket (most recently seen) per Kademlia protocol.
    fn touch_node(&mut self, node_id: &PeerId, address: Option<&str>) -> bool {
        if let Some(pos) = self.nodes.iter().position(|n| &n.id == node_id) {
            self.nodes[pos].last_seen = SystemTime::now();
            if let Some(addr) = address {
                self.nodes[pos].address = addr.to_string();
            }
            let node = self.nodes.remove(pos);
            self.nodes.push(node);
            true
        } else {
            false
        }
    }

    fn get_nodes(&self) -> &[NodeInfo] {
        &self.nodes
    }

    fn find_node(&self, node_id: &PeerId) -> Option<&NodeInfo> {
        self.nodes.iter().find(|n| &n.id == node_id)
    }
}

/// Kademlia routing table
pub struct KademliaRoutingTable {
    buckets: Vec<KBucket>,
    node_id: PeerId,
    _k_value: usize,
}

impl KademliaRoutingTable {
    fn new(node_id: PeerId, k_value: usize) -> Self {
        let mut buckets = Vec::new();
        for _ in 0..KADEMLIA_BUCKET_COUNT {
            buckets.push(KBucket::new(k_value));
        }

        Self {
            buckets,
            node_id,
            _k_value: k_value,
        }
    }

    fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        let bucket_index = self.get_bucket_index(&node.id);
        self.buckets[bucket_index].add_node(node)
    }

    fn remove_node(&mut self, node_id: &PeerId) {
        let bucket_index = self.get_bucket_index(node_id);
        self.buckets[bucket_index].remove_node(node_id);
    }

    /// Update `last_seen` (and optionally address) for a node and move it to
    /// the tail of its k-bucket. Returns `true` if the node was found.
    fn touch_node(&mut self, node_id: &PeerId, address: Option<&str>) -> bool {
        let bucket_index = self.get_bucket_index(node_id);
        self.buckets[bucket_index].touch_node(node_id, address)
    }

    fn find_closest_nodes(&self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        // Optimization: Start from the bucket closest to the key and work outwards
        // This avoids collecting all nodes from all 256 buckets when we only need a few
        let target_bucket = self.get_bucket_index_for_key(key);

        let mut candidates: Vec<(NodeInfo, [u8; 32])> = Vec::with_capacity(count * 2);

        // Visit buckets in order of proximity to target, each exactly once.
        // Uses checked arithmetic so indices that would exceed [0, 255] are
        // skipped rather than clamped, preventing duplicate bucket visits.
        let bucket_iter = std::iter::once(target_bucket).chain(
            (1..KADEMLIA_BUCKET_COUNT).flat_map(move |offset| {
                let above = target_bucket
                    .checked_add(offset)
                    .filter(|&b| b < KADEMLIA_BUCKET_COUNT);
                let below = target_bucket.checked_sub(offset);
                above.into_iter().chain(below)
            }),
        );

        for bucket_idx in bucket_iter {
            for node in self.buckets[bucket_idx].get_nodes() {
                let distance = xor_distance_bytes(node.id.to_bytes(), key.as_bytes());
                candidates.push((node.clone(), distance));
            }

            // Early exit: if we have enough candidates, we can stop expanding
            if candidates.len() >= count * CANDIDATE_EXPANSION_FACTOR {
                break;
            }
        }

        // Sort by distance
        candidates.sort_by(|a, b| a.1.cmp(&b.1));

        // Return top `count` nodes
        candidates
            .into_iter()
            .take(count)
            .map(|(node, _)| node)
            .collect()
    }

    fn get_bucket_index_for_key(&self, key: &DhtKey) -> usize {
        let distance = xor_distance_bytes(self.node_id.to_bytes(), key.as_bytes());

        // Find first bit that differs
        for i in 0..256 {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);

            if (distance[byte_index] >> bit_index) & 1 == 1 {
                return i;
            }
        }

        255 // Same key as node
    }

    /// Look up a node by its exact peer ID. O(K) scan of the target bucket.
    fn find_node_by_id(&self, node_id: &PeerId) -> Option<&NodeInfo> {
        let bucket_index = self.get_bucket_index(node_id);
        self.buckets[bucket_index].find_node(node_id)
    }

    /// Total number of nodes across all buckets.
    pub fn node_count(&self) -> usize {
        self.buckets.iter().map(|b| b.get_nodes().len()).sum()
    }

    /// Iterate over every node in the routing table.
    fn iter_nodes(&self) -> impl Iterator<Item = &NodeInfo> {
        self.buckets.iter().flat_map(|b| b.get_nodes().iter())
    }

    fn get_bucket_index(&self, node_id: &PeerId) -> usize {
        let distance = xor_distance_bytes(self.node_id.to_bytes(), node_id.to_bytes());

        // Find first bit that differs
        for i in 0..256 {
            let byte_index = i / 8;
            let bit_index = 7 - (i % 8);

            if (distance[byte_index] >> bit_index) & 1 == 1 {
                return i;
            }
        }

        255 // Same node
    }
}

/// Consistency level for operations
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum ConsistencyLevel {
    One,    // At least 1 replica
    Quorum, // Majority of replicas
    All,    // All replicas
}

/// Load metrics for a node
#[derive(Debug, Clone)]
pub struct LoadMetric {
    pub storage_used_percent: f64,
    pub bandwidth_used_percent: f64,
    pub request_rate: f64,
}

/// Store receipt for DHT operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreReceipt {
    pub key: DhtKey,
    pub stored_at: Vec<PeerId>,
    pub timestamp: SystemTime,
    pub success: bool,
}

impl StoreReceipt {
    pub fn is_successful(&self) -> bool {
        self.success
    }
}

/// Data store for local storage
struct DataStore {
    data: HashMap<DhtKey, Vec<u8>>,
    metadata: HashMap<DhtKey, DataMetadata>,
}

#[derive(Debug, Clone)]
struct DataMetadata {
    _size: usize,
    _stored_at: SystemTime,
    access_count: u64,
    last_accessed: SystemTime,
}

impl DataStore {
    fn new() -> Self {
        Self {
            data: HashMap::new(),
            metadata: HashMap::new(),
        }
    }

    fn put(&mut self, key: DhtKey, value: Vec<u8>) {
        let metadata = DataMetadata {
            _size: value.len(),
            _stored_at: SystemTime::now(),
            access_count: 0,
            last_accessed: SystemTime::now(),
        };

        self.data.insert(key, value);
        self.metadata.insert(key, metadata);
    }

    fn get(&mut self, key: &DhtKey) -> Option<Vec<u8>> {
        if let Some(metadata) = self.metadata.get_mut(key) {
            metadata.access_count += 1;
            metadata.last_accessed = SystemTime::now();
        }

        self.data.get(key).cloned()
    }

    fn _remove(&mut self, key: &DhtKey) -> Option<Vec<u8>> {
        self.metadata.remove(key);
        self.data.remove(key)
    }
}

/// Replication manager for maintaining data redundancy
struct ReplicationManager {
    _replication_factor: usize,
    _consistency_level: ConsistencyLevel,
    _pending_repairs: Vec<DhtKey>,
}

impl ReplicationManager {
    fn new(replication_factor: usize) -> Self {
        Self {
            _replication_factor: replication_factor,
            _consistency_level: ConsistencyLevel::Quorum,
            _pending_repairs: Vec::new(),
        }
    }

    fn _required_replicas(&self) -> usize {
        match self._consistency_level {
            ConsistencyLevel::One => 1,
            // Quorum requires strict majority for Byzantine fault tolerance: floor(n/2) + 1
            // For K=8, this gives 5 (tolerates 3 failures). This is intentionally stricter
            // than simple majority (div_ceil which gives 4) to ensure BFT guarantees.
            ConsistencyLevel::Quorum => (self._replication_factor / 2) + 1,
            ConsistencyLevel::All => self._replication_factor,
        }
    }

    fn _schedule_repair(&mut self, key: DhtKey) {
        if !self._pending_repairs.contains(&key) {
            self._pending_repairs.push(key);
        }
    }
}

/// Load balancer for intelligent data distribution
struct LoadBalancer {
    node_loads: HashMap<PeerId, LoadMetric>,
    _rebalance_threshold: f64,
}

impl LoadBalancer {
    fn new() -> Self {
        Self {
            node_loads: HashMap::new(),
            _rebalance_threshold: 0.8,
        }
    }

    fn _update_load(&mut self, node_id: PeerId, load: LoadMetric) {
        self.node_loads.insert(node_id, load);
    }

    fn select_least_loaded(&self, candidates: &[NodeInfo], count: usize) -> Vec<PeerId> {
        // Filter NaN values during collection to avoid intermediate allocations with invalid data
        let mut sorted: Vec<_> = candidates
            .iter()
            .filter_map(|node| {
                let load = self
                    .node_loads
                    .get(&node.id)
                    .map(|l| l.storage_used_percent)
                    .unwrap_or(0.0);
                // Filter NaN during collection rather than after
                if load.is_nan() {
                    None
                } else {
                    Some((node.id, load))
                }
            })
            .collect();

        // Use total_cmp for safe float comparison
        sorted.sort_by(|a, b| a.1.total_cmp(&b.1));

        sorted.into_iter().take(count).map(|(id, _)| id).collect()
    }

    fn _should_rebalance(&self) -> bool {
        self.node_loads
            .values()
            .any(|load| load.storage_used_percent > self._rebalance_threshold)
    }
}

// ---------------------------------------------------------------------------
// Address parsing and subnet masking helpers for diversity checks
// ---------------------------------------------------------------------------

/// Parse an IP address from a node address string ("ip:port" or bare "ip").
fn parse_ip(address: &str) -> Option<IpAddr> {
    if let Ok(socket) = address.parse::<SocketAddr>() {
        Some(socket.ip())
    } else {
        address.parse::<IpAddr>().ok()
    }
}

/// Zero out the host bits of an IPv4 address beyond `prefix_len`.
fn mask_ipv4(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Addr {
    let bits = u32::from(addr);
    let mask = if prefix_len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix_len)
    };
    Ipv4Addr::from(bits & mask)
}

/// Zero out the host bits of an IPv6 address beyond `prefix_len`.
fn mask_ipv6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let bits = u128::from(addr);
    let mask = if prefix_len >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix_len)
    };
    Ipv6Addr::from(bits & mask)
}

/// Default maximum nodes per geographic region. Matches
/// `GeographicRoutingConfig::max_nodes_per_region` default.
const GEO_DEFAULT_MAX_PER_REGION: usize = 50;

/// DHT query timeout duration
const DHT_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

/// Alpha parameter from Kademlia - max parallel queries
const MAX_PARALLEL_QUERIES: usize = 3;

/// K parameter - replication factor
const K: usize = 8;

/// Maximum value size for DHT store operations (512 bytes)
/// The DHT is designed as a "phonebook" for peer discovery, not general storage.
/// Record types (NODE_AD, GROUP_BEACON, DATA_POINTER) should fit within 512 bytes.
/// Larger data should be stored via send_message() in the application layer.
const MAX_DHT_VALUE_SIZE: usize = 512;

/// Maximum node count for FindNode requests
/// Prevents amplification attacks by limiting response size
const MAX_FIND_NODE_COUNT: usize = 20;

/// Maximum pending DHT requests before evicting oldest (prevents memory DoS)
const MAX_PENDING_DHT_REQUESTS: usize = 10_000;

/// Number of K-buckets in Kademlia routing table (one per bit in 256-bit key space)
const KADEMLIA_BUCKET_COUNT: usize = 256;

/// Candidate expansion factor for find_closest_nodes optimization
/// Collect 2x requested count before early exit to ensure good selection
const CANDIDATE_EXPANSION_FACTOR: usize = 2;

/// DHT routing table maintenance interval in seconds
/// Periodic refresh of buckets and eviction of stale nodes
const MAINTENANCE_INTERVAL_SECS: u64 = 60;

/// DHT request wrapper with request ID for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtRequestWrapper {
    /// Unique request ID for response correlation
    pub id: String,
    /// The underlying DHT message
    pub message: DhtMessage,
}

/// DHT response wrapper with request ID for correlation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtResponseWrapper {
    /// Request ID this response corresponds to
    pub id: String,
    /// The underlying DHT response
    pub response: DhtResponse,
}

/// Main DHT Core Engine
pub struct DhtCoreEngine {
    node_id: PeerId,
    routing_table: Arc<RwLock<KademliaRoutingTable>>,
    data_store: Arc<RwLock<DataStore>>,
    replication_manager: Arc<RwLock<ReplicationManager>>,
    load_balancer: Arc<RwLock<LoadBalancer>>,

    // Security Components
    security_metrics: Arc<SecurityMetricsCollector>,
    bucket_refresh_manager: Arc<RwLock<BucketRefreshManager>>,
    close_group_validator: Arc<RwLock<CloseGroupValidator>>,
    eviction_manager: Arc<RwLock<EvictionManager>>,

    /// IP diversity limits — checked against the live routing table on each
    /// `add_node` call rather than maintained as incremental counters.
    ip_diversity_config: IPDiversityConfig,
    /// Maximum nodes per geographic region.
    geo_max_per_region: usize,

    // Network query components
    /// Transport handle for sending messages to remote peers
    transport: Option<Arc<dyn NetworkSender>>,
    /// Pending requests waiting for responses (request_id -> response sender)
    /// LRU cache with max 10k entries to prevent memory DoS
    pending_requests: Arc<RwLock<LruCache<String, oneshot::Sender<DhtResponse>>>>,

    // Trust-weighted peer selection
    /// Optional trust-aware peer selector for combining distance with trust scores
    trust_peer_selector: Option<TrustAwarePeerSelector<EigenTrustEngine>>,

    /// Shutdown token for background maintenance tasks
    shutdown: CancellationToken,
}

impl DhtCoreEngine {
    /// Create new DHT engine with specified node ID
    pub fn new(node_id: PeerId) -> Result<Self> {
        Self::new_with_validation_mode(node_id, CloseGroupEnforcementMode::Strict)
    }

    /// Create new DHT engine for testing (permissive validation)
    #[cfg(test)]
    pub fn new_for_tests(node_id: PeerId) -> Result<Self> {
        Self::new_with_validation_mode(node_id, CloseGroupEnforcementMode::LogOnly)
    }

    /// Create new DHT engine with specified validation mode
    pub(crate) fn new_with_validation_mode(
        node_id: PeerId,
        enforcement_mode: CloseGroupEnforcementMode,
    ) -> Result<Self> {
        // Initialize security components
        let security_metrics = Arc::new(SecurityMetricsCollector::new());
        let validator_config =
            CloseGroupValidatorConfig::default().with_enforcement_mode(enforcement_mode);
        let close_group_validator = Arc::new(RwLock::new(CloseGroupValidator::new(
            validator_config.clone(),
        )));

        let mut bucket_refresh_manager = BucketRefreshManager::new_with_validation(
            node_id,
            CloseGroupValidatorConfig::default(),
        );
        // Link validator to refresh manager
        bucket_refresh_manager.set_validator(close_group_validator.clone());
        let bucket_refresh_manager = Arc::new(RwLock::new(bucket_refresh_manager));

        let eviction_manager = Arc::new(RwLock::new(EvictionManager::new(
            MaintenanceConfig::default(),
        )));

        Ok(Self {
            node_id,
            routing_table: Arc::new(RwLock::new(KademliaRoutingTable::new(node_id, K))),
            data_store: Arc::new(RwLock::new(DataStore::new())),
            replication_manager: Arc::new(RwLock::new(ReplicationManager::new(K))),
            load_balancer: Arc::new(RwLock::new(LoadBalancer::new())),
            security_metrics,
            bucket_refresh_manager,
            close_group_validator,
            eviction_manager,
            ip_diversity_config: IPDiversityConfig::default(),
            geo_max_per_region: GEO_DEFAULT_MAX_PER_REGION,
            transport: None,
            pending_requests: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(MAX_PENDING_DHT_REQUESTS)
                    .context("MAX_PENDING_DHT_REQUESTS must be non-zero")?,
            ))),
            trust_peer_selector: None,
            shutdown: CancellationToken::new(),
        })
    }

    /// Set the transport handle for network operations
    ///
    /// Once set, `retrieve()` will query remote peers when a key is not found locally.
    pub fn set_transport(&mut self, transport: Arc<dyn NetworkSender>) {
        self.transport = Some(transport);
    }

    /// Check if network operations are available
    #[must_use]
    pub fn has_transport(&self) -> bool {
        self.transport.is_some()
    }

    /// Get this node's ID
    #[must_use]
    pub fn node_id(&self) -> &PeerId {
        &self.node_id
    }

    /// Number of peers currently in the routing table.
    pub async fn routing_table_size(&self) -> usize {
        self.routing_table.read().await.node_count()
    }

    // ===== Trust-weighted peer selection methods =====

    /// Enable trust-weighted peer selection
    ///
    /// When enabled, peer selection for DHT operations will combine XOR distance
    /// with EigenTrust scores to prefer higher-trust nodes.
    ///
    /// # Arguments
    /// * `trust_engine` - The EigenTrust engine providing trust scores
    /// * `config` - Configuration for trust selection behavior
    pub fn enable_trust_selection(
        &mut self,
        trust_engine: Arc<EigenTrustEngine>,
        config: TrustSelectionConfig,
    ) {
        self.trust_peer_selector = Some(TrustAwarePeerSelector::new(trust_engine, config));
        tracing::info!("DHT trust-weighted peer selection enabled");
    }

    /// Enable trust-weighted peer selection with separate configs for queries and storage
    ///
    /// Storage operations use stricter trust requirements since data persistence
    /// depends on node reliability.
    pub fn enable_trust_selection_with_storage_config(
        &mut self,
        trust_engine: Arc<EigenTrustEngine>,
        query_config: TrustSelectionConfig,
        storage_config: TrustSelectionConfig,
    ) {
        self.trust_peer_selector = Some(TrustAwarePeerSelector::with_storage_config(
            trust_engine,
            query_config,
            storage_config,
        ));
        tracing::info!("DHT trust-weighted peer selection enabled with separate storage config");
    }

    /// Disable trust-weighted peer selection
    ///
    /// Falls back to pure distance-based selection.
    pub fn disable_trust_selection(&mut self) {
        self.trust_peer_selector = None;
        tracing::info!("DHT trust-weighted peer selection disabled");
    }

    /// Check if trust-weighted peer selection is enabled
    #[must_use]
    pub fn has_trust_selection(&self) -> bool {
        self.trust_peer_selector.is_some()
    }

    /// Select peers for a query operation, considering trust if enabled
    ///
    /// If trust selection is enabled, combines XOR distance with trust scores.
    /// Otherwise, returns closest nodes by XOR distance only.
    async fn select_query_peers(&self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        let routing = self.routing_table.read().await;
        // Get 2x candidates to allow trust-based filtering
        let candidates = routing.find_closest_nodes(key, count * 2);
        drop(routing);

        if let Some(ref selector) = self.trust_peer_selector {
            selector.select_peers(key, &candidates, count)
        } else {
            // Fallback: take closest by distance
            candidates.into_iter().take(count).collect()
        }
    }

    /// Select peers for a storage operation, considering trust if enabled
    ///
    /// Storage operations use stricter trust requirements when trust selection
    /// is enabled, as data persistence depends on node reliability.
    async fn select_storage_peers(&self, key: &DhtKey, count: usize) -> Vec<NodeInfo> {
        let routing = self.routing_table.read().await;
        // Get 3x candidates for storage to allow stricter trust filtering
        let candidates = routing.find_closest_nodes(key, count * 3);
        drop(routing);

        if let Some(ref selector) = self.trust_peer_selector {
            selector.select_storage_peers(key, &candidates, count)
        } else {
            // Fallback: take closest by distance
            candidates.into_iter().take(count).collect()
        }
    }

    /// Signal background maintenance tasks to stop
    pub fn signal_shutdown(&self) {
        self.shutdown.cancel();
    }

    /// Start background maintenance tasks for security and health
    pub fn start_maintenance_tasks(&self) {
        let refresh_manager = self.bucket_refresh_manager.clone();
        let eviction_manager = self.eviction_manager.clone();
        let close_group_validator = self.close_group_validator.clone();
        let security_metrics = self.security_metrics.clone();
        let shutdown = self.shutdown.clone();

        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(MAINTENANCE_INTERVAL_SECS));
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    () = shutdown.cancelled() => {
                        tracing::info!("DHT core maintenance task shutting down");
                        break;
                    }
                }

                // 1. Run Bucket Refresh Logic with Validation Integration
                {
                    let mut mgr = refresh_manager.write().await;

                    // Check for attack mode escalation based on validation failures
                    if mgr.should_trigger_attack_mode() {
                        if let Some(validator) = mgr.validator() {
                            validator.write().await.escalate_to_bft();
                            tracing::warn!(
                                "Escalating to BFT mode due to validation failures (rate: {:.2}%)",
                                mgr.overall_validation_rate() * 100.0
                            );
                        }
                    } else if let Some(validator) = mgr.validator() {
                        // De-escalate if validation rate recovers above 85%
                        if mgr.overall_validation_rate() > 0.85 {
                            validator.write().await.deescalate_from_bft();
                        }
                    }

                    // Get buckets needing refresh
                    let buckets = mgr.get_buckets_needing_refresh();
                    if !buckets.is_empty() {
                        // Get buckets that also need validation
                        let validation_buckets = mgr.get_buckets_needing_validation();
                        let mut total_validated = 0usize;
                        let mut total_evicted = 0usize;

                        for bucket in buckets {
                            // Record refresh (in a real impl, trigger network lookups first)
                            mgr.record_refresh_success(bucket, 0);

                            // Perform trust-based validation during refresh
                            if validation_buckets.contains(&bucket) {
                                // Get nodes that need validation from the refresh manager
                                let nodes_to_validate = mgr.get_nodes_in_bucket(bucket);

                                // Validate each node using trust-based validation
                                let validator = close_group_validator.read().await;
                                let mut evict_list = Vec::new();

                                for node_id in &nodes_to_validate {
                                    // Query trust score from eviction manager's trust cache
                                    // This cache is populated by EigenTrust updates via update_trust_score()
                                    let trust_score = {
                                        let evict_mgr = eviction_manager.read().await;
                                        evict_mgr.get_trust_score(node_id)
                                    };

                                    let (is_valid, failure_reason) =
                                        validator.validate_trust_only(node_id, trust_score);

                                    if !is_valid && let Some(reason) = failure_reason {
                                        tracing::info!(
                                            node_id = ?node_id,
                                            bucket = bucket,
                                            reason = ?reason,
                                            "Node failed validation during refresh"
                                        );
                                        evict_list
                                            .push((*node_id, EvictionReason::CloseGroupRejection));
                                    }
                                }
                                drop(validator);

                                total_validated += nodes_to_validate.len();

                                // Queue evictions
                                if !evict_list.is_empty() {
                                    let mut evict_mgr = eviction_manager.write().await;
                                    for (node_id, reason) in evict_list {
                                        evict_mgr.record_eviction(&node_id, reason);
                                        total_evicted += 1;
                                    }
                                }

                                // Record validation metrics
                                let nodes_count = nodes_to_validate.len();
                                mgr.record_validation_result(bucket, nodes_count, 0);

                                tracing::debug!(
                                    bucket = bucket,
                                    nodes_validated = nodes_count,
                                    "Bucket validation completed during refresh"
                                );
                            }
                        }

                        // Update security metrics
                        if total_validated > 0 || total_evicted > 0 {
                            security_metrics
                                .record_validation_during_refresh(total_validated, total_evicted);
                            tracing::info!(
                                total_validated = total_validated,
                                total_evicted = total_evicted,
                                "Refresh validation cycle completed"
                            );
                        }
                    }
                }

                // 2. Active Eviction Enforcement
                {
                    let mut eviction_mgr = eviction_manager.write().await;
                    let candidates = eviction_mgr.get_eviction_candidates();
                    for (node_id, reason) in candidates {
                        tracing::warn!("Evicting node {} for reason: {:?}", node_id, reason);
                        // Remove from eviction tracking (routing table removal
                        // would be triggered by the caller or a separate mechanism)
                        eviction_mgr.remove_node(&node_id);
                    }
                }

                // 4. Update Metrics
                // (Example: update churn rate)
                // metrics.update_churn(...)
            }
        });
    }

    /// Get the security metrics collector
    pub fn security_metrics(&self) -> Arc<SecurityMetricsCollector> {
        self.security_metrics.clone()
    }

    /// Store data in the DHT
    ///
    /// When trust-weighted selection is enabled, storage targets are selected
    /// by combining XOR distance with trust scores, using stricter requirements
    /// than query operations since data persistence depends on node reliability.
    ///
    /// # Errors
    /// Returns an error if the value exceeds `MAX_DHT_VALUE_SIZE` (512 bytes).
    pub async fn store(&mut self, key: &DhtKey, value: Vec<u8>) -> Result<StoreReceipt> {
        // Security: Reject oversized values to prevent memory exhaustion
        if value.len() > MAX_DHT_VALUE_SIZE {
            return Err(anyhow::anyhow!(
                "Value too large: {} bytes (max: {} bytes)",
                value.len(),
                MAX_DHT_VALUE_SIZE
            ));
        }

        // Find nodes to store at using trust-aware selection if enabled
        let target_nodes = self.select_storage_peers(key, K).await;

        // Select nodes based on load (secondary filter)
        let load_balancer = self.load_balancer.read().await;
        let selected_nodes = load_balancer.select_least_loaded(&target_nodes, K);

        tracing::debug!(
            key = ?hex::encode(key.as_bytes()),
            num_targets = selected_nodes.len(),
            trust_selection = self.has_trust_selection(),
            "Selected storage targets"
        );

        // Store locally if we're one of the selected nodes or if no nodes are available (test/single-node mode)
        if selected_nodes.contains(&self.node_id) || selected_nodes.is_empty() {
            let mut store = self.data_store.write().await;
            // Avoid unnecessary clone of value: key is cloned for ownership, value is consumed by this branch
            store.put(*key, value);
            // Return early since we've consumed value
            return Ok(StoreReceipt {
                key: *key,
                stored_at: selected_nodes,
                timestamp: SystemTime::now(),
                success: true,
            });
        }

        Ok(StoreReceipt {
            key: *key,
            stored_at: selected_nodes,
            timestamp: SystemTime::now(),
            success: true,
        })
    }

    /// Retrieve data from the DHT
    ///
    /// First checks local storage. If not found locally and a transport is configured,
    /// queries the K closest nodes in parallel and returns the first successful response.
    pub async fn retrieve(&self, key: &DhtKey) -> Result<Option<Vec<u8>>> {
        // Step 1: Check local store first
        {
            let mut store = self.data_store.write().await;
            if let Some(value) = store.get(key) {
                tracing::debug!(key = ?hex::encode(key.as_bytes()), "Key found in local store");
                return Ok(Some(value));
            }
        }

        // Step 2: Get transport or return None if not available
        let transport = match &self.transport {
            Some(t) => Arc::clone(t),
            None => {
                tracing::debug!("No transport available for network query");
                return Ok(None);
            }
        };

        // Step 3: Select peers using trust-aware selection if enabled
        let closest_nodes = self.select_query_peers(key, K).await;

        if closest_nodes.is_empty() {
            tracing::debug!("No nodes in routing table to query");
            return Ok(None);
        }

        tracing::debug!(
            key = ?hex::encode(key.as_bytes()),
            num_nodes = closest_nodes.len().min(MAX_PARALLEL_QUERIES),
            trust_selection = self.has_trust_selection(),
            "Querying nodes for key"
        );

        // Step 4: Query nodes in parallel (up to alpha at a time)
        let nodes_to_query: Vec<_> = closest_nodes
            .into_iter()
            .take(MAX_PARALLEL_QUERIES)
            .collect();

        let query_futures: Vec<_> = nodes_to_query
            .iter()
            .map(|node| self.query_node_for_key(Arc::clone(&transport), node, key))
            .collect();

        // Step 5: Wait for responses (each query has its own DHT_QUERY_TIMEOUT)
        let responses = futures::future::join_all(query_futures).await;

        // Return first successful response
        for response in responses {
            if let Ok(Some(value)) = response {
                tracing::debug!(key = ?hex::encode(key.as_bytes()), "Key found on remote node");
                return Ok(Some(value));
            }
        }
        tracing::debug!(key = ?hex::encode(key.as_bytes()), "Key not found on any queried node");
        Ok(None)
    }

    /// Query a single node for a key value
    async fn query_node_for_key(
        &self,
        transport: Arc<dyn NetworkSender>,
        node: &NodeInfo,
        key: &DhtKey,
    ) -> Result<Option<Vec<u8>>> {
        // Generate unique request ID
        let request_id = Uuid::new_v4().to_string();

        // Create response channel
        let (tx, rx) = oneshot::channel();

        // Register pending request - reject if at capacity to avoid evicting in-flight requests
        {
            let mut pending = self.pending_requests.write().await;
            if pending.len() >= MAX_PENDING_DHT_REQUESTS {
                return Err(anyhow!(
                    "DHT request capacity exceeded ({} pending requests). Too many concurrent requests.",
                    MAX_PENDING_DHT_REQUESTS
                ));
            }
            pending.put(request_id.clone(), tx);
        }

        // Create the DHT message
        let message = DhtMessage::Retrieve {
            key: *key,
            consistency: ConsistencyLevel::One,
        };

        // Wrap with request ID
        let wrapped_request = DhtRequestWrapper {
            id: request_id.clone(),
            message,
        };

        // Serialize the request using postcard
        let request_bytes = match postcard::to_stdvec(&wrapped_request) {
            Ok(bytes) => bytes,
            Err(e) => {
                // Clean up pending request
                let mut pending = self.pending_requests.write().await;
                pending.pop(&request_id);
                return Err(anyhow!(
                    "Failed to serialize DHT request for key {}: {e}",
                    hex::encode(key.as_bytes())
                ));
            }
        };

        // Send request via transport
        if let Err(e) = transport
            .send_message(&node.id, "/dht/1.0.0", request_bytes)
            .await
        {
            // Clean up pending request
            let mut pending = self.pending_requests.write().await;
            pending.pop(&request_id);
            tracing::debug!(peer_id = %node.id, error = %e, "Failed to send DHT request");
            return Err(anyhow!(
                "Failed to send DHT request to peer {}: {e}",
                node.id
            ));
        }

        // Wait for response with timeout
        match tokio::time::timeout(DHT_QUERY_TIMEOUT, rx).await {
            Ok(Ok(response)) => {
                // Clean up happens automatically when channel completes
                match response {
                    DhtResponse::RetrieveReply { value } => Ok(value),
                    DhtResponse::Error { message, .. } => {
                        tracing::debug!(peer_id = %node.id, error = %message, "DHT error response");
                        Ok(None)
                    }
                    _ => {
                        tracing::debug!(peer_id = %node.id, "Unexpected DHT response type");
                        Ok(None)
                    }
                }
            }
            Ok(Err(_recv_error)) => {
                // Channel closed without response
                tracing::debug!(peer_id = %node.id, "Response channel closed");
                Ok(None)
            }
            Err(_timeout) => {
                // Timeout - clean up pending request
                let mut pending = self.pending_requests.write().await;
                pending.pop(&request_id);
                tracing::debug!(peer_id = %node.id, "DHT request timed out");
                Ok(None)
            }
        }
    }

    /// Handle an incoming DHT response from the network
    ///
    /// This method should be called by the transport layer when a DHT response
    /// message is received. It routes the response to the waiting caller.
    pub async fn handle_response(&self, response_wrapper: DhtResponseWrapper) {
        let mut pending = self.pending_requests.write().await;
        if let Some(tx) = pending.pop(&response_wrapper.id) {
            // Send response - log if receiver dropped (timeout or cancelled request)
            if tx.send(response_wrapper.response).is_err() {
                tracing::debug!(
                    request_id = %response_wrapper.id,
                    "Response receiver dropped (request likely timed out)"
                );
            }
        } else {
            tracing::trace!(
                request_id = %response_wrapper.id,
                "Received response for unknown or timed-out request"
            );
        }
    }

    /// Handle an incoming DHT request from the network
    ///
    /// Processes the request and returns a response wrapper ready to be sent back.
    pub async fn handle_request(&self, request_wrapper: DhtRequestWrapper) -> DhtResponseWrapper {
        let response = match request_wrapper.message {
            DhtMessage::Retrieve { ref key, .. } => match self.data_store.write().await.get(key) {
                Some(value) => DhtResponse::RetrieveReply { value: Some(value) },
                None => DhtResponse::RetrieveReply { value: None },
            },
            DhtMessage::Store {
                ref key, ref value, ..
            } => {
                // Security: Reject oversized values to prevent memory exhaustion
                if value.len() > MAX_DHT_VALUE_SIZE {
                    return DhtResponseWrapper {
                        id: request_wrapper.id,
                        response: DhtResponse::Error {
                            code: crate::dht::network_integration::ErrorCode::InvalidMessage,
                            message: format!(
                                "Value too large: {} bytes (max: {} bytes)",
                                value.len(),
                                MAX_DHT_VALUE_SIZE
                            ),
                            retry_after: None,
                        },
                    };
                }
                self.data_store.write().await.put(*key, value.clone());
                DhtResponse::StoreAck {
                    replicas: vec![self.node_id],
                }
            }
            DhtMessage::FindNode { ref target, count } => {
                // Security: Cap count to prevent amplification attacks
                let capped_count = count.min(MAX_FIND_NODE_COUNT);
                let routing = self.routing_table.read().await;
                let nodes = routing.find_closest_nodes(target, capped_count);
                DhtResponse::FindNodeReply {
                    nodes,
                    distances: Vec::new(),
                }
            }
            DhtMessage::FindValue { ref key } => {
                let value = self.data_store.write().await.get(key);
                if value.is_some() {
                    DhtResponse::FindValueReply {
                        value,
                        nodes: Vec::new(),
                    }
                } else {
                    let routing = self.routing_table.read().await;
                    let nodes = routing.find_closest_nodes(key, K);
                    DhtResponse::FindValueReply { value: None, nodes }
                }
            }
            DhtMessage::Ping {
                timestamp,
                sender_info,
            } => DhtResponse::Pong {
                timestamp,
                node_info: sender_info,
            },
            _ => DhtResponse::Error {
                code: crate::dht::network_integration::ErrorCode::InvalidMessage,
                message: "Unsupported message type".to_string(),
                retry_after: None,
            },
        };

        DhtResponseWrapper {
            id: request_wrapper.id,
            response,
        }
    }

    /// Find nodes closest to a key
    pub async fn find_nodes(&self, key: &DhtKey, count: usize) -> Result<Vec<NodeInfo>> {
        let routing = self.routing_table.read().await;
        Ok(routing.find_closest_nodes(key, count))
    }

    /// Join the DHT network
    pub async fn join_network(&mut self, bootstrap_nodes: Vec<NodeInfo>) -> Result<()> {
        let mut routing = self.routing_table.write().await;

        for node in bootstrap_nodes {
            routing.add_node(node)?;
        }

        Ok(())
    }

    /// Leave the DHT network gracefully
    pub async fn leave_network(&mut self) -> Result<()> {
        // Transfer data to other nodes before leaving
        // In a real implementation, would redistribute stored data

        let mut store = self.data_store.write().await;
        store.data.clear();
        store.metadata.clear();

        Ok(())
    }

    /// Look up a node's address from the routing table by peer ID.
    ///
    /// Returns the stored address if the peer is in the routing table,
    /// `None` otherwise. O(K) scan of the target k-bucket.
    pub async fn get_node_address(&self, peer_id: &PeerId) -> Option<String> {
        let routing = self.routing_table.read().await;
        routing.find_node_by_id(peer_id).map(|n| n.address.clone())
    }

    /// Record a successful interaction with a peer by updating its `last_seen`
    /// timestamp (and optionally its address) and moving it to the tail of its
    /// k-bucket (most recently seen).
    ///
    /// Standard Kademlia: any successful RPC implicitly proves liveness, so the
    /// routing table should reflect this without requiring dedicated pings.
    /// Passing the current address ensures stale addresses are replaced when a
    /// peer reconnects from a different endpoint.
    pub async fn touch_node(&self, node_id: &PeerId, address: Option<&str>) -> bool {
        let mut routing = self.routing_table.write().await;
        routing.touch_node(node_id, address)
    }

    /// Handle node failure
    pub async fn handle_node_failure(&mut self, failed_node: PeerId) -> Result<()> {
        // Remove from routing table
        let mut routing = self.routing_table.write().await;
        routing.remove_node(&failed_node);

        // Schedule repairs for affected data
        let _replication = self.replication_manager.write().await;
        // In real implementation, would identify affected keys and schedule repairs

        Ok(())
    }

    /// Evict a node from the routing table with a specific reason.
    ///
    /// This is called when a node fails security validation or is detected
    /// as malicious through Sybil/collusion detection.
    pub async fn evict_node(&self, node_id: &PeerId, reason: EvictionReason) -> Result<()> {
        // 1. Remove from routing table
        {
            let mut routing = self.routing_table.write().await;
            routing.remove_node(node_id);
        }

        // 2. Update security metrics based on eviction reason
        let reason_str = match &reason {
            EvictionReason::ConsecutiveFailures(_) => "consecutive_failures",
            EvictionReason::LowTrust(_) => "low_trust",
            EvictionReason::CloseGroupRejection => "close_group_rejection",
            EvictionReason::Stale => "stale",
        };
        self.security_metrics.record_eviction(reason_str).await;

        // 3. Log eviction for data integrity tracking
        // Note: Data health tracking handled elsewhere
        // Evicted nodes will be removed from routing table, which affects future lookups

        tracing::info!(
            node_id = %node_id,
            reason = ?reason,
            "Node evicted from DHT"
        );

        Ok(())
    }

    /// Evict a node due to close group validation failure.
    ///
    /// This is a specialized eviction for security-related failures.
    pub async fn evict_node_for_security(
        &self,
        node_id: &PeerId,
        failure_reason: CloseGroupFailure,
    ) -> Result<()> {
        let eviction_reason = match failure_reason {
            CloseGroupFailure::NotInCloseGroup => EvictionReason::CloseGroupRejection,
            CloseGroupFailure::EvictedFromCloseGroup => EvictionReason::CloseGroupRejection,
            CloseGroupFailure::InsufficientConfirmation => EvictionReason::CloseGroupRejection,
            CloseGroupFailure::LowTrustScore => {
                EvictionReason::LowTrust("Security validation failed".to_string())
            }
            CloseGroupFailure::InsufficientGeographicDiversity => {
                EvictionReason::LowTrust("Geographic diversity violation".to_string())
            }
            CloseGroupFailure::SuspectedCollusion => {
                EvictionReason::LowTrust("Suspected collusion".to_string())
            }
            CloseGroupFailure::AttackModeTriggered => {
                EvictionReason::LowTrust("Attack mode triggered".to_string())
            }
        };

        self.evict_node(node_id, eviction_reason).await
    }

    /// Get eviction candidates from the refresh manager.
    ///
    /// Returns nodes that should be evicted based on validation failures.
    pub async fn get_eviction_candidates(&self) -> Vec<(PeerId, CloseGroupFailure)> {
        self.bucket_refresh_manager
            .read()
            .await
            .get_nodes_for_eviction()
            .await
    }

    /// Check if the system is currently in attack mode.
    #[must_use]
    pub async fn is_attack_mode(&self) -> bool {
        self.bucket_refresh_manager
            .read()
            .await
            .is_attack_mode()
            .await
    }

    /// Get the bucket refresh manager for external access
    pub fn bucket_refresh_manager(&self) -> Arc<RwLock<BucketRefreshManager>> {
        self.bucket_refresh_manager.clone()
    }

    /// Get the close group validator for external access
    pub fn close_group_validator(&self) -> Arc<RwLock<CloseGroupValidator>> {
        self.close_group_validator.clone()
    }

    /// Add a node to the DHT with security checks.
    ///
    /// Diversity limits (IP subnet and geographic region) are derived from the
    /// live routing table contents on every call, so counts are always accurate
    /// regardless of evictions, reconnections, or address changes.
    pub async fn add_node(&mut self, node: NodeInfo) -> Result<()> {
        // 1. Security Check: Close Group Validator
        {
            let validator = self.close_group_validator.read().await;
            if !validator.validate(&node.id) {
                tracing::warn!("Node failed close group validation: {:?}", node.id);
                return Err(anyhow::anyhow!("Node failed close group validation"));
            }
        }

        // Parse candidate IP once for the diversity checks below.
        let candidate_ip = parse_ip(&node.address);

        // 2. Security Check: IP + Geographic Diversity
        //
        // Counts are derived from the routing table in a single pass.
        // Nodes already present (reconnecting with the same ID) are
        // excluded from the count so they can update their address
        // without inflating limits.
        // 3. Add to routing table — single write lock for both the diversity
        //    check and the insertion to avoid a TOCTOU race where touch_node
        //    could change an address between a read-lock check and the write.
        let mut routing = self.routing_table.write().await;
        if let Some(ip) = candidate_ip {
            self.check_diversity(&routing, &node.id, ip)?;
        }
        routing.add_node(node)?;

        Ok(())
    }

    /// Check IP subnet and geographic diversity against the live routing table.
    ///
    /// Single pass over all nodes — each node's address is parsed once.
    /// `candidate_id` is excluded from counting so that a reconnecting node
    /// doesn't block itself.
    fn check_diversity(
        &self,
        routing: &KademliaRoutingTable,
        candidate_id: &PeerId,
        candidate_ip: IpAddr,
    ) -> Result<()> {
        // Loopback addresses (127.0.0.0/8, ::1) are used in tests and local
        // development where many nodes share the same IP.  Diversity limits
        // don't apply to them.
        if candidate_ip.is_loopback() {
            return Ok(());
        }

        let candidate_region = GeographicRegion::from_ip(candidate_ip);
        let mut region_count: usize = 0;

        match candidate_ip {
            IpAddr::V4(v4) => {
                let candidate_24 = mask_ipv4(v4, 24);
                let candidate_16 = mask_ipv4(v4, 16);

                let mut count_exact: usize = 0;
                let mut count_24: usize = 0;
                let mut count_16: usize = 0;
                let mut network_size: usize = 0;

                for node in routing.iter_nodes() {
                    if node.id == *candidate_id {
                        continue;
                    }
                    network_size += 1;
                    let Some(existing_ip) = parse_ip(&node.address) else {
                        continue;
                    };
                    if existing_ip.is_loopback() {
                        continue;
                    }
                    if GeographicRegion::from_ip(existing_ip) == candidate_region {
                        region_count += 1;
                    }
                    if let IpAddr::V4(existing_v4) = existing_ip {
                        if existing_v4 == v4 {
                            count_exact += 1;
                        }
                        if mask_ipv4(existing_v4, 24) == candidate_24 {
                            count_24 += 1;
                        }
                        if mask_ipv4(existing_v4, 16) == candidate_16 {
                            count_16 += 1;
                        }
                    }
                }

                let per_ip = self.dynamic_per_ip_limit(network_size);
                let limit_32 =
                    std::cmp::min(self.ip_diversity_config.max_nodes_per_ipv4_32, per_ip);
                let limit_24 =
                    std::cmp::min(self.ip_diversity_config.max_nodes_per_ipv4_24, per_ip * 3);
                let limit_16 =
                    std::cmp::min(self.ip_diversity_config.max_nodes_per_ipv4_16, per_ip * 10);

                if count_exact >= limit_32 {
                    return Err(anyhow!(
                        "IP diversity: /32 limit ({limit_32}) exceeded for {v4}"
                    ));
                }
                if count_24 >= limit_24 {
                    return Err(anyhow!(
                        "IP diversity: /24 limit ({limit_24}) exceeded for {candidate_24}"
                    ));
                }
                if count_16 >= limit_16 {
                    return Err(anyhow!(
                        "IP diversity: /16 limit ({limit_16}) exceeded for {candidate_16}"
                    ));
                }
            }
            IpAddr::V6(v6) => {
                let candidate_64 = mask_ipv6(v6, 64);
                let candidate_48 = mask_ipv6(v6, 48);
                let candidate_32 = mask_ipv6(v6, 32);

                let mut count_64: usize = 0;
                let mut count_48: usize = 0;
                let mut count_32: usize = 0;

                for node in routing.iter_nodes() {
                    if node.id == *candidate_id {
                        continue;
                    }
                    let Some(existing_ip) = parse_ip(&node.address) else {
                        continue;
                    };
                    if existing_ip.is_loopback() {
                        continue;
                    }
                    if GeographicRegion::from_ip(existing_ip) == candidate_region {
                        region_count += 1;
                    }
                    if let IpAddr::V6(existing_v6) = existing_ip {
                        if mask_ipv6(existing_v6, 64) == candidate_64 {
                            count_64 += 1;
                        }
                        if mask_ipv6(existing_v6, 48) == candidate_48 {
                            count_48 += 1;
                        }
                        if mask_ipv6(existing_v6, 32) == candidate_32 {
                            count_32 += 1;
                        }
                    }
                }

                let cfg = &self.ip_diversity_config;
                if count_64 >= cfg.max_nodes_per_64 {
                    return Err(anyhow!(
                        "IP diversity: /64 limit ({}) exceeded",
                        cfg.max_nodes_per_64
                    ));
                }
                if count_48 >= cfg.max_nodes_per_48 {
                    return Err(anyhow!(
                        "IP diversity: /48 limit ({}) exceeded",
                        cfg.max_nodes_per_48
                    ));
                }
                if count_32 >= cfg.max_nodes_per_32 {
                    return Err(anyhow!(
                        "IP diversity: /32 limit ({}) exceeded",
                        cfg.max_nodes_per_32
                    ));
                }
            }
        }

        if region_count >= self.geo_max_per_region {
            return Err(anyhow!(
                "Geographic diversity: region {candidate_region:?} limit ({}) exceeded",
                self.geo_max_per_region
            ));
        }

        Ok(())
    }

    /// Dynamic per-IP limit: `min(cap, floor(network_size * fraction))`,
    /// clamped to at least 1.
    fn dynamic_per_ip_limit(&self, network_size: usize) -> usize {
        let fraction =
            (network_size as f64 * self.ip_diversity_config.max_network_fraction).floor() as usize;
        std::cmp::min(
            self.ip_diversity_config.max_per_ip_cap,
            std::cmp::max(1, fraction),
        )
    }
}

// Manual Debug implementation to avoid cascade of Debug requirements
impl std::fmt::Debug for DhtCoreEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DhtCoreEngine")
            .field("node_id", &self.node_id)
            .field("routing_table", &"Arc<RwLock<KademliaRoutingTable>>")
            .field("data_store", &"Arc<RwLock<DataStore>>")
            .field("replication_manager", &"Arc<RwLock<ReplicationManager>>")
            .field("load_balancer", &"Arc<RwLock<LoadBalancer>>")
            .field("security_metrics", &"Arc<SecurityMetricsCollector>")
            .field(
                "bucket_refresh_manager",
                &"Arc<RwLock<BucketRefreshManager>>",
            )
            .field("close_group_validator", &"Arc<RwLock<CloseGroupValidator>>")
            .field("eviction_manager", &"Arc<RwLock<EvictionManager>>")
            .field("ip_diversity_config", &self.ip_diversity_config)
            .field("geo_max_per_region", &self.geo_max_per_region)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[tokio::test]
    async fn test_basic_store_retrieve() -> Result<()> {
        let mut dht = DhtCoreEngine::new(PeerId::from_bytes([42u8; 32]))?;
        let key = DhtKey::new(b"test_key");
        let value = b"test_value".to_vec();

        let receipt = dht.store(&key, value.clone()).await?;
        assert!(receipt.is_successful());

        let retrieved = dht.retrieve(&key).await?;
        assert_eq!(retrieved, Some(value));

        Ok(())
    }

    #[tokio::test]
    async fn test_xor_distance() {
        let key1 = DhtKey::from_bytes([0u8; 32]);
        let key2 = DhtKey::from_bytes([255u8; 32]);

        let distance = key1.distance(&key2);
        assert_eq!(distance, [255u8; 32]);
    }

    /// Helper: create a NodeInfo with a deterministic PeerId derived from a
    /// single byte.  Keeps tests concise.
    fn make_node(byte: u8, address: &str) -> NodeInfo {
        NodeInfo {
            id: PeerId::from_bytes([byte; 32]),
            address: address.to_string(),
            last_seen: SystemTime::now(),
            capacity: NodeCapacity::default(),
        }
    }

    // -----------------------------------------------------------------------
    // KBucket::touch_node tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_touch_node_updates_address() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "1.2.3.4:9000");
        bucket.add_node(node).unwrap();

        // Touch with a new address
        let found = bucket.touch_node(&PeerId::from_bytes([1u8; 32]), Some("5.6.7.8:9000"));
        assert!(found);
        assert_eq!(bucket.get_nodes().last().unwrap().address, "5.6.7.8:9000");
    }

    #[test]
    fn test_touch_node_none_preserves_address() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        let node = make_node(1, "1.2.3.4:9000");
        bucket.add_node(node).unwrap();

        let found = bucket.touch_node(&PeerId::from_bytes([1u8; 32]), None);
        assert!(found);
        assert_eq!(bucket.get_nodes().last().unwrap().address, "1.2.3.4:9000");
    }

    #[test]
    fn test_touch_node_moves_to_tail() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket.add_node(make_node(1, "1.1.1.1:9000")).unwrap();
        bucket.add_node(make_node(2, "2.2.2.2:9000")).unwrap();
        bucket.add_node(make_node(3, "3.3.3.3:9000")).unwrap();

        // Touch the first node — it should move to the tail
        bucket.touch_node(&PeerId::from_bytes([1u8; 32]), None);
        let ids: Vec<u8> = bucket
            .get_nodes()
            .iter()
            .map(|n| n.id.to_bytes()[0])
            .collect();
        assert_eq!(ids, vec![2, 3, 1]);
    }

    #[test]
    fn test_touch_node_missing_returns_false() {
        let k = 8;
        let mut bucket = KBucket::new(k);
        bucket.add_node(make_node(1, "1.1.1.1:9000")).unwrap();

        let found = bucket.touch_node(&PeerId::from_bytes([99u8; 32]), Some("9.9.9.9:9000"));
        assert!(!found);
    }

    // -----------------------------------------------------------------------
    // find_closest_nodes tests — boundary bucket indices
    // -----------------------------------------------------------------------

    #[test]
    fn test_find_closest_nodes_no_duplicates_at_bucket_zero() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Insert nodes that land in different buckets.  XOR with [0;32]
        // means the bucket index is the leading-bit position of the node id.
        // Byte 0 = 0x80 → bucket 0, byte 0 = 0x40 → bucket 1, etc.
        let mut id_bytes = [0u8; 32];
        id_bytes[0] = 0x80; // bucket 0
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                address: "10.0.0.1:9000".to_string(),
                last_seen: SystemTime::now(),
                capacity: NodeCapacity::default(),
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[0] = 0x40; // bucket 1
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                address: "10.0.0.2:9000".to_string(),
                last_seen: SystemTime::now(),
                capacity: NodeCapacity::default(),
            })
            .unwrap();

        // Search for a key that targets bucket 0
        let mut key_bytes = [0u8; 32];
        key_bytes[0] = 0x80;
        let key = DhtKey::from_bytes(key_bytes);
        let results = table.find_closest_nodes(&key, 8);

        // Verify no duplicates by collecting IDs into a set
        let mut seen = HashSet::new();
        for node in &results {
            assert!(seen.insert(node.id), "Duplicate node {:?}", node.id);
        }
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_closest_nodes_no_duplicates_at_bucket_255() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Bucket 255 requires the differing bit at position 255 (last bit
        // of last byte).  XOR distance with [0;32] is the id itself, so we
        // need id where only the very last bit is set.
        let mut id_bytes = [0u8; 32];
        id_bytes[31] = 0x01; // bucket 255
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                address: "10.0.0.1:9000".to_string(),
                last_seen: SystemTime::now(),
                capacity: NodeCapacity::default(),
            })
            .unwrap();

        id_bytes = [0u8; 32];
        id_bytes[31] = 0x02; // bucket 254
        table
            .add_node(NodeInfo {
                id: PeerId::from_bytes(id_bytes),
                address: "10.0.0.2:9000".to_string(),
                last_seen: SystemTime::now(),
                capacity: NodeCapacity::default(),
            })
            .unwrap();

        let mut key_bytes = [0u8; 32];
        key_bytes[31] = 0x01;
        let key = DhtKey::from_bytes(key_bytes);
        let results = table.find_closest_nodes(&key, 8);

        let mut seen = HashSet::new();
        for node in &results {
            assert!(seen.insert(node.id), "Duplicate node {:?}", node.id);
        }
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn test_find_closest_nodes_returns_sorted_by_distance() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let mut table = KademliaRoutingTable::new(local_id, 8);

        // Insert 5 nodes at varying distances
        for i in 0..5u8 {
            let mut id_bytes = [0u8; 32];
            id_bytes[0] = 0x80 >> i; // buckets 0,1,2,3,4
            table
                .add_node(NodeInfo {
                    id: PeerId::from_bytes(id_bytes),
                    address: format!("10.0.0.{}:9000", i + 1),
                    last_seen: SystemTime::now(),
                    capacity: NodeCapacity::default(),
                })
                .unwrap();
        }

        let key = DhtKey::from_bytes([0u8; 32]);
        let results = table.find_closest_nodes(&key, 3);

        assert_eq!(results.len(), 3);
        // Results should be sorted by XOR distance to key
        for window in results.windows(2) {
            let d0 = xor_distance_bytes(window[0].id.to_bytes(), key.as_bytes());
            let d1 = xor_distance_bytes(window[1].id.to_bytes(), key.as_bytes());
            assert!(d0 <= d1, "Results not sorted by distance");
        }
    }

    #[test]
    fn test_find_closest_nodes_empty_table() {
        let local_id = PeerId::from_bytes([0u8; 32]);
        let table = KademliaRoutingTable::new(local_id, 8);

        let key = DhtKey::from_bytes([42u8; 32]);
        let results = table.find_closest_nodes(&key, 8);
        assert!(results.is_empty());
    }
}
