# Trust Signals API Reference

## Overview

saorsa-core provides an EigenTrust-based reputation system for tracking node reliability.
The trust system is owned by `AdaptiveDHT`, which is the sole authority on peer trust scores.

Consumers (like saorsa-node) report application-level outcomes via `TrustEvent`. DHT-internal
events (iterative lookup success/failure) are recorded automatically.

The trust system enables:
- **Sybil resistance**: Malicious nodes are downscored automatically
- **Quality routing**: Optional trust-weighted peer selection (behind config flag)
- **Self-healing**: The network learns from failures and adapts
- **Live eviction**: Peers below trust threshold are evicted from the routing table

## Quick Start

```rust
use saorsa_core::{P2PNode, TrustEvent};

// After successful data retrieval from a peer:
node.report_trust_event(&peer_id, TrustEvent::SuccessfulResponse).await;

// After failed data retrieval:
node.report_trust_event(&peer_id, TrustEvent::CorruptedData).await;

// Check peer trust before operations:
let trust = node.peer_trust(&peer_id);
if trust < 0.3 {
    tracing::warn!("Low trust peer: {peer_id}");
}
```

## P2PNode Trust Methods

### `report_trust_event(peer_id, event)`

Report an application-level trust event for a peer. This is the primary method
for saorsa-node to report outcomes the DHT layer cannot observe directly.

```rust
pub async fn report_trust_event(&self, peer_id: &PeerId, event: TrustEvent)
```

### `peer_trust(peer_id)`

Get the current trust score for a peer (0.0 to 1.0). Returns 0.5 for unknown peers.

```rust
pub fn peer_trust(&self, peer_id: &PeerId) -> f64
```

### `trust_engine()`

Get the underlying TrustEngine for advanced operations.

```rust
pub fn trust_engine(&self) -> Arc<TrustEngine>
```

## TrustEvent Enum

All trust-relevant outcomes are expressed as `TrustEvent` variants:

| Event | Severity | Description |
|-------|----------|-------------|
| `SuccessfulResponse` | Positive | Peer provided a correct, verified response |
| `SuccessfulConnection` | Positive | Peer connection established successfully |
| `FailedResponse` | 1x penalty | Generic response failure |
| `ConnectionFailed` | 1x penalty | Could not establish connection |
| `ConnectionTimeout` | 1x penalty | Connection attempt timed out |
| `DataUnavailable` | 1x penalty | Peer did not have requested data |
| `Refused` | 1x penalty | Peer explicitly refused the request |
| `UnexpectedDisconnect` | 1x penalty | Peer disconnected unexpectedly |
| `CorruptedData` | 2x penalty | Data failed integrity verification |
| `ProtocolViolation` | 2x penalty | Peer violated wire protocol |

## When to Report Trust Events

| Scenario | TrustEvent | Notes |
|----------|------------|-------|
| Chunk retrieved and verified | `SuccessfulResponse` | Data integrity confirmed |
| Chunk hash mismatch | `CorruptedData` | 2x penalty — severe |
| Request timeout | `ConnectionTimeout` | May be transient |
| Connection refused | `Refused` | Peer explicitly refused |
| Peer returned empty response | `DataUnavailable` | Data not found |
| Storage verification passed | `SuccessfulResponse` | Peer maintains data |
| Storage verification failed | `CorruptedData` | Peer lost/corrupted data |

## Trust-Weighted Routing

Trust-weighted routing is disabled by default. Enable it via `AdaptiveDhtConfig`:

```rust
use saorsa_core::AdaptiveDhtConfig;

let config = AdaptiveDhtConfig {
    trust_weighted_routing: true,  // Enable blended distance+trust selection
    routing_weight: 0.3,           // 30% trust, 70% distance
    ..Default::default()
};
```

When enabled, iterative DHT lookups prefer higher-trust peers at similar XOR distances.

## Architecture

```
P2PNode
    │
    ├── report_trust_event(peer, event) ──► AdaptiveDHT ──► TrustEngine
    │                                           │
    ├── peer_trust(peer) ◄────────────── TrustEngine.score()
    │
    └── DHT operations ──► DhtNetworkManager ──► TrustEngine
                           (records per-peer outcomes internally)
```

- **TrustEngine** is the sole authority on peer trust scores
- **AdaptiveDHT** owns TrustEngine and DhtNetworkManager
- **DhtNetworkManager** records trust for DHT operations (iterative lookups)
- **P2PNode** exposes `report_trust_event()` for application-level signals
