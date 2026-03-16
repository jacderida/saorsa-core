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

Only events observable by the saorsa-core network layer are included.
Application-level events (data verification, storage checks) should be added
when the consuming application layer exists.

| Event | Severity | Description | Where it fires |
|-------|----------|-------------|----------------|
| `SuccessfulResponse` | Positive | Peer responded to a request | `send_request()` success |
| `SuccessfulConnection` | Positive | Peer connected and authenticated | `handle_peer_connected()` |
| `ConnectionFailed` | 1x penalty | Could not establish connection | `send_request()` error, `dial_candidate()` error |
| `ConnectionTimeout` | 1x penalty | Connection attempt timed out | `send_request()` timeout, `dial_candidate()` timeout |
| `ProtocolViolation` | 2x penalty | Peer violated wire protocol | Future: DHT message validation |

Note: Peer disconnects are normal connection lifecycle — they do not affect trust.

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
