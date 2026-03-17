# Trust Signals API Reference

## Overview

saorsa-core provides a response-rate trust system for tracking node reliability.
The trust system is owned by `AdaptiveDHT`, which is the sole authority on peer trust scores.

DHT-internal events (iterative lookup success/failure) are recorded automatically.
External callers can report additional network-observable outcomes via `TrustEvent`.

The trust system enables:
- **Sybil resistance**: Malicious nodes are downscored automatically
- **Binary blocking**: Peers below the block threshold are evicted and rejected
- **Self-healing**: Time decay moves blocked peers back toward neutral over days
- **Live eviction**: Peers below trust threshold are evicted from the routing table immediately

## Quick Start

```rust
use saorsa_core::{P2PNode, TrustEvent};

// After successful data retrieval from a peer:
node.report_trust_event(&peer_id, TrustEvent::SuccessfulResponse).await;

// After a connection failure:
node.report_trust_event(&peer_id, TrustEvent::ConnectionFailed).await;

// Check peer trust before operations:
let trust = node.peer_trust(&peer_id);
if trust < 0.3 {
    tracing::warn!("Low trust peer: {peer_id}");
}
```

## P2PNode Trust Methods

### `report_trust_event(peer_id, event)`

Report a network-observable trust event for a peer. Use this for connection
outcomes that the DHT layer did not record automatically (e.g. failures
observed by the application's own request paths).

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
pub fn trust_engine(&self) -> &Arc<TrustEngine>
```

## TrustEvent Enum

Only network-observable events are included. Application-level events
(data verification, storage checks) will be added as `TrustEvent` variants
when saorsa-node's data layer is built.

| Event | Severity | Description | Where it fires |
|-------|----------|-------------|----------------|
| `SuccessfulResponse` | Positive | Peer responded to a request | `send_request()` success |
| `SuccessfulConnection` | Positive | Peer connected and authenticated | `handle_peer_connected()` |
| `ConnectionFailed` | 1x penalty | Could not establish connection | `send_request()` error, `dial_candidate()` error |
| `ConnectionTimeout` | 1x penalty | Connection attempt timed out | `send_request()` timeout, `dial_candidate()` timeout |

Note: Peer disconnects are normal connection lifecycle — they do not affect trust.

## Peer Blocking

Peers whose trust score falls below `block_threshold` are:
- **Evicted** from the DHT routing table (via EvictionManager)
- **Blocked** from sending DHT messages (silently dropped)
- **Rejected** from re-entering the routing table on reconnect

```rust
use saorsa_core::AdaptiveDhtConfig;

let config = AdaptiveDhtConfig {
    block_threshold: 0.15,  // Block peers below 15% trust
    ..Default::default()
};
```

DHT routing uses pure Kademlia XOR distance — trust does not influence peer selection order.

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
- **P2PNode** exposes `report_trust_event()` for additional network-observable signals
