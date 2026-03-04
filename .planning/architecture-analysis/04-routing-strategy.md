# Routing Strategy Analysis

## Overview

**Answer to Critical Question 3**: **Direct P2P delivery with automatic relay via saorsa-transport when needed. Routing uses S/Kademlia (SKad).**

**Architectural Notes**:
- All nodes are headless in this repository
- saorsa-transport provides automatic relay when direct connection fails
- S/Kademlia routing for DHT operations

---

## Question 1: Are messages routed through intermediate nodes (multi-hop)?

**Answer**: **NO (direct delivery preferred)** - Messages attempt direct P2P delivery first, with automatic saorsa-transport relay as fallback.

**Evidence**:
- Direct delivery attempt: `src/messaging/transport.rs:78` (`try_direct_delivery()`)
- saorsa-transport relay: Built into transport layer (automatic when direct fails)
- No multi-hop application-layer routing

**Behavior**:
1. **First attempt**: Direct P2P connection to recipient
2. **If direct fails**: saorsa-transport automatically handles relay/NAT traversal
3. **No multi-hop routing**: Application doesn't route through intermediate peers

---

## Question 2: Do headless devices act as message relays?

**Answer**: **YES (all nodes are headless in this repo)** - saorsa-transport layer provides relay functionality.

**Clarification**:
- All nodes in saorsa-core are headless nodes
- Relay functionality provided by saorsa-transport transport layer
- Application layer (saorsa-core) uses direct delivery
- Transport layer (saorsa-transport) handles relay when needed

**Evidence**:
- Device types: All nodes use headless configuration
- Relay: saorsa-transport transport layer (not application layer)
- NAT traversal: saorsa-transport handles automatically

---

## Question 3: Is routing direct P2P or does it use DHT routing?

**Answer**: **Both** - Direct P2P for messages, DHT routing (S/Kademlia) for peer discovery.

**Message Delivery**:
- ✅ Direct P2P: `src/messaging/transport.rs:78` (try_direct_delivery)
- ✅ saorsa-transport relay: Automatic fallback for NAT/firewall traversal

**Peer Discovery & DHT Operations**:
- ✅ S/Kademlia (SKad): DHT routing protocol
- ✅ K=8 replication: DHT operations use Kademlia routing
- ✅ Witness protocol: S/Kademlia witness attestations (ADR-005)

**Evidence**:
- SKad routing: `src/dht/` (S/Kademlia implementation)
- Witness protocol: ADR-005 (Byzantine fault tolerance)
- Direct delivery: `src/messaging/transport.rs:62-309`

---

## Question 4: What is the delivery path for a typical message?

**Answer**: **Direct P2P with saorsa-transport relay fallback**

**Delivery Flow**:

```
1. Message Creation
   └─> src/messaging/service.rs:331-335

2. Encryption
   └─> src/messaging/encryption.rs:44-74
   └─> ChaCha20Poly1305 encryption

3. DHT Storage (for offline delivery)
   └─> src/messaging/transport.rs:95
   └─> 1-hour TTL

4. Direct Delivery Attempt
   └─> src/messaging/transport.rs:78-309
   └─> Try direct P2P to recipient endpoints

5a. Direct Success
   └─> Message delivered via QUIC
   └─> End

5b. Direct Failure → saorsa-transport Relay
   └─> saorsa-transport automatically selects relay nodes
   └─> NAT traversal, firewall bypass
   └─> Message delivered via relay
   └─> End
```

---

## Question 5: How does routing work for DHT operations?

**Answer**: **Multiple routing strategies with adaptive selection**

**Routing Strategies Available**:
1. **S/Kademlia (SKad)**: XOR distance metric with K=8 replication
2. **Hyperbolic Routing**: Greedy routing in hyperbolic space
3. **Trust-weighted Routing**: EigenTrust reputation-based selection

**S/Kademlia Features**:
- **Kademlia XOR distance**: Nodes closer to key store data
- **K=8 replication**: Each key stored on 8 nodes
- **Witness protocol**: Byzantine fault tolerance (ADR-005)

**Hyperbolic Routing Features**:
- **Greedy routing**: Navigate hyperbolic coordinate space
- **Low stretch**: Near-optimal path lengths
- **Scalable**: O(log n) routing table size

**Adaptive Selection**:
- **Multi-Armed Bandit**: Thompson Sampling selects best strategy
- **Context-aware**: Chooses routing based on network conditions
- **Performance tracking**: Learns from routing success/failure

**Evidence**:
- SKad implementation: `src/dht/core_engine.rs:622-668`
- Hyperbolic routing: `src/adaptive/mod.rs` (routing strategies)
- Witness protocol: ADR-005 (S/Kademlia Witness Protocol)
- Replication: `src/dht/enhanced_storage.rs:14` (K=8)
- Trust routing: `src/dht/trust_weighted_dht.rs`
- Adaptive selection: ADR-007 (Adaptive Networking with ML)

---

## Architectural Implications

### Impact on Encryption Strategy

**Direct P2P delivery**:
- ✅ Transport-layer encryption (saorsa-transport ML-KEM-768) protects in-transit
- ✅ Application-layer encryption (ChaCha20Poly1305) still REQUIRED for DHT storage

**saorsa-transport relay**:
- ✅ Relay nodes see encrypted QUIC traffic (cannot decrypt)
- ✅ Application-layer encryption provides E2E protection through relay
- ✅ No change to encryption requirements

**Conclusion**: Direct delivery does NOT eliminate need for application-layer encryption because:
1. Messages stored in DHT (untrusted nodes) require encryption
2. Relay nodes (when used) are untrusted intermediaries
3. E2E encryption guarantees privacy regardless of delivery path

### Comparison to Multi-Hop Routing

**If we used multi-hop routing (we don't)**:
- Intermediate nodes would see encrypted messages
- Would require trust in routing nodes
- Would increase latency (each hop)
- Would complicate delivery receipts

**Our approach (direct + relay)**:
- ✅ Simpler: Direct when possible, relay when needed
- ✅ Faster: No unnecessary hops
- ✅ Transparent: saorsa-transport handles relay automatically
- ✅ Secure: E2E encryption protects through relay

---

## Code Evidence Summary

| Finding | File | Line(s) | Evidence |
|---------|------|---------|----------|
| Direct delivery attempt | transport.rs | 78-309 | `try_direct_delivery()` |
| Message delivery loop | transport.rs | 62-88 | `send_message()` |
| DHT storage | transport.rs | 95 | `store_in_dht()` |
| SKad routing | core_engine.rs | 622-668 | K=8 replication |
| Witness protocol | ADR-005 | - | S/Kademlia with attestations |
| Trust routing | trust_weighted_dht.rs | - | EigenTrust integration |

---

## Summary

**Routing Strategy in Saorsa**:
- **Message delivery**: Direct P2P (no multi-hop at application layer)
- **Relay**: Automatic via saorsa-transport when direct fails
- **DHT operations**: Adaptive routing (S/Kademlia, Hyperbolic, Trust-weighted)
- **Routing selection**: Multi-Armed Bandit with Thompson Sampling (ADR-007)
- **Peer discovery**: Kademlia XOR distance + Hyperbolic greedy routing
- **Byzantine tolerance**: Witness attestations (ADR-005)

**Critical finding for Phase 2**:
Direct P2P delivery does NOT eliminate need for application-layer encryption. Messages must be encrypted before DHT storage (untrusted nodes) and when passing through relay nodes (untrusted intermediaries).

---

## Answer to Question 3

**Are messages routed through intermediate nodes (multi-hop)?**

**Answer**: **NO (direct P2P)** - Application layer uses direct delivery. When direct connection fails, saorsa-transport transport layer provides automatic relay (not multi-hop routing).

**Clarification**:
- ✅ Direct P2P preferred
- ✅ saorsa-transport relay as fallback (transparent to application)
- ❌ No multi-hop application-layer routing
- ✅ S/Kademlia routing for DHT operations (peer discovery)

**All nodes are headless**: In saorsa-core repository, all nodes use headless configuration.

**Routing protocol**: S/Kademlia (SKad) with K=8 replication and witness attestations.

---

**Task 4 Complete**: 2026-01-29
**Next**: Task 5 - Message Persistence Classification
