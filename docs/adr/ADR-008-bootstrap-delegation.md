# ADR-008: Bootstrap Peer Discovery Scope

## Status

Superseded

## Context

Earlier designs gave saorsa-core a persistent local store of previously seen
peers and delegated part of that behavior to `saorsa-transport`. That design
has been removed.

The current direction is narrower:

- The DHT is a peer phonebook only.
- Initial network entry uses configured peers.
- User data storage lives above saorsa-core.
- Trust remains in saorsa-core through EigenTrust signals.

## Decision

saorsa-core no longer records peer contact outcomes for future cold starts.
Runtime peer discovery is handled by DHT routing and configured bootstrap
addresses. Any data availability outcomes from higher layers should be reported
to the trust engine rather than stored as transport peer-quality state.

## Consequences

### Positive

1. Startup behavior is easier to reason about.
2. Peer discovery and trust scoring are separate concerns.
3. saorsa-transport no longer needs to expose peer-ranking persistence APIs.
4. Higher layers can report data-serving behavior directly to EigenTrust.

### Negative

1. Nodes rely on configured bootstrap peers and live DHT discovery at startup.
2. Cold-start peer ranking from prior sessions is intentionally unavailable.

## References

- [ADR-002: Delegated Transport via saorsa-transport](./ADR-002-delegated-transport.md)
- [ADR-006: EigenTrust Reputation System](./ADR-006-eigentrust-reputation.md)
