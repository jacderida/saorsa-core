# ADR-002: Delegated Transport via saorsa-transport

## Status

Accepted

## Context

P2P networking requires robust transport infrastructure including:

- Connection management
- NAT traversal
- Protocol negotiation
- Configured peer dialing for initial network entry
- Cryptographic transport

Building these from scratch would require substantial development, hardening,
and security review. The Saorsa stack delegates QUIC, NAT traversal, and
post-quantum transport integration to `saorsa-transport`.

## Decision

saorsa-core delegates transport-layer concerns to `saorsa-transport`.
saorsa-core owns higher-level P2P semantics:

- DHT routing and peer records
- Identity and presence management
- Trust computation through EigenTrust
- Message routing over the transport layer

Initial network entry uses configured peers. After startup, peer discovery is
handled by the DHT phonebook. saorsa-core does not maintain a persistent
peer-ranking store for future cold starts.

## Consequences

### Positive

1. Transport bugs fixed upstream benefit saorsa-core.
2. NAT traversal remains isolated in the transport crate.
3. Post-quantum transport integration stays in one layer.
4. saorsa-core can focus on DHT, trust, identity, and message semantics.

### Negative

1. saorsa-transport upgrades may require adapter changes.
2. Debugging transport failures requires knowledge of the transport crate.
3. Integration tests must exercise real transport behavior.

## Migration Notes

When upgrading `saorsa-transport`:

1. Review the transport changelog for API changes.
2. Update saorsa-core adapter code.
3. Test NAT traversal and relay scenarios.
4. Verify configured peer dialing and DHT discovery.
5. Run the full integration test suite.

## References

- [saorsa-transport Repository](https://github.com/maidsafe/saorsa-transport)
- [QUIC RFC 9000](https://www.rfc-editor.org/rfc/rfc9000)
- [Quinn QUIC Implementation](https://github.com/quinn-rs/quinn)
