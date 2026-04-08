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

//! Dial-back probe primitives.
//!
//! The requester asks N close-group peers to attempt to dial each of its
//! candidate addresses. Each prober reports a per-address outcome. The
//! [`Classifier`](super::classifier::Classifier) then aggregates the outcomes
//! and applies the 2/3 quorum rule described in ADR-014.
//!
//! This module defines:
//!
//! - [`DialBackOutcome`]: a single (address, reachable) record, carried in
//!   `DhtResponse::DialBackReply` on the wire.
//! - [`DialBackProber`]: the trait that a transport-holder implements to
//!   service incoming dial-back requests. The DHT stream handler holds an
//!   `Arc<dyn DialBackProber>` and calls it once per address.
//! - [`DIAL_BACK_PROBE_TIMEOUT`]: the per-address timeout used by the prober
//!   when making each outbound attempt.

use std::time::Duration;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::MultiAddr;

/// Per-address timeout used by a prober for a single dial-back attempt.
///
/// Chosen as 2 seconds because:
///
/// - A real QUIC handshake against a public IPv4 endpoint usually completes
///   well under 1 second even on moderate RTT.
/// - The existing connection cascade allocates ~3 seconds for the direct-dial
///   Happy Eyeballs stage; the probe is effectively a single stage of that,
///   so a slightly tighter budget is appropriate.
/// - A stale prober that hangs must not block the overall classification by
///   more than the per-address budget times the number of addresses.
///
/// See ADR-014 in `docs/adr/` for the wider classification design.
pub const DIAL_BACK_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// Outcome of a single dial-back attempt against one candidate address.
///
/// One of these is produced per address per prober. The requester collects
/// outcomes from multiple probers and feeds them to the
/// [`Classifier`](super::classifier::Classifier) for quorum evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct DialBackOutcome {
    /// The address the prober was asked to dial.
    pub address: MultiAddr,
    /// `true` if the prober successfully established a QUIC handshake to
    /// `address` within [`DIAL_BACK_PROBE_TIMEOUT`]. `false` for any failure
    /// mode (timeout, refused, invalid address, protocol error).
    pub reachable: bool,
}

impl DialBackOutcome {
    /// Construct a new outcome record.
    pub fn new(address: MultiAddr, reachable: bool) -> Self {
        Self { address, reachable }
    }
}

/// Attempt one outbound dial on behalf of a dial-back probe.
///
/// Implementations must not panic: any error (timeout, refused, invalid
/// address, protocol error) counts as `reachable = false`. The trait is
/// intentionally narrow so that the DHT stream handler can depend on an
/// abstraction rather than a concrete transport, keeping the handler unit
/// testable with a mock prober.
#[async_trait]
pub(crate) trait DialBackProber: Send + Sync + 'static {
    /// Try to dial `address` with `timeout`. Return `true` iff a QUIC
    /// connection was successfully established; the probe connection may be
    /// dropped immediately afterwards.
    ///
    /// `timeout` is supplied by the caller (usually [`DIAL_BACK_PROBE_TIMEOUT`])
    /// so probers do not need to know the policy value. Implementations should
    /// enforce this as a hard ceiling per dial attempt.
    async fn probe(&self, address: &MultiAddr, timeout: Duration) -> bool;
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn example_addr(port: u16) -> MultiAddr {
        MultiAddr::from_ipv4(Ipv4Addr::new(192, 0, 2, 1), port)
    }

    #[test]
    fn outcome_roundtrip_serde() {
        let outcome = DialBackOutcome::new(example_addr(9000), true);
        let bytes = postcard::to_stdvec(&outcome).expect("serialize");
        let decoded: DialBackOutcome = postcard::from_bytes(&bytes).expect("deserialize");
        assert_eq!(decoded, outcome);
    }

    /// A prober that records the addresses it was asked about and returns a
    /// fixed boolean for each. Lives in test module so production code cannot
    /// accidentally depend on it.
    pub(super) struct MockProber {
        pub calls: Arc<AtomicUsize>,
        pub verdict: bool,
    }

    #[async_trait]
    impl DialBackProber for MockProber {
        async fn probe(&self, _address: &MultiAddr, _timeout: Duration) -> bool {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.verdict
        }
    }

    #[tokio::test]
    async fn mock_prober_is_invoked_per_address() {
        let calls = Arc::new(AtomicUsize::new(0));
        let prober = MockProber {
            calls: calls.clone(),
            verdict: true,
        };
        let addrs = [example_addr(1), example_addr(2), example_addr(3)];
        for addr in &addrs {
            let reachable = prober.probe(addr, DIAL_BACK_PROBE_TIMEOUT).await;
            assert!(reachable);
        }
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn timeout_constant_is_nonzero_and_bounded() {
        assert!(DIAL_BACK_PROBE_TIMEOUT > Duration::from_millis(0));
        assert!(DIAL_BACK_PROBE_TIMEOUT < Duration::from_secs(10));
    }
}
