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

//! Pure aggregation of dial-back probe outcomes into per-address
//! classifications.
//!
//! The classifier is deliberately I/O-free: it takes a set of probe outcomes
//! produced by the transport layer and applies the 2/3 quorum rule from
//! ADR-014. This lets the aggregation logic be unit-tested exhaustively,
//! separately from the probing mechanism.
//!
//! The classifier is stateless across calls; the caller is responsible for
//! persisting the resulting map if it needs to survive beyond the current
//! classification round.
//!
//! ## `dead_code` allow
//!
//! The types in this module are exercised by the in-file unit tests but not
//! yet consumed by production code — their consumer, the relay acquisition
//! coordinator, lands in a follow-up ADR-014 work item. `dead_code` is
//! temporarily allowed so the foundation can land ahead of its consumer
//! without losing strict-lint coverage on the rest of the crate.

#![allow(dead_code)]

use std::collections::{HashMap, HashSet};

use crate::MultiAddr;

use super::probe::DialBackOutcome;

/// Below this number of probers, every prober must report success for an
/// address to be considered [`AddressClassification::Direct`]. At or above
/// this number, a 2/3 quorum is sufficient. Set by ADR-014.
const MIN_PROBERS_FOR_QUORUM: usize = 3;

/// Classification of one candidate address after aggregating probe outcomes.
///
/// The classifier produces exactly one of these per address it saw in the
/// input. Unseen addresses are absent from the result map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddressClassification {
    /// The address met the quorum threshold and is considered publicly
    /// dialable. Ready to publish in the node's self-record.
    Direct,
    /// Insufficient evidence of public reachability. The address must not be
    /// published as `Direct`; the node should proceed to relay acquisition if
    /// no other address of theirs is classified as `Direct`.
    NotDirect,
}

/// Stateless aggregator that applies the ADR-014 quorum rule.
///
/// Construct with [`Classifier::new`] (there is currently no configuration to
/// tune — the quorum threshold is a constant). Invoke [`Classifier::classify`]
/// once per classification round.
#[derive(Debug, Clone, Default)]
pub(crate) struct Classifier;

impl Classifier {
    /// Construct a classifier.
    pub fn new() -> Self {
        Self
    }

    /// Compute the minimum number of successful probes required for an
    /// address to be classified as `Direct`, given the number of probers
    /// that were queried.
    ///
    /// Returns `None` when `prober_count == 0` — no classification is
    /// possible. Otherwise returns the threshold, which is:
    ///
    /// - `prober_count` itself when `prober_count < MIN_PROBERS_FOR_QUORUM`
    ///   (every prober must agree — "all successes" rule for small networks).
    /// - `⌈2 · prober_count / 3⌉` otherwise (2/3 quorum rule).
    fn required_successes(prober_count: usize) -> Option<usize> {
        if prober_count == 0 {
            return None;
        }
        if prober_count < MIN_PROBERS_FOR_QUORUM {
            return Some(prober_count);
        }
        Some((2 * prober_count).div_ceil(3))
    }

    /// Aggregate a set of probe replies and classify each address.
    ///
    /// `prober_count` is the number of probers that were originally queried.
    /// This may be greater than the number of replies actually received (e.g.,
    /// if a prober crashed or timed out before replying); the quorum threshold
    /// is computed against `prober_count`, not `replies.len()`, so a missing
    /// reply counts as an implicit "no success" from that prober.
    ///
    /// `replies` is an iterator of per-prober outcome lists. Each outer item
    /// is the reply from one prober, containing one `DialBackOutcome` per
    /// address that prober was asked to probe. Addresses that appear in any
    /// reply will appear in the returned map; addresses that appear in no
    /// reply are simply absent.
    ///
    /// The returned map uses the `MultiAddr` as the key. Callers that need a
    /// deterministic order should sort the keys explicitly.
    pub fn classify<I>(
        &self,
        prober_count: usize,
        replies: I,
    ) -> HashMap<MultiAddr, AddressClassification>
    where
        I: IntoIterator<Item = Vec<DialBackOutcome>>,
    {
        let threshold = Self::required_successes(prober_count);

        let mut success_counts: HashMap<MultiAddr, usize> = HashMap::new();
        let mut all_addresses: HashSet<MultiAddr> = HashSet::new();

        for reply in replies {
            for outcome in reply {
                all_addresses.insert(outcome.address.clone());
                if outcome.reachable {
                    *success_counts.entry(outcome.address).or_insert(0) += 1;
                }
            }
        }

        all_addresses
            .into_iter()
            .map(|addr| {
                let successes = success_counts.get(&addr).copied().unwrap_or(0);
                let classification = match threshold {
                    Some(t) if successes >= t => AddressClassification::Direct,
                    _ => AddressClassification::NotDirect,
                };
                (addr, classification)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    fn addr(port: u16) -> MultiAddr {
        MultiAddr::from_ipv4(Ipv4Addr::new(192, 0, 2, 1), port)
    }

    fn ok(a: &MultiAddr) -> DialBackOutcome {
        DialBackOutcome::new(a.clone(), true)
    }

    fn fail(a: &MultiAddr) -> DialBackOutcome {
        DialBackOutcome::new(a.clone(), false)
    }

    // --- required_successes -------------------------------------------------

    #[test]
    fn required_successes_is_none_for_zero_probers() {
        assert_eq!(Classifier::required_successes(0), None);
    }

    #[test]
    fn required_successes_requires_all_for_one_prober() {
        assert_eq!(Classifier::required_successes(1), Some(1));
    }

    #[test]
    fn required_successes_requires_all_for_two_probers() {
        assert_eq!(Classifier::required_successes(2), Some(2));
    }

    #[test]
    fn required_successes_applies_quorum_at_three_probers() {
        // 2/3 of 3 = 2.
        assert_eq!(Classifier::required_successes(3), Some(2));
    }

    #[test]
    fn required_successes_ceils_for_four_probers() {
        // ceil(2 * 4 / 3) = ceil(8/3) = 3.
        assert_eq!(Classifier::required_successes(4), Some(3));
    }

    #[test]
    fn required_successes_exact_two_thirds_for_six_probers() {
        // 2 * 6 / 3 = 4 exactly.
        assert_eq!(Classifier::required_successes(6), Some(4));
    }

    #[test]
    fn required_successes_ceils_for_seven_probers() {
        // ceil(2 * 7 / 3) = ceil(14/3) = 5.
        assert_eq!(Classifier::required_successes(7), Some(5));
    }

    // --- classify end-to-end ------------------------------------------------

    #[test]
    fn classify_empty_input_is_empty_map() {
        let classifier = Classifier::new();
        let result = classifier.classify(3, Vec::<Vec<DialBackOutcome>>::new());
        assert!(result.is_empty());
    }

    #[test]
    fn classify_zero_probers_marks_everything_not_direct() {
        let classifier = Classifier::new();
        let a = addr(1);
        // Even if an outcome claims success, zero probers means no
        // classification is possible.
        let replies = vec![vec![ok(&a)]];
        let result = classifier.classify(0, replies);
        assert_eq!(result[&a], AddressClassification::NotDirect);
    }

    #[test]
    fn classify_single_prober_requires_success() {
        let classifier = Classifier::new();
        let a = addr(1);
        let b = addr(2);
        let replies = vec![vec![ok(&a), fail(&b)]];
        let result = classifier.classify(1, replies);
        assert_eq!(result[&a], AddressClassification::Direct);
        assert_eq!(result[&b], AddressClassification::NotDirect);
    }

    #[test]
    fn classify_two_probers_require_unanimous() {
        let classifier = Classifier::new();
        let a = addr(1);
        // One success out of two → not direct.
        let replies = vec![vec![ok(&a)], vec![fail(&a)]];
        let result = classifier.classify(2, replies);
        assert_eq!(result[&a], AddressClassification::NotDirect);
    }

    #[test]
    fn classify_two_probers_both_success_is_direct() {
        let classifier = Classifier::new();
        let a = addr(1);
        let replies = vec![vec![ok(&a)], vec![ok(&a)]];
        let result = classifier.classify(2, replies);
        assert_eq!(result[&a], AddressClassification::Direct);
    }

    #[test]
    fn classify_three_probers_two_successes_is_direct() {
        let classifier = Classifier::new();
        let a = addr(1);
        let replies = vec![vec![ok(&a)], vec![ok(&a)], vec![fail(&a)]];
        let result = classifier.classify(3, replies);
        assert_eq!(result[&a], AddressClassification::Direct);
    }

    #[test]
    fn classify_three_probers_one_success_is_not_direct() {
        let classifier = Classifier::new();
        let a = addr(1);
        let replies = vec![vec![ok(&a)], vec![fail(&a)], vec![fail(&a)]];
        let result = classifier.classify(3, replies);
        assert_eq!(result[&a], AddressClassification::NotDirect);
    }

    #[test]
    fn classify_missing_reply_counts_as_no_success() {
        let classifier = Classifier::new();
        let a = addr(1);
        // prober_count = 3 but only 2 replies came back. Both say yes →
        // 2 out of 3 = quorum → Direct.
        let replies = vec![vec![ok(&a)], vec![ok(&a)]];
        let result = classifier.classify(3, replies);
        assert_eq!(result[&a], AddressClassification::Direct);
    }

    #[test]
    fn classify_missing_reply_can_tip_to_not_direct() {
        let classifier = Classifier::new();
        let a = addr(1);
        // prober_count = 3, only 1 reply of success → not enough for quorum.
        let replies = vec![vec![ok(&a)]];
        let result = classifier.classify(3, replies);
        assert_eq!(result[&a], AddressClassification::NotDirect);
    }

    #[test]
    fn classify_independent_per_address() {
        let classifier = Classifier::new();
        let a = addr(1);
        let b = addr(2);
        let c = addr(3);
        // a: 3/3 direct. b: 2/3 direct. c: 0/3 not direct.
        let replies = vec![
            vec![ok(&a), ok(&b), fail(&c)],
            vec![ok(&a), ok(&b), fail(&c)],
            vec![ok(&a), fail(&b), fail(&c)],
        ];
        let result = classifier.classify(3, replies);
        assert_eq!(result[&a], AddressClassification::Direct);
        assert_eq!(result[&b], AddressClassification::Direct);
        assert_eq!(result[&c], AddressClassification::NotDirect);
    }

    #[test]
    fn classify_handles_addresses_appearing_in_only_some_replies() {
        let classifier = Classifier::new();
        let a = addr(1);
        let b = addr(2);
        // Only one prober probed b at all, and it succeeded. With
        // prober_count = 3 the quorum demands 2 successes, and b only has 1.
        let replies = vec![vec![ok(&a), ok(&b)], vec![ok(&a)], vec![ok(&a)]];
        let result = classifier.classify(3, replies);
        assert_eq!(result[&a], AddressClassification::Direct);
        assert_eq!(result[&b], AddressClassification::NotDirect);
    }
}
