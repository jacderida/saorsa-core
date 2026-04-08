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

//! # Reachability classification
//!
//! Implements the proactive dial-back probe and per-address classifier
//! described in [ADR-014](../../docs/adr/ADR-014-proactive-relay-first-nat-traversal.md).
//!
//! ## Overview
//!
//! After bootstrap, a node classifies each of its candidate listen addresses by
//! asking close-group peers to dial the address back to it. If ≥ 2/3 of probers
//! succeed (or all probers, for small networks), the address is marked
//! [`AddressClassification::Direct`]; otherwise the node treats itself as
//! private and proceeds to acquire a MASQUE relay from a public close-group
//! peer.
//!
//! The module is organised into two concerns:
//!
//! - [`probe`]: the [`DialBackProber`] trait and per-address [`DialBackOutcome`]
//!   record. Anything that can attempt a one-shot outbound dial implements the
//!   trait; the DHT stream handler holds an `Arc<dyn DialBackProber>` and uses
//!   it to service incoming `DialBackRequest` messages.
//! - [`classifier`]: the pure aggregation logic. Given a set of probe replies
//!   and the number of probers originally queried, [`Classifier`] applies the
//!   quorum rule and returns a per-address [`AddressClassification`] map. It
//!   has no I/O, no async, and is unit-tested in isolation.
//!
//! The wire-level request/response types that carry the protocol over the DHT
//! stream live in [`crate::dht::network_integration`] alongside the other DHT
//! message variants (`DhtMessage::DialBackRequest` / `DhtResponse::DialBackReply`).
//!
//! ## Incremental landing
//!
//! The `Classifier` and `AddressClassification` re-exports appear unused to
//! the compiler today — their direct consumer (the relay acquisition
//! coordinator) is a subsequent ADR-014 work item. The re-exports are kept at
//! the module root so the consumer can land without restructuring the module
//! layout. `unused_imports` is allowed locally for that reason.

#![allow(unused_imports)]

pub(crate) mod acquisition;
pub(crate) mod classifier;
pub(crate) mod probe;

pub(crate) use acquisition::{
    AcquiredRelay, RelayAcquisition, RelayAcquisitionError, RelayCandidate,
    RelaySessionEstablishError, RelaySessionEstablisher,
};
pub(crate) use classifier::{AddressClassification, Classifier};
pub(crate) use probe::{DIAL_BACK_PROBE_TIMEOUT, DialBackOutcome, DialBackProber};
