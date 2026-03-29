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

//! # Address Types
//!
//! Composable, self-describing multi-transport address type for the Saorsa P2P
//! network. Wraps [`saorsa_transport::TransportAddr`] with an optional
//! [`PeerId`] suffix.
//!
//! ## Canonical string format
//!
//! ```text
//! /ip4/<ipv4>/udp/<port>/quic[/p2p/<peer-id>]
//! /ip6/<ipv6>/udp/<port>/quic[/p2p/<peer-id>]
//! /ip4/<ipv4>/tcp/<port>[/p2p/<peer-id>]
//! /ip6/<ipv6>/tcp/<port>[/p2p/<peer-id>]
//! /ip4/<ipv4>/udp/<port>[/p2p/<peer-id>]
//! /bt/<AA:BB:CC:DD:EE:FF>/rfcomm/<channel>[/p2p/<peer-id>]
//! /ble/<AA:BB:CC:DD:EE:FF>/l2cap/<psm>[/p2p/<peer-id>]
//! /lora/<hex-dev-addr>/<freq-hz>[/p2p/<peer-id>]
//! /lorawan/<hex-dev-eui>[/p2p/<peer-id>]
//! ```

use std::fmt::{self, Display};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

pub use saorsa_transport::transport::{LoRaParams, TransportAddr};

use crate::identity::peer_id::PeerId;

/// Composable, self-describing network address with an optional [`PeerId`]
/// suffix.
///
/// Wraps a [`TransportAddr`] (which describes *how* to reach a network
/// endpoint) with an optional peer identity (which describes *who* is behind
/// it).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MultiAddr {
    transport: TransportAddr,
    peer_id: Option<PeerId>,
}

impl From<TransportAddr> for MultiAddr {
    fn from(transport: TransportAddr) -> Self {
        Self::new(transport)
    }
}

impl MultiAddr {
    /// Create a `MultiAddr` from a [`TransportAddr`].
    #[must_use]
    pub fn new(transport: TransportAddr) -> Self {
        Self {
            transport,
            peer_id: None,
        }
    }

    /// Shorthand for QUIC-over-UDP transport.
    #[must_use]
    pub fn quic(addr: SocketAddr) -> Self {
        Self::new(TransportAddr::Udp(addr))
    }

    /// Builder: attach a [`PeerId`] to this address.
    #[must_use]
    pub fn with_peer_id(mut self, peer_id: PeerId) -> Self {
        self.peer_id = Some(peer_id);
        self
    }

    /// Create a QUIC `MultiAddr` from an IP address and port.
    #[must_use]
    pub fn from_ip_port(ip: IpAddr, port: u16) -> Self {
        Self::quic(SocketAddr::new(ip, port))
    }

    /// Create a QUIC `MultiAddr` from an IPv4 address and port.
    #[must_use]
    pub fn from_ipv4(ip: Ipv4Addr, port: u16) -> Self {
        Self::from_ip_port(IpAddr::V4(ip), port)
    }

    /// Create a QUIC `MultiAddr` from an IPv6 address and port.
    #[must_use]
    pub fn from_ipv6(ip: Ipv6Addr, port: u16) -> Self {
        Self::from_ip_port(IpAddr::V6(ip), port)
    }

    // -----------------------------------------------------------------------
    // Accessors
    // -----------------------------------------------------------------------

    /// The underlying transport address.
    #[must_use]
    pub fn transport(&self) -> &TransportAddr {
        &self.transport
    }

    /// Optional peer identity suffix.
    #[must_use]
    pub fn peer_id(&self) -> Option<&PeerId> {
        self.peer_id.as_ref()
    }

    /// `true` when this address uses the QUIC-over-UDP transport — the only
    /// transport currently supported for dialing. When additional transports
    /// are added, update this method (and [`Self::dialable_socket_addr`]).
    #[must_use]
    pub fn is_quic(&self) -> bool {
        matches!(self.transport, TransportAddr::Udp(_))
    }

    /// Returns the [`SocketAddr`] **only** for transports we can currently
    /// dial (QUIC-over-UDP). Returns `None` for all other transports.
    ///
    /// Use [`Self::socket_addr`] when you need the raw socket address
    /// regardless of transport (e.g. IP diversity checks, geo lookups).
    #[must_use]
    pub fn dialable_socket_addr(&self) -> Option<SocketAddr> {
        match self.transport {
            TransportAddr::Udp(sa) => Some(sa),
            _ => None,
        }
    }

    /// Returns the socket address for IP-based transports (`Quic`, `Tcp`,
    /// `Udp`), `None` for non-IP transports.
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.transport.as_socket_addr()
    }

    /// Returns the IP address for IP-based transports, `None` otherwise.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.socket_addr().map(|a| a.ip())
    }

    /// Returns the port for IP-based transports, `None` otherwise.
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.socket_addr().map(|a| a.port())
    }

    /// `true` for IP-based transports with IPv4 addressing.
    pub fn is_ipv4(&self) -> bool {
        self.socket_addr().is_some_and(|a| a.is_ipv4())
    }

    /// `true` for IP-based transports with IPv6 addressing.
    pub fn is_ipv6(&self) -> bool {
        self.socket_addr().is_some_and(|a| a.is_ipv6())
    }

    /// `true` if this is an IP-based loopback address, `false` otherwise.
    pub fn is_loopback(&self) -> bool {
        self.ip().is_some_and(|ip| ip.is_loopback())
    }

    /// `true` if this is an IP-based private/link-local address, `false`
    /// otherwise.
    pub fn is_private(&self) -> bool {
        match self.ip() {
            Some(IpAddr::V4(ip)) => ip.is_private(),
            Some(IpAddr::V6(ip)) => {
                let octets = ip.octets();
                (octets[0] & 0xfe) == 0xfc
            }
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// Display — delegates transport part to TransportAddr, appends /p2p/ suffix
// ---------------------------------------------------------------------------

impl Display for MultiAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        format_transport(&self.transport, f)?;
        if let Some(pid) = &self.peer_id {
            write!(f, "/p2p/{}", pid.to_hex())?;
        }
        Ok(())
    }
}

/// Format a [`TransportAddr`] as a multiaddr-style string.
fn format_transport(transport: &TransportAddr, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match transport {
        TransportAddr::Udp(sa) => match sa.ip() {
            IpAddr::V4(ip) => write!(f, "/ip4/{ip}/udp/{}/quic", sa.port()),
            IpAddr::V6(ip) => write!(f, "/ip6/{ip}/udp/{}/quic", sa.port()),
        },
        TransportAddr::Ble { device_id, .. } => {
            write!(
                f,
                "/ble/{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                device_id[0], device_id[1], device_id[2], device_id[3], device_id[4], device_id[5]
            )
        }
        TransportAddr::LoRa { device_addr, .. } => {
            write!(
                f,
                "/lora/{:02x}{:02x}{:02x}{:02x}",
                device_addr[0], device_addr[1], device_addr[2], device_addr[3]
            )
        }
        // Fall back to TransportAddr's own Display for other transports.
        other => write!(f, "{other}"),
    }
}

// ---------------------------------------------------------------------------
// FromStr — strips /p2p/ suffix, delegates transport parsing to TransportAddr
// ---------------------------------------------------------------------------

impl FromStr for MultiAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        if s.is_empty() {
            return Err(anyhow!("Invalid address format: empty string"));
        }

        // Look for /p2p/ suffix (find last occurrence to be safe).
        if let Some(p2p_idx) = s.rfind("/p2p/") {
            let transport_part = &s[..p2p_idx];
            let peer_hex = &s[p2p_idx + 5..]; // skip "/p2p/"

            // Reject standalone /p2p/<id> with no transport.
            if transport_part.is_empty() {
                return Err(anyhow!(
                    "Peer-only addresses (/p2p/<id>) are not yet supported as standalone MultiAddr"
                ));
            }

            // Reject trailing garbage after peer ID.
            if peer_hex.contains('/') {
                return Err(anyhow!(
                    "Unexpected trailing components after peer ID in: {}",
                    s
                ));
            }

            let transport = parse_transport(transport_part)?;
            let peer_id = PeerId::from_hex(peer_hex)
                .map_err(|e| anyhow!("Invalid peer ID in address: {}", e))?;

            Ok(MultiAddr {
                transport,
                peer_id: Some(peer_id),
            })
        } else {
            // No /p2p/ suffix — pure transport address.
            let transport = parse_transport(s)?;

            Ok(MultiAddr {
                transport,
                peer_id: None,
            })
        }
    }
}

/// BLE MAC address length in bytes.
const BLE_MAC_LEN: usize = 6;
/// LoRa device address length in bytes.
const LORA_ADDR_LEN: usize = 4;
/// LoRa device address hex string length (2 hex chars per byte).
const LORA_ADDR_HEX_LEN: usize = LORA_ADDR_LEN * 2;
/// Minimum multiaddr parts for a valid transport (e.g. `/ble/MAC`).
const MIN_MULTIADDR_PARTS: usize = 3;
/// Minimum multiaddr parts for an IP-based transport (e.g. `/ip4/addr/udp/port`).
const MIN_IP_MULTIADDR_PARTS: usize = 5;

/// Parse a multiaddr-style transport string into a [`TransportAddr`].
///
/// Accepted formats:
/// - `/ip4/<ipv4>/udp/<port>/quic`
/// - `/ip6/<ipv6>/udp/<port>/quic`
/// - `/ip4/<ipv4>/udp/<port>`
/// - `/ip6/<ipv6>/udp/<port>`
/// - `/ble/<MAC>`
/// - `/lora/<hex-dev-addr>`
fn parse_transport(s: &str) -> Result<TransportAddr> {
    let parts: Vec<&str> = s.split('/').collect();

    // parts[0] is always "" (leading /)
    if parts.len() < MIN_MULTIADDR_PARTS {
        return Err(anyhow!("Invalid transport address: {}", s));
    }

    match parts[1] {
        "ip4" | "ip6" => parse_ip_transport(&parts, s),
        "ble" => parse_ble_transport(&parts, s),
        "lora" => parse_lora_transport(&parts, s),
        other => Err(anyhow!("Unsupported transport protocol: {}", other)),
    }
}

/// Parse `/ip4/...` or `/ip6/...` multiaddr into a UDP [`TransportAddr`].
fn parse_ip_transport(parts: &[&str], original: &str) -> Result<TransportAddr> {
    // Minimum: ["", "ip4", addr, "udp", port]
    if parts.len() < MIN_IP_MULTIADDR_PARTS {
        return Err(anyhow!("Invalid IP transport address: {}", original));
    }

    let ip: IpAddr = parts[2]
        .parse()
        .map_err(|e| anyhow!("Invalid IP address '{}': {}", parts[2], e))?;

    if parts[3] != "udp" && parts[3] != "tcp" {
        return Err(anyhow!(
            "Expected 'udp' or 'tcp' protocol, got '{}'",
            parts[3]
        ));
    }

    let port: u16 = parts[4]
        .parse()
        .map_err(|e| anyhow!("Invalid port '{}': {}", parts[4], e))?;

    Ok(TransportAddr::Udp(SocketAddr::new(ip, port)))
}

/// Parse `/ble/<MAC>` multiaddr into a BLE [`TransportAddr`].
fn parse_ble_transport(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < MIN_MULTIADDR_PARTS {
        return Err(anyhow!("Invalid BLE address: {}", original));
    }
    let mac_str = parts[2];
    let mac_bytes: Vec<u8> = mac_str
        .split(':')
        .map(|b| u8::from_str_radix(b, 16).map_err(|e| anyhow!("Invalid BLE MAC byte: {}", e)))
        .collect::<Result<Vec<u8>>>()?;
    if mac_bytes.len() != BLE_MAC_LEN {
        return Err(anyhow!(
            "BLE MAC address must be {} bytes, got {}",
            BLE_MAC_LEN,
            mac_bytes.len()
        ));
    }
    let mut device_id = [0u8; BLE_MAC_LEN];
    device_id.copy_from_slice(&mac_bytes);
    Ok(TransportAddr::Ble {
        device_id,
        service_uuid: None,
    })
}

/// Parse `/lora/<hex-dev-addr>` multiaddr into a LoRa [`TransportAddr`].
fn parse_lora_transport(parts: &[&str], original: &str) -> Result<TransportAddr> {
    if parts.len() < MIN_MULTIADDR_PARTS {
        return Err(anyhow!("Invalid LoRa address: {}", original));
    }
    let hex_str = parts[2];
    if hex_str.len() != LORA_ADDR_HEX_LEN {
        return Err(anyhow!(
            "LoRa device address must be {} bytes ({} hex chars), got '{}'",
            LORA_ADDR_LEN,
            LORA_ADDR_HEX_LEN,
            hex_str
        ));
    }
    let bytes: Vec<u8> = (0..LORA_ADDR_LEN)
        .map(|i| {
            u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
                .map_err(|e| anyhow!("Invalid LoRa hex byte: {}", e))
        })
        .collect::<Result<Vec<u8>>>()?;
    let mut device_addr = [0u8; LORA_ADDR_LEN];
    device_addr.copy_from_slice(&bytes);
    Ok(TransportAddr::LoRa {
        device_addr,
        params: LoRaParams::default(),
    })
}

// ---------------------------------------------------------------------------
// Serde — serialize as canonical string
// ---------------------------------------------------------------------------

impl Serialize for MultiAddr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MultiAddr {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<MultiAddr>().map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// AddressBook
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use saorsa_transport::transport::TransportType;
    use std::net::Ipv6Addr;

    #[test]
    fn test_network_address_creation() {
        let addr = MultiAddr::from_ipv4(Ipv4Addr::new(127, 0, 0, 1), 8080);
        assert_eq!(addr.ip(), Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(addr.port(), Some(8080));
        assert!(addr.is_ipv4());
        assert!(addr.is_loopback());
    }

    #[test]
    fn test_network_address_from_string() {
        let addr = "/ip4/127.0.0.1/udp/8080/quic".parse::<MultiAddr>().unwrap();
        assert_eq!(addr.ip(), Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(addr.port(), Some(8080));
    }

    #[test]
    fn test_network_address_display() {
        let addr = MultiAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 9000);
        assert_eq!(addr.to_string(), "/ip4/192.168.1.1/udp/9000/quic");
    }

    #[test]
    fn test_private_address_detection() {
        let private_addr = MultiAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 9000);
        assert!(private_addr.is_private());

        let public_addr = MultiAddr::from_ipv4(Ipv4Addr::new(8, 8, 8, 8), 53);
        assert!(!public_addr.is_private());
    }

    #[test]
    fn test_ipv6_address() {
        let addr = MultiAddr::from_ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1), 8080);
        assert!(addr.is_ipv6());
        assert!(addr.is_loopback());
    }

    #[test]
    fn test_multiaddr_tcp_parses_as_udp() {
        // TCP multiaddr strings are accepted but mapped to the Udp variant
        // (saorsa-transport no longer has a separate TCP variant).
        let addr = "/ip4/192.168.1.1/tcp/9000".parse::<MultiAddr>().unwrap();
        assert_eq!(addr.ip(), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(addr.port(), Some(9000));
        assert!(matches!(addr.transport(), TransportAddr::Udp(_)));
    }

    #[test]
    fn test_multiaddr_quic_parsing() {
        let addr = "/ip4/10.0.0.1/udp/9000/quic".parse::<MultiAddr>().unwrap();
        assert_eq!(addr.ip(), Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(addr.port(), Some(9000));
        assert!(matches!(addr.transport(), TransportAddr::Udp(_)));
    }

    #[test]
    fn test_multiaddr_raw_udp_parsing() {
        let addr = "/ip4/10.0.0.1/udp/5000".parse::<MultiAddr>().unwrap();
        assert_eq!(addr.port(), Some(5000));
        assert!(matches!(addr.transport(), TransportAddr::Udp(_)));
    }

    #[test]
    fn test_multiaddr_ipv6_quic_parsing() {
        let addr = "/ip6/::1/udp/8080/quic".parse::<MultiAddr>().unwrap();
        assert_eq!(
            addr.ip(),
            Some(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))
        );
        assert_eq!(addr.port(), Some(8080));
        assert!(addr.is_loopback());
    }

    #[test]
    fn test_display_roundtrip_quic() {
        let addr = MultiAddr::from_ipv4(Ipv4Addr::new(1, 2, 3, 4), 9000);
        let s = addr.to_string();
        let parsed: MultiAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_ble_roundtrip() {
        let addr = MultiAddr::new(TransportAddr::Ble {
            device_id: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            service_uuid: None,
        });
        let s = addr.to_string();
        assert_eq!(s, "/ble/01:02:03:04:05:06");
        let parsed: MultiAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_lora_roundtrip() {
        let addr = MultiAddr::new(TransportAddr::LoRa {
            device_addr: [0xDE, 0xAD, 0xBE, 0xEF],
            params: LoRaParams::default(),
        });
        let s = addr.to_string();
        assert_eq!(s, "/lora/deadbeef");
        let parsed: MultiAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_peer_id_suffix() {
        let peer_id = PeerId::from_bytes([0xAA; 32]);
        let addr = MultiAddr::from_ipv4(Ipv4Addr::new(1, 2, 3, 4), 9000).with_peer_id(peer_id);
        let s = addr.to_string();
        assert!(s.starts_with("/ip4/1.2.3.4/udp/9000/quic/p2p/"));
        let parsed: MultiAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
        assert_eq!(parsed.peer_id(), Some(&peer_id));
    }

    #[test]
    fn test_non_ip_transport_accessors() {
        let addr = MultiAddr::new(TransportAddr::Ble {
            device_id: [0; 6],
            service_uuid: None,
        });
        assert_eq!(addr.socket_addr(), None);
        assert_eq!(addr.ip(), None);
        assert_eq!(addr.port(), None);
        assert!(!addr.is_loopback());
        assert!(!addr.is_private());
        assert!(!addr.is_ipv4());
        assert!(!addr.is_ipv6());
    }

    #[test]
    fn test_serde_direct_roundtrip() {
        let addr = MultiAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1), 9000);
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(json, r#""/ip4/10.0.0.1/udp/9000/quic""#);
        let recovered: MultiAddr = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, recovered);
    }

    #[test]
    fn test_transport_type() {
        assert_eq!(
            TransportAddr::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .transport_type(),
            TransportType::Udp
        );
        assert_eq!(
            TransportAddr::Ble {
                device_id: [0; 6],
                service_uuid: None
            }
            .transport_type(),
            TransportType::Ble
        );
    }

    #[test]
    fn test_invalid_format_rejected() {
        // Bare "ip:port" is no longer accepted — canonical format required.
        assert!("127.0.0.1:8080".parse::<MultiAddr>().is_err());
        assert!("garbage".parse::<MultiAddr>().is_err());
        assert!("/ip4/not-an-ip/tcp/80".parse::<MultiAddr>().is_err());
        assert!("".parse::<MultiAddr>().is_err());
    }

    /// T2: Serde roundtrip for a `MultiAddr` that includes a `/p2p/<id>` suffix.
    #[test]
    fn test_serde_roundtrip_with_peer_id() {
        let peer_id = PeerId::from_bytes([0xBB; 32]);
        let addr = MultiAddr::from_ipv4(Ipv4Addr::new(10, 0, 0, 1), 9000).with_peer_id(peer_id);

        let json = serde_json::to_string(&addr).unwrap();
        assert!(
            json.contains("/p2p/"),
            "serialized form must contain /p2p/ suffix"
        );

        let recovered: MultiAddr = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, recovered, "serde roundtrip must be lossless");
        assert_eq!(recovered.peer_id(), Some(&peer_id));
    }

    /// T3: `dialable_socket_addr()` returns `None` for non-UDP transports.
    #[test]
    fn test_dialable_socket_addr_none_for_non_udp() {
        let ble_addr = MultiAddr::new(TransportAddr::Ble {
            device_id: [0; 6],
            service_uuid: None,
        });
        assert!(
            ble_addr.dialable_socket_addr().is_none(),
            "BLE addresses should not be dialable (UDP-only policy)"
        );

        // Sanity: QUIC-over-UDP *is* dialable.
        let quic_addr = MultiAddr::quic(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80));
        assert!(quic_addr.dialable_socket_addr().is_some());
    }

    /// T4: Standalone `/p2p/<id>` without a transport prefix is rejected.
    #[test]
    fn test_standalone_peer_id_rejected() {
        let peer_hex = "aa".repeat(32); // 64 hex chars
        let input = format!("/p2p/{peer_hex}");
        let result = input.parse::<MultiAddr>();
        assert!(
            result.is_err(),
            "standalone /p2p/<id> without transport must be rejected"
        );
    }

    /// L2: `From<TransportAddr>` enables idiomatic `.into()` conversion.
    #[test]
    fn test_from_transport_addr() {
        let transport = TransportAddr::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9000));
        let addr: MultiAddr = transport.clone().into();
        assert_eq!(addr.transport(), &transport);
        assert_eq!(addr.peer_id(), None);
    }
}
