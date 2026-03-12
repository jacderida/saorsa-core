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
//! network.
//!
//! ## Canonical string format
//!
//! ```text
//! /ip4/<ipv4>/udp/<port>/quic[/p2p/<peer-id>]
//! /ip6/<ipv6>/udp/<port>/quic[/p2p/<peer-id>]
//! /ip4/<ipv4>/tcp/<port>[/p2p/<peer-id>]
//! /ip6/<ipv6>/tcp/<port>[/p2p/<peer-id>]
//! /bt/<AA:BB:CC:DD:EE:FF>/rfcomm/<channel>[/p2p/<peer-id>]
//! /ble/<AA:BB:CC:DD:EE:FF>/l2cap/<psm>[/p2p/<peer-id>]
//! /lora/<hex-dev-addr>/<freq-hz>[/p2p/<peer-id>]
//! /lorawan/<hex-dev-eui>[/p2p/<peer-id>]
//! /p2p/<peer-id>
//! ```

use std::fmt::{self, Display};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use anyhow::{Result, anyhow};
use serde::{Deserialize, Serialize};

use crate::identity::peer_id::PeerId;

/// Transport protocol and its addressing parameters.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Transport {
    /// QUIC over UDP (primary Saorsa transport).
    Quic(SocketAddr),
    /// Plain TCP.
    Tcp(SocketAddr),
    /// Classic Bluetooth RFCOMM.
    Bluetooth {
        /// 6-byte MAC address.
        mac: [u8; 6],
        /// RFCOMM channel number.
        channel: u8,
    },
    /// Bluetooth Low Energy L2CAP.
    Ble {
        /// 6-byte MAC address.
        mac: [u8; 6],
        /// Protocol/Service Multiplexer.
        psm: u16,
    },
    /// LoRa point-to-point.
    LoRa {
        /// 4-byte device address.
        dev_addr: u32,
        /// Frequency in Hz.
        freq_hz: u32,
    },
    /// LoRaWAN (network-managed).
    LoRaWan {
        /// 8-byte Device EUI.
        dev_eui: u64,
    },
}

impl Transport {
    /// Human-readable transport kind for logging / metrics.
    #[must_use]
    pub fn kind(&self) -> &'static str {
        match self {
            Transport::Quic(_) => "quic",
            Transport::Tcp(_) => "tcp",
            Transport::Bluetooth { .. } => "bluetooth",
            Transport::Ble { .. } => "ble",
            Transport::LoRa { .. } => "lora",
            Transport::LoRaWan { .. } => "lorawan",
        }
    }
}

/// Composable, self-describing network address with an optional [`PeerId`]
/// suffix.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MultiAddr {
    transport: Transport,
    peer_id: Option<PeerId>,
}

impl MultiAddr {
    /// Create a `MultiAddr` from a [`Transport`].
    #[must_use]
    pub fn new(transport: Transport) -> Self {
        Self {
            transport,
            peer_id: None,
        }
    }

    /// Shorthand for `Transport::Quic`.
    #[must_use]
    pub fn quic(addr: SocketAddr) -> Self {
        Self::new(Transport::Quic(addr))
    }

    /// Shorthand for `Transport::Tcp`.
    #[must_use]
    pub fn tcp(addr: SocketAddr) -> Self {
        Self::new(Transport::Tcp(addr))
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

    /// The underlying transport.
    #[must_use]
    pub fn transport(&self) -> &Transport {
        &self.transport
    }

    /// Optional peer identity suffix.
    #[must_use]
    pub fn peer_id(&self) -> Option<&PeerId> {
        self.peer_id.as_ref()
    }

    /// Returns the socket address for IP-based transports (`Quic`, `Tcp`),
    /// `None` for non-IP transports.
    #[must_use]
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        match &self.transport {
            Transport::Quic(a) | Transport::Tcp(a) => Some(*a),
            _ => None,
        }
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
// Display — canonical `/`-delimited format
// ---------------------------------------------------------------------------

impl Display for MultiAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.transport {
            Transport::Quic(addr) => match addr.ip() {
                IpAddr::V4(ip) => write!(f, "/ip4/{}/udp/{}/quic", ip, addr.port())?,
                IpAddr::V6(ip) => write!(f, "/ip6/{}/udp/{}/quic", ip, addr.port())?,
            },
            Transport::Tcp(addr) => match addr.ip() {
                IpAddr::V4(ip) => write!(f, "/ip4/{}/tcp/{}", ip, addr.port())?,
                IpAddr::V6(ip) => write!(f, "/ip6/{}/tcp/{}", ip, addr.port())?,
            },
            Transport::Bluetooth { mac, channel } => {
                write!(
                    f,
                    "/bt/{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}/rfcomm/{}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], channel
                )?;
            }
            Transport::Ble { mac, psm } => {
                write!(
                    f,
                    "/ble/{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}/l2cap/{}",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], psm
                )?;
            }
            Transport::LoRa { dev_addr, freq_hz } => {
                write!(f, "/lora/{:08x}/{}", dev_addr, freq_hz)?;
            }
            Transport::LoRaWan { dev_eui } => {
                write!(f, "/lorawan/{:016x}", dev_eui)?;
            }
        }
        if let Some(pid) = &self.peer_id {
            write!(f, "/p2p/{}", pid.to_hex())?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// FromStr — canonical format only
// ---------------------------------------------------------------------------

impl FromStr for MultiAddr {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return Err(anyhow!("Invalid address format: {}", s));
        }

        // Peer-only: /p2p/<hex>
        if parts[0] == "p2p" {
            // Peer-only addresses aren't routable without a transport layer.
            return Err(anyhow!(
                "Peer-only addresses (/p2p/<id>) are not yet supported as standalone MultiAddr"
            ));
        }

        // IP-based formats
        if parts[0] == "ip4" || parts[0] == "ip6" {
            return parse_ip_addr(&parts, s);
        }

        // Bluetooth: /bt/<MAC>/rfcomm/<channel>
        if parts[0] == "bt" {
            return parse_bluetooth(&parts, s);
        }

        // BLE: /ble/<MAC>/l2cap/<psm>
        if parts[0] == "ble" {
            return parse_ble(&parts, s);
        }

        // LoRa: /lora/<dev-addr>/<freq-hz>
        if parts[0] == "lora" {
            return parse_lora(&parts, s);
        }

        // LoRaWAN: /lorawan/<dev-eui>
        if parts[0] == "lorawan" {
            return parse_lorawan(&parts, s);
        }

        Err(anyhow!("Invalid address format: {}", s))
    }
}

/// Parse `/ip4/...` or `/ip6/...` addresses.
fn parse_ip_addr(parts: &[&str], original: &str) -> Result<MultiAddr> {
    // Minimum: ["ip4", ip, proto, port] or ["ip4", ip, "udp", port, "quic"]
    if parts.len() < 4 {
        return Err(anyhow!("Invalid IP address format: {}", original));
    }

    let ip: IpAddr = parts[1]
        .parse()
        .map_err(|_| anyhow!("Invalid IP address: {}", parts[1]))?;

    // Validate ip4/ip6 matches actual address type
    match (parts[0], &ip) {
        ("ip4", IpAddr::V4(_)) | ("ip6", IpAddr::V6(_)) => {}
        _ => return Err(anyhow!("IP version mismatch in: {}", original)),
    }

    let proto = parts[2];
    let (transport, peer_start) = match proto {
        "tcp" => {
            let port: u16 = parts[3]
                .parse()
                .map_err(|_| anyhow!("Invalid port: {}", parts[3]))?;
            (Transport::Tcp(SocketAddr::new(ip, port)), 4)
        }
        "udp" => {
            let port: u16 = parts[3]
                .parse()
                .map_err(|_| anyhow!("Invalid port: {}", parts[3]))?;
            // Must be followed by "quic"
            if parts.len() < 5 || parts[4] != "quic" {
                return Err(anyhow!(
                    "UDP addresses must include /quic suffix: {}",
                    original
                ));
            }
            (Transport::Quic(SocketAddr::new(ip, port)), 5)
        }
        _ => {
            return Err(anyhow!(
                "Unsupported IP protocol '{}' in: {}",
                proto,
                original
            ));
        }
    };

    let peer_id = parse_optional_peer_id(parts, peer_start)?;
    Ok(MultiAddr { transport, peer_id })
}

/// Parse `/bt/<MAC>/rfcomm/<channel>`.
fn parse_bluetooth(parts: &[&str], original: &str) -> Result<MultiAddr> {
    if parts.len() < 4 || parts[2] != "rfcomm" {
        return Err(anyhow!("Invalid Bluetooth address: {}", original));
    }
    let mac = parse_mac(parts[1])?;
    let channel: u8 = parts[3]
        .parse()
        .map_err(|_| anyhow!("Invalid RFCOMM channel: {}", parts[3]))?;
    let peer_id = parse_optional_peer_id(parts, 4)?;
    Ok(MultiAddr {
        transport: Transport::Bluetooth { mac, channel },
        peer_id,
    })
}

/// Parse `/ble/<MAC>/l2cap/<psm>`.
fn parse_ble(parts: &[&str], original: &str) -> Result<MultiAddr> {
    if parts.len() < 4 || parts[2] != "l2cap" {
        return Err(anyhow!("Invalid BLE address: {}", original));
    }
    let mac = parse_mac(parts[1])?;
    let psm: u16 = parts[3]
        .parse()
        .map_err(|_| anyhow!("Invalid L2CAP PSM: {}", parts[3]))?;
    let peer_id = parse_optional_peer_id(parts, 4)?;
    Ok(MultiAddr {
        transport: Transport::Ble { mac, psm },
        peer_id,
    })
}

/// Parse `/lora/<hex-dev-addr>/<freq-hz>`.
fn parse_lora(parts: &[&str], original: &str) -> Result<MultiAddr> {
    if parts.len() < 3 {
        return Err(anyhow!("Invalid LoRa address: {}", original));
    }
    let dev_addr = u32::from_str_radix(parts[1], 16)
        .map_err(|_| anyhow!("Invalid LoRa dev_addr hex: {}", parts[1]))?;
    let freq_hz: u32 = parts[2]
        .parse()
        .map_err(|_| anyhow!("Invalid LoRa freq_hz: {}", parts[2]))?;
    let peer_id = parse_optional_peer_id(parts, 3)?;
    Ok(MultiAddr {
        transport: Transport::LoRa { dev_addr, freq_hz },
        peer_id,
    })
}

/// Parse `/lorawan/<hex-dev-eui>`.
fn parse_lorawan(parts: &[&str], original: &str) -> Result<MultiAddr> {
    if parts.len() < 2 {
        return Err(anyhow!("Invalid LoRaWAN address: {}", original));
    }
    let dev_eui = u64::from_str_radix(parts[1], 16)
        .map_err(|_| anyhow!("Invalid LoRaWAN dev_eui hex: {}", parts[1]))?;
    let peer_id = parse_optional_peer_id(parts, 2)?;
    Ok(MultiAddr {
        transport: Transport::LoRaWan { dev_eui },
        peer_id,
    })
}

/// Parse an optional `/p2p/<hex>` suffix starting at `start_index`.
fn parse_optional_peer_id(parts: &[&str], start_index: usize) -> Result<Option<PeerId>> {
    if parts.len() <= start_index {
        return Ok(None);
    }
    if parts[start_index] == "p2p" && parts.len() > start_index + 1 {
        if parts.len() > start_index + 2 {
            return Err(anyhow!(
                "Unexpected trailing components after peer ID: {:?}",
                &parts[start_index + 2..]
            ));
        }
        let peer_id = PeerId::from_hex(parts[start_index + 1])
            .map_err(|e| anyhow!("Invalid peer ID in address: {}", e))?;
        Ok(Some(peer_id))
    } else {
        Err(anyhow!(
            "Unexpected trailing components: {:?}",
            &parts[start_index..]
        ))
    }
}

/// Parse a colon-separated MAC address string into 6 bytes.
fn parse_mac(s: &str) -> Result<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return Err(anyhow!("Invalid MAC address (expected 6 octets): {}", s));
    }
    let mut mac = [0u8; 6];
    for (i, part) in parts.iter().enumerate() {
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| anyhow!("Invalid MAC octet '{}' in: {}", part, s))?;
    }
    Ok(mac)
}

/// Collection of network addresses for a peer
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressBook {
    /// Primary addresses for this peer
    pub addresses: Vec<MultiAddr>,
    /// Last known good address
    pub last_known_good: Option<MultiAddr>,
}

impl AddressBook {
    /// Create a new empty address book
    pub fn new() -> Self {
        Self {
            addresses: Vec::new(),
            last_known_good: None,
        }
    }

    /// Create an address book with a single address
    pub fn with_address(address: MultiAddr) -> Self {
        Self {
            addresses: vec![address.clone()],
            last_known_good: Some(address),
        }
    }

    /// Add an address to the book
    pub fn add_address(&mut self, address: MultiAddr) {
        if !self.addresses.contains(&address) {
            self.addresses.push(address);
        }
    }

    /// Remove an address from the book
    pub fn remove_address(&mut self, address: &MultiAddr) {
        self.addresses.retain(|a| a != address);
        if self.last_known_good.as_ref() == Some(address) {
            self.last_known_good = self.addresses.first().cloned();
        }
    }

    /// Update the last known good address
    pub fn update_last_known_good(&mut self, address: MultiAddr) {
        if self.addresses.contains(&address) {
            self.last_known_good = Some(address);
        }
    }

    /// Get the best address to try first
    pub fn best_address(&self) -> Option<&MultiAddr> {
        self.last_known_good
            .as_ref()
            .or_else(|| self.addresses.first())
    }

    /// Get all addresses
    pub fn addresses(&self) -> &[MultiAddr] {
        &self.addresses
    }

    /// Check if the address book is empty
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }

    /// Get the number of addresses
    pub fn len(&self) -> usize {
        self.addresses.len()
    }
}

impl Default for AddressBook {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for AddressBook {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.addresses.is_empty() {
            write!(f, "Empty address book")
        } else {
            write!(
                f,
                "Addresses: [{}]",
                self.addresses
                    .iter()
                    .map(|a| a.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    }
}

/// Serde helpers for serializing `MultiAddr` as a plain string.
///
/// Use with `#[serde(with = "crate::address::serde_as_string")]` on fields
/// of type `MultiAddr` to maintain wire-protocol compatibility.
pub mod serde_as_string {
    use super::MultiAddr;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(addr: &MultiAddr, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&addr.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<MultiAddr, D::Error> {
        let s = String::deserialize(d)?;
        s.parse::<MultiAddr>().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

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
    fn test_address_book() {
        let mut book = AddressBook::new();
        let addr1 = MultiAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 9000);
        let addr2 = MultiAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 2), 9001);

        book.add_address(addr1.clone());
        book.add_address(addr2.clone());

        assert_eq!(book.len(), 2);
        assert_eq!(book.best_address(), Some(&addr1));

        book.update_last_known_good(addr2.clone());
        assert_eq!(book.best_address(), Some(&addr2));
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
    fn test_multiaddr_tcp_parsing() {
        let addr = "/ip4/192.168.1.1/tcp/9000".parse::<MultiAddr>().unwrap();
        assert_eq!(addr.ip(), Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert_eq!(addr.port(), Some(9000));
        assert!(matches!(addr.transport(), Transport::Tcp(_)));
    }

    #[test]
    fn test_multiaddr_quic_parsing() {
        let addr = "/ip4/10.0.0.1/udp/9000/quic".parse::<MultiAddr>().unwrap();
        assert_eq!(addr.ip(), Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert_eq!(addr.port(), Some(9000));
        assert!(matches!(addr.transport(), Transport::Quic(_)));
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
    fn test_display_roundtrip_tcp() {
        let addr = MultiAddr::tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80));
        let s = addr.to_string();
        let parsed: MultiAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_bluetooth_roundtrip() {
        let addr = MultiAddr::new(Transport::Bluetooth {
            mac: [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            channel: 5,
        });
        let s = addr.to_string();
        assert_eq!(s, "/bt/AA:BB:CC:DD:EE:FF/rfcomm/5");
        let parsed: MultiAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_ble_roundtrip() {
        let addr = MultiAddr::new(Transport::Ble {
            mac: [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
            psm: 128,
        });
        let s = addr.to_string();
        assert_eq!(s, "/ble/01:02:03:04:05:06/l2cap/128");
        let parsed: MultiAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_lora_roundtrip() {
        let addr = MultiAddr::new(Transport::LoRa {
            dev_addr: 0xDEAD_BEEF,
            freq_hz: 868_000_000,
        });
        let s = addr.to_string();
        assert_eq!(s, "/lora/deadbeef/868000000");
        let parsed: MultiAddr = s.parse().unwrap();
        assert_eq!(addr, parsed);
    }

    #[test]
    fn test_lorawan_roundtrip() {
        let addr = MultiAddr::new(Transport::LoRaWan {
            dev_eui: 0x0011_2233_4455_6677,
        });
        let s = addr.to_string();
        assert_eq!(s, "/lorawan/0011223344556677");
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
        let addr = MultiAddr::new(Transport::Bluetooth {
            mac: [0; 6],
            channel: 1,
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
    fn test_serde_as_string_roundtrip() {
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize)]
        struct Wrapper {
            #[serde(with = "super::serde_as_string")]
            addr: MultiAddr,
        }

        let original = Wrapper {
            addr: MultiAddr::from_ipv4(Ipv4Addr::new(192, 168, 1, 1), 9000),
        };

        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("/ip4/192.168.1.1/udp/9000/quic"));

        let recovered: Wrapper = serde_json::from_str(&json).unwrap();
        assert_eq!(recovered.addr.ip(), original.addr.ip());
        assert_eq!(recovered.addr.port(), original.addr.port());
    }

    #[test]
    fn test_transport_kind() {
        assert_eq!(
            Transport::Quic(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).kind(),
            "quic"
        );
        assert_eq!(
            Transport::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).kind(),
            "tcp"
        );
        assert_eq!(
            Transport::Bluetooth {
                mac: [0; 6],
                channel: 0
            }
            .kind(),
            "bluetooth"
        );
    }

    #[test]
    fn test_invalid_format_rejected() {
        assert!("127.0.0.1:8080".parse::<MultiAddr>().is_err());
        assert!("garbage".parse::<MultiAddr>().is_err());
        assert!("/ip4/127.0.0.1/udp/8080".parse::<MultiAddr>().is_err()); // missing /quic
        assert!("/ip4/not-an-ip/tcp/80".parse::<MultiAddr>().is_err());
    }
}
