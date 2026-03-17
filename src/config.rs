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

//! # Configuration Management System
//!
//! This module provides configuration management for the P2P network,
//! supporting layered configuration (environment > file > defaults) with validation.
//!
//! ## Features
//! - Environment variable override support
//! - TOML/JSON configuration file support
//! - IPv4/IPv6 address validation
//! - Secure defaults

use crate::address::MultiAddr;
use crate::error::ConfigError;
use crate::validation::{ValidationContext, validate_config_value, validate_network_address};
use crate::{P2PError, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::str::FromStr;
use tracing::info;

/// Main configuration structure for the P2P network
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default)]
pub struct Config {
    /// Network configuration
    pub network: NetworkConfig,
    /// Security configuration
    pub security: SecurityConfig,
    /// Transport configuration
    pub transport: TransportConfig,
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkConfig {
    /// Bootstrap nodes for network discovery
    pub bootstrap_nodes: Vec<String>,
    /// Local listen address (0.0.0.0:9000 for all interfaces)
    pub listen_address: String,
    /// Enable IPv6 support
    pub ipv6_enabled: bool,
    /// Maximum concurrent connections
    pub max_connections: usize,
    /// Connection timeout in seconds
    pub connection_timeout: u64,
    /// Keepalive interval in seconds
    pub keepalive_interval: u64,
    /// Allow loopback addresses (for devnet/testnet)
    pub allow_loopback: bool,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    /// Connection limit per IP
    pub connection_limit: u32,
}

/// Transport configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TransportConfig {
    /// Optional override for maximum application-layer message size in bytes.
    ///
    /// When `None`, transport-layer defaults are used.
    pub max_message_size: Option<usize>,
}

// Default implementations

const DEFAULT_MAX_CONNECTIONS: usize = 10000;
const DEFAULT_CONNECTION_TIMEOUT_SECS: u64 = 30;
const DEFAULT_KEEPALIVE_INTERVAL_SECS: u64 = 60;
const DEFAULT_CONNECTION_LIMIT: u32 = 100;
const MAX_CONNECTIONS_UPPER_BOUND: usize = 100_000;

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: vec![],
            // Bind all interfaces by default; env can override via Config::load()
            listen_address: "0.0.0.0:9000".to_string(),
            ipv6_enabled: true,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connection_timeout: DEFAULT_CONNECTION_TIMEOUT_SECS,
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL_SECS,
            allow_loopback: false,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            connection_limit: DEFAULT_CONNECTION_LIMIT,
        }
    }
}

impl Config {
    /// Load configuration from multiple sources with precedence:
    /// 1. Environment variables (highest)
    /// 2. Configuration file
    /// 3. Default values (lowest)
    pub fn load() -> Result<Self> {
        Self::load_with_path::<&str>(None)
    }

    /// Load configuration with a specific config file path
    pub fn load_with_path<P: AsRef<Path>>(path: Option<P>) -> Result<Self> {
        // Start with defaults
        let mut config = Self::default();

        // Load from file if provided or look for default locations
        if let Some(path) = path {
            config = Self::load_from_file(path)?;
        } else {
            // Try default config locations
            for location in &["saorsa.toml", "config.toml", "/etc/saorsa/config.toml"] {
                if Path::new(location).exists() {
                    info!("Loading config from: {}", location);
                    config = Self::load_from_file(location)?;
                    break;
                }
            }
        }

        // Override with environment variables
        config.apply_env_overrides()?;

        // Validate the final configuration
        config.validate()?;

        Ok(config)
    }

    /// Load configuration from a TOML file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = fs::read_to_string(&path).map_err(|e| {
            P2PError::Config(ConfigError::IoError {
                path: path.as_ref().to_string_lossy().to_string().into(),
                source: e,
            })
        })?;

        toml::from_str(&content)
            .map_err(|e| P2PError::Config(ConfigError::ParseError(e.to_string().into())))
    }

    /// Save configuration to a TOML file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| P2PError::Config(ConfigError::ParseError(e.to_string().into())))?;

        fs::write(&path, content).map_err(|e| {
            P2PError::Config(ConfigError::IoError {
                path: path.as_ref().to_string_lossy().to_string().into(),
                source: e,
            })
        })?;

        Ok(())
    }

    /// Apply environment variable overrides
    fn apply_env_overrides(&mut self) -> Result<()> {
        if let Ok(val) = env::var("SAORSA_LISTEN_ADDRESS") {
            self.network.listen_address = val;
        }
        if let Ok(val) = env::var("SAORSA_BOOTSTRAP_NODES") {
            self.network.bootstrap_nodes = val.split(',').map(String::from).collect();
        }
        if let Ok(val) = env::var("SAORSA_MAX_CONNECTIONS") {
            self.network.max_connections = val.parse().map_err(|_| {
                P2PError::Config(ConfigError::InvalidValue {
                    field: "max_connections".to_string().into(),
                    reason: "Invalid value".to_string().into(),
                })
            })?;
        }

        Ok(())
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        let mut errors = Vec::new();

        // Validate network addresses
        if let Err(e) = self.validate_address(&self.network.listen_address, "listen_address") {
            errors.push(e);
        }

        for (i, node) in self.network.bootstrap_nodes.iter().enumerate() {
            if let Err(e) = self.validate_address(node, &format!("bootstrap_node[{}]", i)) {
                errors.push(e);
            }
        }

        // Validate ranges using validation framework
        if let Err(e) = validate_config_value(
            &self.network.max_connections.to_string(),
            Some(1_usize),
            Some(MAX_CONNECTIONS_UPPER_BOUND),
        ) {
            errors.push(P2PError::Config(ConfigError::InvalidValue {
                field: "max_connections".to_string().into(),
                reason: e.to_string().into(),
            }));
        }

        if let Some(max_message_size) = self.transport.max_message_size
            && max_message_size == 0
        {
            errors.push(P2PError::Config(ConfigError::InvalidValue {
                field: "transport.max_message_size".to_string().into(),
                reason: "max_message_size must be at least 1".to_string().into(),
            }));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            // Return the first error, or a generic error if somehow the vec is empty
            Err(errors.into_iter().next().unwrap_or_else(|| {
                P2PError::Config(ConfigError::InvalidValue {
                    field: "unknown".to_string().into(),
                    reason: "Validation failed with unknown error".to_string().into(),
                })
            }))
        }
    }

    /// Validate network address format
    fn validate_address(&self, addr: &str, field: &str) -> Result<()> {
        // Try parsing as SocketAddr first
        if let Ok(socket_addr) = SocketAddr::from_str(addr) {
            // Use our validation framework
            let ctx = ValidationContext::default()
                .allow_localhost() // Allow localhost for development
                .allow_private_ips(); // Allow private IPs for development

            return validate_network_address(&socket_addr, &ctx).map_err(|e| {
                P2PError::Config(ConfigError::InvalidValue {
                    field: field.to_string().into(),
                    reason: e.to_string().into(),
                })
            });
        }

        // Try parsing as multiaddr format
        if addr.starts_with("/ip4/") || addr.starts_with("/ip6/") {
            // Basic multiaddr validation
            return Ok(());
        }

        Err(P2PError::Config(ConfigError::InvalidValue {
            field: field.to_string().into(),
            reason: format!("Invalid address format: {}", addr).into(),
        }))
    }

    /// Create development configuration
    pub fn development() -> Self {
        let mut config = Self::default();
        config.network.listen_address = "127.0.0.1:9000".to_string();
        config.security.connection_limit = 1000;
        config
    }

    /// Get parsed listen address
    pub fn listen_socket_addr(&self) -> Result<SocketAddr> {
        SocketAddr::from_str(&self.network.listen_address).map_err(|e| {
            P2PError::Config(ConfigError::InvalidValue {
                field: "listen_address".to_string().into(),
                reason: format!("Invalid address: {}", e).into(),
            })
        })
    }

    /// Get parsed bootstrap addresses
    pub fn bootstrap_addrs(&self) -> Result<Vec<MultiAddr>> {
        self.network
            .bootstrap_nodes
            .iter()
            .map(|addr| {
                addr.parse::<MultiAddr>().map_err(|e| {
                    P2PError::Config(ConfigError::InvalidValue {
                        field: "bootstrap_nodes".to_string().into(),
                        reason: format!("Invalid address: {}", e).into(),
                    })
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.network.listen_address, "0.0.0.0:9000");
        assert_eq!(config.security.connection_limit, DEFAULT_CONNECTION_LIMIT);
        assert_eq!(config.transport.max_message_size, None);
    }

    #[test]
    fn test_development_config() {
        let config = Config::development();
        assert_eq!(config.network.listen_address, "127.0.0.1:9000");
        assert_eq!(config.security.connection_limit, 1000);
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        // Invalid address
        config.network.listen_address = "invalid".to_string();
        assert!(config.validate().is_err());

        // Valid multiaddr
        config.network.listen_address = "/ip4/127.0.0.1/tcp/9000".to_string();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_config_validation_rejects_zero_transport_max_message_size() {
        let mut config = Config::default();
        config.transport.max_message_size = Some(0);
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_save_and_load_config() {
        let config = Config::development();
        let file = NamedTempFile::new().unwrap();

        config.save_to_file(file.path()).unwrap();

        let loaded = Config::load_from_file(file.path()).unwrap();
        assert_eq!(loaded.network.listen_address, config.network.listen_address);
    }

    #[test]
    #[serial_test::serial]
    #[allow(unsafe_code)] // Required for env::set_var in tests only
    fn test_env_overrides() {
        use std::sync::Mutex;

        // Use a static mutex to ensure thread safety
        static ENV_MUTEX: Mutex<()> = Mutex::new(());
        let _guard = ENV_MUTEX.lock().unwrap();

        // Save original value
        let orig_listen = env::var("SAORSA_LISTEN_ADDRESS").ok();

        // Set test value - unsafe block required in Rust 2024
        unsafe {
            env::set_var("SAORSA_LISTEN_ADDRESS", "127.0.0.1:8000");
        }

        let config = Config::load().unwrap();
        assert_eq!(config.network.listen_address, "127.0.0.1:8000");

        // Restore original value
        unsafe {
            match orig_listen {
                Some(val) => env::set_var("SAORSA_LISTEN_ADDRESS", val),
                None => env::remove_var("SAORSA_LISTEN_ADDRESS"),
            }
        }
    }
}
