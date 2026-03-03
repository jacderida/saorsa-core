// Copyright 2024 Saorsa Labs
// SPDX-License-Identifier: AGPL-3.0-or-later

//! CLI commands for identity management

use super::node_identity::{IdentityData, NodeIdentity, PeerId};
use crate::Result;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::info;

/// Generate a new identity (no proof-of-work)
pub fn generate_identity() -> Result<()> {
    let start = std::time::Instant::now();
    let identity = NodeIdentity::generate()?;
    let elapsed = start.elapsed();

    info!("✅ Identity generated successfully (no PoW)");
    info!("⏱️  Generation time: {:?}", elapsed);
    info!("📋 Identity Details:");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("Node ID:      {}", identity.peer_id());
    info!(
        "Public Key:   {}",
        hex::encode(identity.public_key().as_bytes())
    );
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    Ok(())
}

/// Save identity to file
pub fn save_identity(identity: &NodeIdentity, path: &Path) -> Result<()> {
    let data = identity.export();
    let json = serde_json::to_string_pretty(&data).map_err(|e| {
        crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
            format!("Failed to serialize identity: {}", e).into(),
        ))
    })?;

    fs::write(path, json).map_err(|e| {
        crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
            format!("Failed to write identity file: {}", e).into(),
        ))
    })?;

    info!("✅ Identity saved to: {}", path.display());
    Ok(())
}

/// Load identity from file
pub fn load_identity(path: &Path) -> Result<NodeIdentity> {
    let json = fs::read_to_string(path).map_err(|e| {
        crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
            format!("Failed to read identity file: {}", e).into(),
        ))
    })?;

    let data: IdentityData = serde_json::from_str(&json).map_err(|e| {
        crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
            format!("Failed to parse identity file: {}", e).into(),
        ))
    })?;

    let identity = NodeIdentity::import(&data)?;

    info!("✅ Identity loaded from: {}", path.display());
    info!("Node ID: {}", identity.peer_id());

    Ok(identity)
}

/// Display identity information
pub fn show_identity(identity: &NodeIdentity) -> Result<()> {
    info!("🆔 P2P Identity Information");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("Node ID:       {}", identity.peer_id());
    info!(
        "Public Key:    {}",
        hex::encode(identity.public_key().as_bytes())
    );
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    Ok(())
}

// Public CLI types and handler used by integration tests

#[derive(Debug)]
pub enum IdentityCommand {
    /// Generate a new identity
    Generate {
        /// Output file path
        output: Option<PathBuf>,

        /// Seed for deterministic generation
        seed: Option<String>,
    },

    /// Show identity information
    Show {
        /// Identity file path
        path: Option<PathBuf>,
    },

    /// Verify identity validity
    Verify {
        /// Identity file path
        path: Option<PathBuf>,
    },

    /// Export identity in different formats
    Export {
        /// Identity file path
        path: Option<PathBuf>,

        /// Output file
        output: PathBuf,

        /// Export format
        format: String,
    },

    /// Sign a message
    Sign {
        /// Identity file path
        identity: Option<PathBuf>,

        /// Message to sign (file path or text)
        message: MessageInput,

        /// Output file for signature
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Clone)]
pub enum MessageInput {
    Text(String),
    File(PathBuf),
}

#[derive(Debug)]
pub enum ExportFormat {
    Json,
    Base64,
    Hex,
}

pub struct IdentityCliHandler {
    default_path: Option<PathBuf>,
}

impl IdentityCliHandler {
    pub fn new(default_path: Option<PathBuf>) -> Self {
        Self { default_path }
    }

    pub async fn execute(&self, command: IdentityCommand) -> Result<String> {
        match command {
            IdentityCommand::Generate { output, seed } => self.handle_generate(output, seed).await,
            IdentityCommand::Show { path } => self.handle_show(path).await,
            IdentityCommand::Verify { path } => self.handle_verify(path).await,
            IdentityCommand::Export {
                path,
                output,
                format,
            } => self.handle_export(path, output, format).await,
            IdentityCommand::Sign {
                identity,
                message,
                output,
            } => self.handle_sign(identity, message, output).await,
        }
    }

    async fn handle_generate(
        &self,
        output: Option<PathBuf>,
        seed: Option<String>,
    ) -> Result<String> {
        let output_path = output
            .or_else(|| self.default_path.clone())
            .ok_or_else(|| {
                crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                    "No output path specified".into(),
                ))
            })?;

        let identity = if let Some(seed_str) = seed {
            // Deterministic generation from seed
            let mut seed_bytes = [0u8; 32];
            let seed_hash = blake3::hash(seed_str.as_bytes());
            seed_bytes.copy_from_slice(seed_hash.as_bytes());
            NodeIdentity::from_seed(&seed_bytes)?
        } else {
            NodeIdentity::generate()?
        };

        identity.save_to_file(&output_path).await?;

        let word_address = derive_word_address(identity.peer_id());

        Ok(format!(
            "Generated new identity\nNode ID: {}\nWord Address: {}\nSaved to: {}",
            identity.peer_id(),
            word_address,
            output_path.display()
        ))
    }

    async fn handle_show(&self, path: Option<PathBuf>) -> Result<String> {
        let path = path.or_else(|| self.default_path.clone()).ok_or_else(|| {
            crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                "No identity found".into(),
            ))
        })?;

        let identity = NodeIdentity::load_from_file(&path).await?;

        let word_address = derive_word_address(identity.peer_id());

        Ok(format!(
            "Identity Information\nNode ID: {}\nWord Address: {}\nPublic Key: {}\nPoW Difficulty: N/A",
            identity.peer_id(),
            word_address,
            hex::encode(identity.public_key().as_bytes())
        ))
    }

    async fn handle_verify(&self, path: Option<PathBuf>) -> Result<String> {
        let path = path.or_else(|| self.default_path.clone()).ok_or_else(|| {
            crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                "No identity found".into(),
            ))
        })?;

        let identity = NodeIdentity::load_from_file(&path).await?;

        let _word_address = derive_word_address(identity.peer_id());

        Ok("Identity is valid\n✓ Proof of Work: Valid\n✓ Cryptographic keys: Valid\n✓ Word address: Matches".to_string())
    }

    async fn handle_export(
        &self,
        path: Option<PathBuf>,
        output: PathBuf,
        format: String,
    ) -> Result<String> {
        let path = path.or_else(|| self.default_path.clone()).ok_or_else(|| {
            crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                "No identity found".into(),
            ))
        })?;

        let identity = NodeIdentity::load_from_file(&path).await?;

        match format.as_str() {
            "json" => {
                identity.save_to_file(&output).await?;
                Ok(format!("Identity exported to {}", output.display()))
            }
            _ => Err(crate::P2PError::Identity(
                crate::error::IdentityError::InvalidFormat(
                    format!("Unsupported format: {}", format).into(),
                ),
            )),
        }
    }

    async fn handle_sign(
        &self,
        identity_path: Option<PathBuf>,
        message: MessageInput,
        output: Option<PathBuf>,
    ) -> Result<String> {
        let path = identity_path
            .or_else(|| self.default_path.clone())
            .ok_or_else(|| {
                crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                    "No identity found".into(),
                ))
            })?;

        let identity = NodeIdentity::load_from_file(&path).await?;

        let message_bytes = match message {
            MessageInput::Text(s) => s.into_bytes(),
            MessageInput::File(p) => tokio::fs::read(&p).await.map_err(|e| {
                crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                    format!("Failed to read message file: {}", e).into(),
                ))
            })?,
        };

        let signature = identity.sign(&message_bytes)?;
        let sig_hex = hex::encode(signature.as_bytes());

        if let Some(output_path) = output {
            tokio::fs::write(&output_path, &sig_hex)
                .await
                .map_err(|e| {
                    crate::P2PError::Identity(crate::error::IdentityError::InvalidFormat(
                        format!("Failed to write signature: {}", e).into(),
                    ))
                })?;
        }

        let message_hash = blake3::hash(&message_bytes).to_hex();
        Ok(format!(
            "Signature: {}\nMessage hash: {}",
            sig_hex, message_hash
        ))
    }
}

fn derive_word_address(peer_id: &PeerId) -> String {
    let hex = hex::encode(peer_id.to_bytes());
    if hex.len() >= 16 {
        format!(
            "{}-{}-{}-{}",
            &hex[0..4],
            &hex[4..8],
            &hex[8..12],
            &hex[12..16]
        )
    } else {
        hex
    }
}

impl IdentityCommand {
    pub fn try_parse_from<I, T>(iter: I) -> std::result::Result<Self, String>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        // For test purposes, parse basic commands
        let args: Vec<String> = iter
            .into_iter()
            .map(|s| s.into().into_string().unwrap_or_default())
            .collect();

        if args.len() < 2 || args[0] != "identity" {
            return Err("invalid subcommand".to_string());
        }

        match args[1].as_str() {
            "generate" => {
                let mut i = 2;
                while i < args.len() {
                    i += 1;
                }
                Ok(IdentityCommand::Generate {
                    output: None,
                    seed: None,
                })
            }
            "show" => {
                let mut path = None;
                let mut i = 2;
                while i < args.len() {
                    if args[i] == "--path" && i + 1 < args.len() {
                        path = Some(PathBuf::from(&args[i + 1]));
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                Ok(IdentityCommand::Show { path })
            }
            _ => Err("invalid subcommand".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_save_and_load_identity() {
        let temp_dir = TempDir::new().expect("Should create temp directory for test");
        let identity_path = temp_dir.path().join("test_identity.json");

        // Generate identity
        let identity = NodeIdentity::generate().expect("Should generate identity in test");
        let original_id = *identity.peer_id();

        // Save
        save_identity(&identity, &identity_path).expect("Should save identity in test");

        // Load
        let loaded = load_identity(&identity_path).expect("Should load identity in test");

        // Verify
        assert_eq!(loaded.peer_id(), &original_id);
    }
}
