// src-tauri/src/security/master_key.rs
//! Master key derivation and management

use crate::security::keyring::KeyringManager;
use anyhow::{Context, Result};
use rand::RngCore;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

/// Size of the master key in bytes (256 bits)
const MASTER_KEY_SIZE: usize = 32;

/// Master key manager for handling encryption key lifecycle
pub struct MasterKeyManager {
    keyring: Arc<KeyringManager>,
    master_key_cache: Mutex<Option<[u8; MASTER_KEY_SIZE]>>,
}

impl MasterKeyManager {
    /// Create a new MasterKeyManager
    pub async fn new(keyring: Arc<KeyringManager>) -> Result<Self> {
        info!("Initializing MasterKeyManager");
        
        Ok(Self {
            keyring,
            master_key_cache: Mutex::new(None),
        })
    }
    
    /// Get the master key, creating it if it doesn't exist
    pub async fn get_or_create_master_key(&self) -> Result<[u8; MASTER_KEY_SIZE]> {
        // Check cached key first
        {
            let cache = self.master_key_cache.lock().unwrap();
            if let Some(cached_key) = *cache {
                debug!("Returning cached master key");
                return Ok(cached_key);
            }
        }
        
        // Try to load existing master key
        match self.load_master_key().await {
            Ok(key) => {
                info!("Loaded existing master key from keyring");
                {
                    let mut cache = self.master_key_cache.lock().unwrap();
                    *cache = Some(key);
                }
                Ok(key)
            }
            Err(_) => {
                info!("No existing master key found, creating new one");
                let key = self.create_master_key().await?;
                {
                    let mut cache = self.master_key_cache.lock().unwrap();
                    *cache = Some(key);
                }
                Ok(key)
            }
        }
    }
    
    /// Create a new master key and store it securely
    async fn create_master_key(&self) -> Result<[u8; MASTER_KEY_SIZE]> {
        info!("Creating new master key");
        
        // Generate a strong random master key
        let mut master_key = [0u8; MASTER_KEY_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut master_key);
        
        // Store the master key
        self.keyring.store_data("master_key", &master_key)
            .context("Failed to store master key")?;
        
        info!("Master key created and stored successfully");
        Ok(master_key)
    }
    
    /// Load the master key from secure storage
    async fn load_master_key(&self) -> Result<[u8; MASTER_KEY_SIZE]> {
        debug!("Loading master key from keyring");
        
        let master_key = self.keyring.get_data("master_key")
            .context("Master key not found in keyring")?;
        
        if master_key.len() != MASTER_KEY_SIZE {
            anyhow::bail!("Invalid master key length: expected {}, got {}", MASTER_KEY_SIZE, master_key.len());
        }
        
        let mut key_array = [0u8; MASTER_KEY_SIZE];
        key_array.copy_from_slice(&master_key);
        
        debug!("Master key loaded successfully");
        Ok(key_array)
    }
    
    /// Check if a master key exists
    pub async fn master_key_exists(&self) -> Result<bool> {
        match self.keyring.key_exists("master_key") {
            Ok(exists) => Ok(exists),
            Err(_) => Ok(false),
        }
    }
    
    /// Get information about the master key
    pub async fn get_master_key_info(&self) -> Result<MasterKeyInfo> {
        let exists = self.master_key_exists().await?;
        let cached = {
            let cache = self.master_key_cache.lock().unwrap();
            cache.is_some()
        };
        
        Ok(MasterKeyInfo {
            exists,
            cached,
            creation_time: None,
            key_size: MASTER_KEY_SIZE,
            salt_size: 16,
        })
    }
}

/// Information about the master key status
#[derive(Debug, Clone)]
pub struct MasterKeyInfo {
    pub exists: bool,
    pub cached: bool,
    pub creation_time: Option<std::time::SystemTime>,
    pub key_size: usize,
    pub salt_size: usize,
}

impl MasterKeyInfo {
    /// Get a human-readable status string
    pub fn status_string(&self) -> String {
        match (self.exists, self.cached) {
            (true, true) => "Available (cached)".to_string(),
            (true, false) => "Available (not cached)".to_string(),
            (false, _) => "Not created".to_string(),
        }
    }
}