// src-tauri/src/security/mod.rs
//! Security module providing encryption, keyring management, and secure storage
//! 
//! This module implements the security foundation for the Desktop Agent application,
//! ensuring all sensitive data (API keys, user data) is properly encrypted and protected.

pub mod encryption;
pub mod keyring;
pub mod master_key;

use anyhow::Result;
use std::sync::Arc;
use tracing::{debug, info};
use uuid::Uuid;

pub use encryption::{EncryptionManager, EncryptedData};
pub use keyring::KeyringManager;
pub use master_key::MasterKeyManager;

/// Errors that can occur in the security module
#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("Keyring operation failed: {0}")]
    Keyring(String),
    
    #[error("Encryption operation failed: {0}")]
    Encryption(String),
    
    #[error("Master key operation failed: {0}")]
    MasterKey(String),
    
    #[error("Invalid data format: {0}")]
    InvalidFormat(String),
    
    #[error("Authentication failed: {0}")]
    Authentication(String),
}

/// Result type for security operations
pub type SecurityResult<T> = Result<T, SecurityError>;

/// Main security manager that coordinates all security operations
#[derive(Clone)]
pub struct SecurityManager {
    encryption: Arc<EncryptionManager>,
    keyring: Arc<KeyringManager>,
    pub master_key: Arc<MasterKeyManager>,  // Make this public for access
    app_id: String,
}

impl SecurityManager {
    /// Create a new SecurityManager instance
    /// 
    /// This initializes all security components and ensures the master key is available
    pub async fn new() -> Result<Self> {
        info!("Initializing SecurityManager...");
        
        let app_id = "com.desktop-agent.app".to_string();
        
        // Initialize keyring manager
        let keyring = Arc::new(KeyringManager::new(&app_id)?);
        debug!("Keyring manager initialized");
        
        // Initialize master key manager
        let master_key_manager = Arc::new(MasterKeyManager::new(keyring.clone()).await?);
        debug!("Master key manager initialized");
        
        // Get or create master key
        let master_key = master_key_manager.get_or_create_master_key().await?;
        debug!("Master key available");
        
        // Initialize encryption manager with master key
        let encryption = Arc::new(EncryptionManager::new(master_key)?);
        debug!("Encryption manager initialized");
        
        info!("SecurityManager initialized successfully");
        
        Ok(Self {
            encryption,
            keyring,
            master_key: master_key_manager,
            app_id,
        })
    }
    
    /// Store an API key securely for a given provider
    /// 
    /// # Arguments
    /// * `provider` - The provider name (e.g., "gemini", "openai")
    /// * `api_key` - The API key to store
    /// 
    /// # Returns
    /// * `Ok(())` if the key was stored successfully
    /// * `Err(SecurityError)` if storage failed
    pub async fn store_api_key(&self, provider: &str, api_key: &str) -> SecurityResult<()> {
        if provider.trim().is_empty() {
            return Err(SecurityError::InvalidFormat("Provider name cannot be empty".to_string()));
        }
        
        if api_key.trim().is_empty() {
            return Err(SecurityError::InvalidFormat("API key cannot be empty".to_string()));
        }
        
        debug!("Storing API key for provider: {}", provider);
        
        // Encrypt the API key
        let encrypted_key = self.encryption.encrypt(api_key.as_bytes())
            .map_err(|e| SecurityError::Encryption(e.to_string()))?;
        
        // Create storage key
        let storage_key = format!("api_key_{}", provider);
        
        // Store encrypted key in keyring
        self.keyring.store_data(&storage_key, &encrypted_key.to_bytes())
            .map_err(|e| SecurityError::Keyring(e.to_string()))?;
        
        info!("API key stored successfully for provider: {}", provider);
        Ok(())
    }
    
    /// Retrieve an API key for a given provider
    /// 
    /// # Arguments
    /// * `provider` - The provider name
    /// 
    /// # Returns
    /// * `Ok(Some(api_key))` if the key exists and was decrypted successfully
    /// * `Ok(None)` if no key exists for this provider
    /// * `Err(SecurityError)` if retrieval or decryption failed
    pub async fn get_api_key(&self, provider: &str) -> SecurityResult<Option<String>> {
        if provider.trim().is_empty() {
            return Err(SecurityError::InvalidFormat("Provider name cannot be empty".to_string()));
        }
        
        debug!("Retrieving API key for provider: {}", provider);
        
        let storage_key = format!("api_key_{}", provider);
        
        // Get encrypted data from keyring
        let encrypted_bytes = match self.keyring.get_data(&storage_key) {
            Ok(data) => data,
            Err(e) => {
                if e.to_string().contains("not found") {
                    debug!("No API key found for provider: {}", provider);
                    return Ok(None);
                }
                return Err(SecurityError::Keyring(e.to_string()));
            }
        };
        
        // Parse encrypted data
        let encrypted_data = EncryptedData::from_bytes(&encrypted_bytes)
            .map_err(|e| SecurityError::InvalidFormat(e.to_string()))?;
        
        // Decrypt the API key
        let decrypted_bytes = self.encryption.decrypt(&encrypted_data)
            .map_err(|e| SecurityError::Encryption(e.to_string()))?;
        
        let api_key = String::from_utf8(decrypted_bytes)
            .map_err(|e| SecurityError::InvalidFormat(format!("Invalid UTF-8 in API key: {}", e)))?;
        
        debug!("API key retrieved successfully for provider: {}", provider);
        Ok(Some(api_key))
    }
    
    /// Delete an API key for a given provider
    /// 
    /// # Arguments
    /// * `provider` - The provider name
    /// 
    /// # Returns
    /// * `Ok(true)` if the key was deleted
    /// * `Ok(false)` if no key existed for this provider
    /// * `Err(SecurityError)` if deletion failed
    pub async fn delete_api_key(&self, provider: &str) -> SecurityResult<bool> {
        if provider.trim().is_empty() {
            return Err(SecurityError::InvalidFormat("Provider name cannot be empty".to_string()));
        }
        
        debug!("Deleting API key for provider: {}", provider);
        
        let storage_key = format!("api_key_{}", provider);
        
        match self.keyring.delete_data(&storage_key) {
            Ok(()) => {
                info!("API key deleted successfully for provider: {}", provider);
                Ok(true)
            }
            Err(e) => {
                if e.to_string().contains("not found") {
                    debug!("No API key found to delete for provider: {}", provider);
                    Ok(false)
                } else {
                    Err(SecurityError::Keyring(e.to_string()))
                }
            }
        }
    }
    
    /// List all providers that have API keys stored
    /// 
    /// # Returns
    /// * `Ok(Vec<String>)` with provider names
    /// * `Err(SecurityError)` if listing failed
    pub async fn list_configured_providers(&self) -> SecurityResult<Vec<String>> {
        debug!("Listing configured providers");
        
        let keys = self.keyring.list_keys()
            .map_err(|e| SecurityError::Keyring(e.to_string()))?;
        
        let providers: Vec<String> = keys
            .iter()
            .filter_map(|key| {
                if key.starts_with("api_key_") {
                    Some(key.trim_start_matches("api_key_").to_string())
                } else {
                    None
                }
            })
            .collect();
        
        debug!("Found {} configured providers", providers.len());
        Ok(providers)
    }
    
    /// Encrypt arbitrary data using the master key
    /// 
    /// # Arguments
    /// * `data` - The data to encrypt
    /// 
    /// # Returns
    /// * `Ok(EncryptedData)` with the encrypted data
    /// * `Err(SecurityError)` if encryption failed
    pub fn encrypt_data(&self, data: &[u8]) -> SecurityResult<EncryptedData> {
        self.encryption.encrypt(data)
            .map_err(|e| SecurityError::Encryption(e.to_string()))
    }
    
    /// Decrypt arbitrary data using the master key
    /// 
    /// # Arguments
    /// * `encrypted_data` - The encrypted data to decrypt
    /// 
    /// # Returns
    /// * `Ok(Vec<u8>)` with the decrypted data
    /// * `Err(SecurityError)` if decryption failed
    pub fn decrypt_data(&self, encrypted_data: &EncryptedData) -> SecurityResult<Vec<u8>> {
        self.encryption.decrypt(encrypted_data)
            .map_err(|e| SecurityError::Encryption(e.to_string()))
    }
    
    /// Generate a secure random identifier
    /// 
    /// # Returns
    /// A new UUID v4 as a string
    pub fn generate_id(&self) -> String {
        Uuid::new_v4().to_string()
    }
    
    /// Test the security system to ensure all components are working
    /// 
    /// # Returns
    /// * `Ok(())` if all tests pass
    /// * `Err(SecurityError)` if any test fails
    pub async fn health_check(&self) -> SecurityResult<()> {
        debug!("Running security system health check");
        
        // Test encryption/decryption
        let test_data = b"Hello, World!";
        let encrypted = self.encrypt_data(test_data)?;
        let decrypted = self.decrypt_data(&encrypted)?;
        
        if decrypted != test_data {
            return Err(SecurityError::Encryption("Health check failed: decrypted data doesn't match original".to_string()));
        }
        
        // Test keyring operations
        let test_key = format!("health_check_{}", Uuid::new_v4());
        let test_value = b"test_value";
        
        self.keyring.store_data(&test_key, test_value)
            .map_err(|e| SecurityError::Keyring(format!("Health check failed during store: {}", e)))?;
        
        let retrieved = self.keyring.get_data(&test_key)
            .map_err(|e| SecurityError::Keyring(format!("Health check failed during retrieve: {}", e)))?;
        
        if retrieved != test_value {
            return Err(SecurityError::Keyring("Health check failed: retrieved data doesn't match stored data".to_string()));
        }
        
        self.keyring.delete_data(&test_key)
            .map_err(|e| SecurityError::Keyring(format!("Health check failed during cleanup: {}", e)))?;
        
        info!("Security system health check passed");
        Ok(())
    }
}

// Ensure SecurityManager is thread-safe
unsafe impl Send for SecurityManager {}
unsafe impl Sync for SecurityManager {}