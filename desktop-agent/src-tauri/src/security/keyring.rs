// src-tauri/src/security/keyring.rs
//! OS keyring integration for secure credential storage
//! 
//! This module provides cross-platform secure storage using the operating system's
//! native keyring/keychain services (Windows Credential Manager, macOS Keychain, Linux Secret Service).

use anyhow::{Context, Result};
use keyring::{Entry, Error as KeyringError};
use tracing::{debug, info, warn};

/// Manages secure storage operations with the OS keyring
pub struct KeyringManager {
    service_name: String,
    app_prefix: String,
}

impl KeyringManager {
    /// Create a new KeyringManager
    /// 
    /// # Arguments
    /// * `app_id` - Unique application identifier (e.g., "com.desktop-agent.app")
    /// 
    /// # Returns
    /// * `Ok(KeyringManager)` if initialization succeeds
    /// * `Err(anyhow::Error)` if keyring is not available
    pub fn new(app_id: &str) -> Result<Self> {
        info!("Initializing KeyringManager for app: {}", app_id);
        
        let service_name = format!("{}.credentials", app_id);
        let app_prefix = format!("{}_", app_id.replace(".", "_"));
        
        // Test keyring availability by trying to access it
        let _test_entry = Entry::new(&service_name, "test_availability")?;
        debug!("Keyring service available");
        
        Ok(Self {
            service_name,
            app_prefix,
        })
    }
    
    /// Store data securely in the keyring
    /// 
    /// # Arguments
    /// * `key` - Unique identifier for the data
    /// * `data` - The data to store (as bytes)
    /// 
    /// # Returns
    /// * `Ok(())` if storage succeeds
    /// * `Err(anyhow::Error)` if storage fails
    pub fn store_data(&self, key: &str, data: &[u8]) -> Result<()> {
        if key.trim().is_empty() {
            anyhow::bail!("Key cannot be empty");
        }
        
        let full_key = self.make_full_key(key);
        debug!("Storing data for key: {}", key);
        
        let entry = Entry::new(&self.service_name, &full_key)
            .with_context(|| format!("Failed to create keyring entry for key: {}", key))?;
        
        // Convert bytes to base64 for storage (keyring stores strings)
        let encoded_data = base64::encode(data);
        
        entry.set_password(&encoded_data)
            .with_context(|| format!("Failed to store data for key: {}", key))?;
        
        debug!("Data stored successfully for key: {}", key);
        Ok(())
    }
    
    /// Retrieve data from the keyring
    /// 
    /// # Arguments
    /// * `key` - Unique identifier for the data
    /// 
    /// # Returns
    /// * `Ok(Vec<u8>)` with the retrieved data
    /// * `Err(anyhow::Error)` if retrieval fails or key doesn't exist
    pub fn get_data(&self, key: &str) -> Result<Vec<u8>> {
        if key.trim().is_empty() {
            anyhow::bail!("Key cannot be empty");
        }
        
        let full_key = self.make_full_key(key);
        debug!("Retrieving data for key: {}", key);
        
        let entry = Entry::new(&self.service_name, &full_key)
            .with_context(|| format!("Failed to create keyring entry for key: {}", key))?;
        
        let encoded_data = entry.get_password()
            .map_err(|e| match e {
                KeyringError::NoEntry => anyhow::anyhow!("Key not found: {}", key),
                _ => anyhow::anyhow!("Failed to retrieve data for key {}: {}", key, e),
            })?;
        
        // Decode from base64
        let data = base64::decode(&encoded_data)
            .with_context(|| format!("Failed to decode data for key: {}", key))?;
        
        debug!("Data retrieved successfully for key: {}", key);
        Ok(data)
    }
    
    /// Delete data from the keyring
    /// 
    /// # Arguments
    /// * `key` - Unique identifier for the data to delete
    /// 
    /// # Returns
    /// * `Ok(())` if deletion succeeds or key doesn't exist
    /// * `Err(anyhow::Error)` if deletion fails
    pub fn delete_data(&self, key: &str) -> Result<()> {
        if key.trim().is_empty() {
            anyhow::bail!("Key cannot be empty");
        }
        
        let full_key = self.make_full_key(key);
        debug!("Deleting data for key: {}", key);
        
        let entry = Entry::new(&self.service_name, &full_key)
            .with_context(|| format!("Failed to create keyring entry for key: {}", key))?;
        
        match entry.delete_password() {
            Ok(()) => {
                debug!("Data deleted successfully for key: {}", key);
                Ok(())
            }
            Err(KeyringError::NoEntry) => {
                debug!("Key not found (already deleted): {}", key);
                Ok(())  // Treat as success - idempotent operation
            }
            Err(e) => {
                anyhow::bail!("Failed to delete data for key {}: {}", key, e);
            }
        }
    }
    
    /// Check if a key exists in the keyring
    /// 
    /// # Arguments
    /// * `key` - Unique identifier to check
    /// 
    /// # Returns
    /// * `Ok(true)` if the key exists
    /// * `Ok(false)` if the key doesn't exist
    /// * `Err(anyhow::Error)` if the check fails
    pub fn key_exists(&self, key: &str) -> Result<bool> {
        if key.trim().is_empty() {
            anyhow::bail!("Key cannot be empty");
        }
        
        let full_key = self.make_full_key(key);
        let entry = Entry::new(&self.service_name, &full_key)
            .with_context(|| format!("Failed to create keyring entry for key: {}", key))?;
        
        match entry.get_password() {
            Ok(_) => Ok(true),
            Err(KeyringError::NoEntry) => Ok(false),
            Err(e) => anyhow::bail!("Failed to check existence of key {}: {}", key, e),
        }
    }
    
    /// List all keys stored by this application
    /// 
    /// Note: This is a best-effort implementation. Some keyring backends
    /// don't support enumeration, so this may return an empty list even
    /// if keys exist.
    /// 
    /// # Returns
    /// * `Ok(Vec<String>)` with the list of keys (without app prefix)
    /// * `Err(anyhow::Error)` if listing fails
    pub fn list_keys(&self) -> Result<Vec<String>> {
        debug!("Attempting to list all keys for service: {}", self.service_name);
        
        // Note: The keyring crate doesn't provide a built-in way to enumerate keys.
        // This is a limitation of some keyring backends (e.g., Windows Credential Manager).
        // 
        // For now, we'll return an empty list and log a warning.
        // In the future, we could maintain a separate index of keys.
        
        warn!("Key enumeration is not supported by the keyring backend");
        warn!("Consider maintaining an application-level index of stored keys");
        
        // Return empty list for now
        // TODO: Implement application-level key tracking
        Ok(Vec::new())
    }
    
    /// Clear all data stored by this application
    /// 
    /// # Returns
    /// * `Ok(u32)` with the number of keys deleted
    /// * `Err(anyhow::Error)` if clearing fails
    pub fn clear_all(&self) -> Result<u32> {
        warn!("Clearing all keyring data for service: {}", self.service_name);
        
        // Since we can't enumerate keys reliably, we'll attempt to delete
        // known key patterns. This is not ideal, but it's a limitation
        // of the keyring backend.
        
        let common_keys = vec![
            "master_key",
            "api_key_gemini",
            "api_key_openai", 
            "api_key_anthropic",
            "api_key_cohere",
        ];
        
        let mut deleted_count = 0;
        
        for key in common_keys {
            match self.delete_data(key) {
                Ok(()) => {
                    deleted_count += 1;
                    debug!("Deleted key: {}", key);
                }
                Err(e) => {
                    debug!("Failed to delete key {} (might not exist): {}", key, e);
                }
            }
        }
        
        info!("Cleared {} keys from keyring", deleted_count);
        Ok(deleted_count)
    }
    
    /// Get information about the keyring backend
    /// 
    /// # Returns
    /// Information about the keyring system being used
    pub fn get_backend_info(&self) -> String {
        #[cfg(target_os = "windows")]
        return "Windows Credential Manager".to_string();
        
        #[cfg(target_os = "macos")]
        return "macOS Keychain".to_string();
        
        #[cfg(target_os = "linux")]
        return "Linux Secret Service (libsecret)".to_string();
        
        #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
        return "Unknown keyring backend".to_string();
    }
    
    /// Test keyring functionality
    /// 
    /// # Returns
    /// * `Ok(())` if all keyring operations work correctly
    /// * `Err(anyhow::Error)` if any operation fails
    pub fn test_functionality(&self) -> Result<()> {
        debug!("Testing keyring functionality");
        
        let test_key = "test_functionality";
        let test_data = b"Hello, Keyring!";
        
        // Test store
        self.store_data(test_key, test_data)
            .context("Failed to store test data")?;
        
        // Test retrieve
        let retrieved_data = self.get_data(test_key)
            .context("Failed to retrieve test data")?;
        
        if retrieved_data != test_data {
            anyhow::bail!("Retrieved data doesn't match stored data");
        }
        
        // Test existence check
        if !self.key_exists(test_key)? {
            anyhow::bail!("Key existence check failed");
        }
        
        // Test delete
        self.delete_data(test_key)
            .context("Failed to delete test data")?;
        
        // Verify deletion
        if self.key_exists(test_key)? {
            anyhow::bail!("Key still exists after deletion");
        }
        
        info!("Keyring functionality test passed");
        Ok(())
    }
    
    /// Create the full key name with app prefix
    fn make_full_key(&self, key: &str) -> String {
        format!("{}{}", self.app_prefix, key)
    }
}

// Add base64 encoding/decoding functionality
mod base64 {
    use anyhow::Result;
    
    /// Encode bytes to base64 string
    pub fn encode(data: &[u8]) -> String {
        
        const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        
        let mut result = String::new();
        let mut i = 0;
        
        while i < data.len() {
            let b1 = data[i];
            let b2 = if i + 1 < data.len() { data[i + 1] } else { 0 };
            let b3 = if i + 2 < data.len() { data[i + 2] } else { 0 };
            
            let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
            
            result.push(CHARS[((n >> 18) & 63) as usize] as char);
            result.push(CHARS[((n >> 12) & 63) as usize] as char);
            result.push(if i + 1 < data.len() { CHARS[((n >> 6) & 63) as usize] as char } else { '=' });
            result.push(if i + 2 < data.len() { CHARS[(n & 63) as usize] as char } else { '=' });
            
            i += 3;
        }
        
        result
    }
    
    /// Decode base64 string to bytes
    pub fn decode(encoded: &str) -> Result<Vec<u8>> {
        let encoded = encoded.trim();
        if encoded.is_empty() {
            return Ok(Vec::new());
        }
        
        // Simple base64 decoder
        let mut result = Vec::new();
        let chars: Vec<u8> = encoded.bytes().collect();
        
        if chars.len() % 4 != 0 {
            anyhow::bail!("Invalid base64 length");
        }
        
        let mut i = 0;
        while i < chars.len() {
            let c1 = decode_char(chars[i])?;
            let c2 = decode_char(chars[i + 1])?;
            let c3 = if chars[i + 2] == b'=' { 0 } else { decode_char(chars[i + 2])? };
            let c4 = if chars[i + 3] == b'=' { 0 } else { decode_char(chars[i + 3])? };
            
            let n = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;
            
            result.push((n >> 16) as u8);
            if chars[i + 2] != b'=' {
                result.push((n >> 8) as u8);
            }
            if chars[i + 3] != b'=' {
                result.push(n as u8);
            }
            
            i += 4;
        }
        
        Ok(result)
    }
    
    fn decode_char(c: u8) -> Result<u32> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'+' => Ok(62),
            b'/' => Ok(63),
            b'=' => Ok(0),
            _ => anyhow::bail!("Invalid base64 character: {}", c as char),
        }
    }
}