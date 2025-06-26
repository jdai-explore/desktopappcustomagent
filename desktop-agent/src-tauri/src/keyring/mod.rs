use keyring::Entry;

use crate::error::{AppError, Result};

const SERVICE_NAME: &str = "desktop-agent";
const MASTER_KEY_NAME: &str = "master-encryption-key";

pub struct KeyringManager;

impl KeyringManager {
    /// Store master key data in OS keyring
    pub fn store_master_key(key_data: &str) -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, MASTER_KEY_NAME)
            .map_err(|e| AppError::Keyring(format!("Failed to create keyring entry: {}", e)))?;
        
        entry
            .set_password(key_data)
            .map_err(|e| AppError::Keyring(format!("Failed to store master key: {}", e)))?;
        
        tracing::info!("Master key stored successfully in OS keyring");
        Ok(())
    }
    
    /// Retrieve master key data from OS keyring
    pub fn get_master_key() -> Result<String> {
        let entry = Entry::new(SERVICE_NAME, MASTER_KEY_NAME)
            .map_err(|e| AppError::Keyring(format!("Failed to access keyring: {}", e)))?;
        
        let key_data = entry
            .get_password()
            .map_err(|e| AppError::Keyring(format!("Failed to retrieve master key: {}", e)))?;
        
        Ok(key_data)
    }
    
    /// Delete master key from OS keyring
    pub fn delete_master_key() -> Result<()> {
        let entry = Entry::new(SERVICE_NAME, MASTER_KEY_NAME)
            .map_err(|e| AppError::Keyring(format!("Failed to access keyring: {}", e)))?;
        
        entry
            .delete_password()
            .map_err(|e| AppError::Keyring(format!("Failed to delete master key: {}", e)))?;
        
        tracing::info!("Master key deleted from OS keyring");
        Ok(())
    }
    
    /// Check if master key exists in OS keyring
    pub fn master_key_exists() -> bool {
        match Entry::new(SERVICE_NAME, MASTER_KEY_NAME) {
            Ok(entry) => entry.get_password().is_ok(),
            Err(_) => false,
        }
    }
    
    /// Store API key for a provider
    pub fn store_api_key(provider: &str, key_name: &str, api_key: &str) -> Result<()> {
        let entry_name = format!("api_{}_{}", provider, key_name);
        let entry = Entry::new(SERVICE_NAME, &entry_name)
            .map_err(|e| AppError::Keyring(format!("Failed to create keyring entry: {}", e)))?;
        
        entry
            .set_password(api_key)
            .map_err(|e| AppError::Keyring(format!("Failed to store API key: {}", e)))?;
        
        tracing::info!("API key stored for provider: {}", provider);
        Ok(())
    }
    
    /// Retrieve API key for a provider
    pub fn get_api_key(provider: &str, key_name: &str) -> Result<String> {
        let entry_name = format!("api_{}_{}", provider, key_name);
        let entry = Entry::new(SERVICE_NAME, &entry_name)
            .map_err(|e| AppError::Keyring(format!("Failed to access keyring: {}", e)))?;
        
        let api_key = entry
            .get_password()
            .map_err(|e| AppError::Keyring(format!("Failed to retrieve API key: {}", e)))?;
        
        Ok(api_key)
    }
    
    /// Delete API key for a provider
    pub fn delete_api_key(provider: &str, key_name: &str) -> Result<()> {
        let entry_name = format!("api_{}_{}", provider, key_name);
        let entry = Entry::new(SERVICE_NAME, &entry_name)
            .map_err(|e| AppError::Keyring(format!("Failed to access keyring: {}", e)))?;
        
        entry
            .delete_password()
            .map_err(|e| AppError::Keyring(format!("Failed to delete API key: {}", e)))?;
        
        tracing::info!("API key deleted for provider: {}", provider);
        Ok(())
    }
    
    /// List all stored API keys (returns provider and key name pairs)
    pub fn list_api_keys() -> Result<Vec<(String, String)>> {
        // Note: This is a simplified implementation
        // In practice, you might need to store metadata separately
        // or use a different approach based on the keyring implementation
        
        tracing::warn!("Listing API keys not fully implemented");
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_keyring_operations() {
        // Note: These tests will interact with the actual OS keyring
        // Should be run with caution and cleaned up after
        
        let test_key = "test_key_data_12345";
        
        // Store key
        assert!(KeyringManager::store_master_key(test_key).is_ok());
        
        // Check existence
        assert!(KeyringManager::master_key_exists());
        
        // Retrieve key
        let retrieved = KeyringManager::get_master_key().unwrap();
        assert_eq!(retrieved, test_key);
        
        // Delete key
        assert!(KeyringManager::delete_master_key().is_ok());
        
        // Check non-existence
        assert!(!KeyringManager::master_key_exists());
    }
}