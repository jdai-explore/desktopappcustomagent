// src-tauri/src/security/encryption.rs
//! AES-GCM encryption utilities for secure data storage
//! 
//! This module provides authenticated encryption using AES-256-GCM, ensuring both
//! confidentiality and integrity of encrypted data.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use anyhow::{Context, Result};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::fmt;
use tracing::debug;

/// Size of AES-256 key in bytes
const KEY_SIZE: usize = 32;

/// Size of AES-GCM nonce in bytes
const NONCE_SIZE: usize = 12;

/// Encrypted data container with nonce and ciphertext
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Random nonce used for this encryption
    pub nonce: [u8; NONCE_SIZE],
    /// Encrypted data with authentication tag
    pub ciphertext: Vec<u8>,
    /// Version of encryption scheme (for future upgrades)
    pub version: u8,
}

impl EncryptedData {
    /// Create new EncryptedData from components
    pub fn new(nonce: [u8; NONCE_SIZE], ciphertext: Vec<u8>) -> Self {
        Self {
            nonce,
            ciphertext,
            version: 1, // Current version
        }
    }
    
    /// Serialize to bytes for storage
    pub fn to_bytes(&self) -> Vec<u8> {
        // Format: [version:1][nonce:12][ciphertext_len:4][ciphertext:N]
        let mut result = Vec::with_capacity(1 + NONCE_SIZE + 4 + self.ciphertext.len());
        
        result.push(self.version);
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&(self.ciphertext.len() as u32).to_le_bytes());
        result.extend_from_slice(&self.ciphertext);
        
        result
    }
    
    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.len() < 1 + NONCE_SIZE + 4 {
            anyhow::bail!("Encrypted data too short");
        }
        
        let version = data[0];
        if version != 1 {
            anyhow::bail!("Unsupported encryption version: {}", version);
        }
        
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&data[1..1 + NONCE_SIZE]);
        
        let ciphertext_len_bytes = &data[1 + NONCE_SIZE..1 + NONCE_SIZE + 4];
        let ciphertext_len = u32::from_le_bytes([
            ciphertext_len_bytes[0],
            ciphertext_len_bytes[1], 
            ciphertext_len_bytes[2],
            ciphertext_len_bytes[3],
        ]) as usize;
        
        let ciphertext_start = 1 + NONCE_SIZE + 4;
        if data.len() < ciphertext_start + ciphertext_len {
            anyhow::bail!("Encrypted data truncated");
        }
        
        let ciphertext = data[ciphertext_start..ciphertext_start + ciphertext_len].to_vec();
        
        Ok(Self {
            version,
            nonce,
            ciphertext,
        })
    }
}

impl fmt::Display for EncryptedData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EncryptedData(v{}, {} bytes)", self.version, self.ciphertext.len())
    }
}

/// AES-256-GCM encryption manager
pub struct EncryptionManager {
    cipher: Aes256Gcm,
}

impl EncryptionManager {
    /// Create a new EncryptionManager with the given master key
    /// 
    /// # Arguments
    /// * `master_key` - 32-byte master key for encryption
    /// 
    /// # Returns
    /// * `Ok(EncryptionManager)` if initialization succeeds
    /// * `Err(anyhow::Error)` if the key is invalid
    pub fn new(master_key: [u8; KEY_SIZE]) -> Result<Self> {
        let key = Key::<Aes256Gcm>::from_slice(&master_key);
        let cipher = Aes256Gcm::new(key);
        
        debug!("EncryptionManager initialized with AES-256-GCM");
        
        Ok(Self { cipher })
    }
    
    /// Encrypt data using AES-256-GCM
    /// 
    /// # Arguments
    /// * `plaintext` - The data to encrypt
    /// 
    /// # Returns
    /// * `Ok(EncryptedData)` containing the encrypted data and nonce
    /// * `Err(anyhow::Error)` if encryption fails
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<EncryptedData> {
        if plaintext.is_empty() {
            anyhow::bail!("Cannot encrypt empty data");
        }
        
        // Generate random nonce
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let nonce_array: [u8; NONCE_SIZE] = nonce.as_slice().try_into()
            .context("Failed to convert nonce to array")?;
        
        // Encrypt with authentication
        let ciphertext = self.cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
        
        debug!("Encrypted {} bytes of data", plaintext.len());
        
        Ok(EncryptedData::new(nonce_array, ciphertext))
    }
    
    /// Decrypt data using AES-256-GCM
    /// 
    /// # Arguments
    /// * `encrypted_data` - The encrypted data to decrypt
    /// 
    /// # Returns
    /// * `Ok(Vec<u8>)` containing the decrypted data
    /// * `Err(anyhow::Error)` if decryption fails or authentication fails
    pub fn decrypt(&self, encrypted_data: &EncryptedData) -> Result<Vec<u8>> {
        if encrypted_data.ciphertext.is_empty() {
            anyhow::bail!("Cannot decrypt empty ciphertext");
        }
        
        let nonce = Nonce::from_slice(&encrypted_data.nonce);
        
        // Decrypt and verify authentication
        let plaintext = self.cipher
            .decrypt(nonce, encrypted_data.ciphertext.as_slice())
            .map_err(|e| anyhow::anyhow!("Decryption failed (possibly tampered data): {}", e))?;
        
        debug!("Decrypted {} bytes of data", plaintext.len());
        
        Ok(plaintext)
    }
    
    /// Encrypt a string and return the encrypted data
    /// 
    /// # Arguments
    /// * `text` - The string to encrypt
    /// 
    /// # Returns
    /// * `Ok(EncryptedData)` containing the encrypted string
    /// * `Err(anyhow::Error)` if encryption fails
    pub fn encrypt_string(&self, text: &str) -> Result<EncryptedData> {
        self.encrypt(text.as_bytes())
    }
    
    /// Decrypt data and return as a UTF-8 string
    /// 
    /// # Arguments
    /// * `encrypted_data` - The encrypted data to decrypt
    /// 
    /// # Returns
    /// * `Ok(String)` containing the decrypted string
    /// * `Err(anyhow::Error)` if decryption fails or data is not valid UTF-8
    pub fn decrypt_string(&self, encrypted_data: &EncryptedData) -> Result<String> {
        let plaintext = self.decrypt(encrypted_data)?;
        String::from_utf8(plaintext)
            .context("Decrypted data is not valid UTF-8")
    }
    
    /// Generate a random encryption key
    /// 
    /// # Returns
    /// A new 32-byte random key suitable for AES-256
    pub fn generate_key() -> [u8; KEY_SIZE] {
        let mut key = [0u8; KEY_SIZE];
        OsRng.fill_bytes(&mut key);
        key
    }
    
    /// Test encryption and decryption functionality
    /// 
    /// # Returns
    /// * `Ok(())` if encryption/decryption works correctly
    /// * `Err(anyhow::Error)` if any test fails
    pub fn test_functionality(&self) -> Result<()> {
        debug!("Testing encryption functionality");
        
        // Test with various data sizes
        let test_cases = vec![
            b"Hello, World!".to_vec(),
            b"A".to_vec(),
            vec![0u8; 1000],  // 1KB of zeros
            (0..255).collect::<Vec<u8>>(),  // All byte values
        ];
        
        for (i, test_data) in test_cases.iter().enumerate() {
            // Test encryption
            let encrypted = self.encrypt(test_data)
                .with_context(|| format!("Failed to encrypt test case {}", i))?;
            
            // Verify nonce is different each time
            let encrypted2 = self.encrypt(test_data)
                .with_context(|| format!("Failed to encrypt test case {} (second time)", i))?;
            
            if encrypted.nonce == encrypted2.nonce {
                anyhow::bail!("Nonce reuse detected in test case {}", i);
            }
            
            // Test decryption
            let decrypted = self.decrypt(&encrypted)
                .with_context(|| format!("Failed to decrypt test case {}", i))?;
            
            if decrypted != *test_data {
                anyhow::bail!("Decrypted data doesn't match original in test case {}", i);
            }
            
            // Test serialization/deserialization
            let serialized = encrypted.to_bytes();
            let deserialized = EncryptedData::from_bytes(&serialized)
                .with_context(|| format!("Failed to deserialize test case {}", i))?;
            
            let decrypted2 = self.decrypt(&deserialized)
                .with_context(|| format!("Failed to decrypt deserialized test case {}", i))?;
            
            if decrypted2 != *test_data {
                anyhow::bail!("Deserialized data doesn't match original in test case {}", i);
            }
        }
        
        // Test string encryption
        let test_string = "Hello, 世界! 🌍";
        let encrypted_string = self.encrypt_string(test_string)?;
        let decrypted_string = self.decrypt_string(&encrypted_string)?;
        
        if decrypted_string != test_string {
            anyhow::bail!("String encryption test failed");
        }
        
        // Test tampering detection
        let test_data = b"Tamper test";
        let mut encrypted = self.encrypt(test_data)?;
        
        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            encrypted.ciphertext[0] ^= 1;
            
            // This should fail
            if self.decrypt(&encrypted).is_ok() {
                anyhow::bail!("Tampering detection failed - decryption should have failed");
            }
        }
        
        debug!("Encryption functionality test passed");
        Ok(())
    }
    
    /// Get information about the encryption scheme
    /// 
    /// # Returns
    /// A string describing the encryption method
    pub fn get_info(&self) -> String {
        "AES-256-GCM with random nonces".to_string()
    }
}

/// Securely zero out memory containing sensitive data
pub fn secure_zero(data: &mut [u8]) {
    // Use volatile write to prevent compiler optimization
    for byte in data.iter_mut() {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}

/// Generate cryptographically secure random bytes
/// 
/// # Arguments
/// * `size` - Number of random bytes to generate
/// 
/// # Returns
/// A vector containing the requested number of random bytes
pub fn generate_random_bytes(size: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; size];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypted_data_serialization() {
        let nonce = [1u8; NONCE_SIZE];
        let ciphertext = vec![1, 2, 3, 4, 5];
        let encrypted = EncryptedData::new(nonce, ciphertext.clone());
        
        let serialized = encrypted.to_bytes();
        let deserialized = EncryptedData::from_bytes(&serialized).unwrap();
        
        assert_eq!(deserialized.version, encrypted.version);
        assert_eq!(deserialized.nonce, encrypted.nonce);
        assert_eq!(deserialized.ciphertext, encrypted.ciphertext);
    }
    
    #[test]
    fn test_encryption_manager() {
        let key = EncryptionManager::generate_key();
        let manager = EncryptionManager::new(key).unwrap();
        
        let plaintext = b"Hello, World!";
        let encrypted = manager.encrypt(plaintext).unwrap();
        let decrypted = manager.decrypt(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted.as_slice());
    }
    
    #[test]
    fn test_string_encryption() {
        let key = EncryptionManager::generate_key();
        let manager = EncryptionManager::new(key).unwrap();
        
        let text = "Hello, 世界! 🌍";
        let encrypted = manager.encrypt_string(text).unwrap();
        let decrypted = manager.decrypt_string(&encrypted).unwrap();
        
        assert_eq!(text, decrypted);
    }
}