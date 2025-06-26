use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use std::sync::Arc;

use crate::error::{AppError, Result};
use crate::keyring::KeyringManager;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 32;

#[derive(Clone)]
pub struct EncryptionManager {
    key: Arc<Key<Aes256Gcm>>,
    salt: Vec<u8>,
}

impl EncryptionManager {
    /// Initialize a new encryption manager with a password
    pub async fn initialize(password: &str) -> Result<Self> {
        // Check if master key already exists
        if KeyringManager::master_key_exists() {
            return Err(AppError::Configuration(
                "Master key already exists. Use unlock instead.".to_string(),
            ));
        }
        
        // Generate salt
        let mut salt = vec![0u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        
        // Derive key from password
        let key = Self::derive_key(password, &salt)?;
        
        // Store master key data in keyring
        let master_data = MasterKeyData { salt: salt.clone() };
        KeyringManager::store_master_key(&master_data.to_string())?;
        
        Ok(Self {
            key: Arc::new(key),
            salt,
        })
    }
    
    /// Unlock existing encryption manager with password
    pub async fn unlock(password: &str) -> Result<Self> {
        // Retrieve master key data from keyring
        let master_data = KeyringManager::get_master_key()?;
        let master_data: MasterKeyData = master_data.parse()?;
        
        // Derive key from password and stored salt
        let key = Self::derive_key(password, &master_data.salt)?;
        
        // Verify the password by trying to decrypt a test value if stored
        // (In production, you'd store an encrypted test value to verify)
        
        Ok(Self {
            key: Arc::new(key),
            salt: master_data.salt,
        })
    }
    
    /// Derive encryption key from password and salt
    fn derive_key(password: &str, salt: &[u8]) -> Result<Key<Aes256Gcm>> {
        let argon2 = Argon2::default();
        let mut key_bytes = [0u8; KEY_SIZE];
        
        // Using Argon2id for key derivation
        argon2
            .hash_password_into(password.as_bytes(), salt, &mut key_bytes)
            .map_err(|e| AppError::Encryption(format!("Key derivation failed: {}", e)))?;
        
        Ok(Key::<Aes256Gcm>::from_slice(&key_bytes).clone())
    }
    
    /// Encrypt data
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(&self.key);
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| AppError::Encryption(format!("Encryption failed: {}", e)))?;
        
        // Combine nonce and ciphertext
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        
        Ok(result)
    }
    
    /// Decrypt data
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE {
            return Err(AppError::Encryption("Invalid ciphertext".to_string()));
        }
        
        // Extract nonce and ciphertext
        let (nonce_bytes, actual_ciphertext) = ciphertext.split_at(NONCE_SIZE);
        let nonce = Nonce::from_slice(nonce_bytes);
        let cipher = Aes256Gcm::new(&self.key);
        
        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, actual_ciphertext)
            .map_err(|e| AppError::Encryption(format!("Decryption failed: {}", e)))?;
        
        Ok(plaintext)
    }
    
    /// Encrypt string data
    pub fn encrypt_string(&self, plaintext: &str) -> Result<String> {
        let encrypted = self.encrypt(plaintext.as_bytes())?;
        Ok(general_purpose::STANDARD.encode(encrypted))
    }
    
    /// Decrypt string data
    pub fn decrypt_string(&self, ciphertext: &str) -> Result<String> {
        let decoded = general_purpose::STANDARD
            .decode(ciphertext)
            .map_err(|e| AppError::Encryption(format!("Base64 decode failed: {}", e)))?;
        
        let decrypted = self.decrypt(&decoded)?;
        
        String::from_utf8(decrypted)
            .map_err(|e| AppError::Encryption(format!("UTF-8 decode failed: {}", e)))
    }
}

/// Master key data stored in keyring
#[derive(Debug)]
struct MasterKeyData {
    salt: Vec<u8>,
}

impl ToString for MasterKeyData {
    fn to_string(&self) -> String {
        general_purpose::STANDARD.encode(&self.salt)
    }
}

impl std::str::FromStr for MasterKeyData {
    type Err = AppError;
    
    fn from_str(s: &str) -> Result<Self> {
        let salt = general_purpose::STANDARD
            .decode(s)
            .map_err(|e| AppError::Encryption(format!("Invalid master key data: {}", e)))?;
        
        Ok(Self { salt })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_encryption_roundtrip() {
        let password = "test_password_123!";
        let manager = EncryptionManager::initialize(password).await.unwrap();
        
        let plaintext = "This is a secret message";
        let encrypted = manager.encrypt_string(plaintext).unwrap();
        let decrypted = manager.decrypt_string(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
    }
    
    #[tokio::test]
    async fn test_different_nonces() {
        let password = "test_password_123!";
        let manager = EncryptionManager::initialize(password).await.unwrap();
        
        let plaintext = "Same message";
        let encrypted1 = manager.encrypt_string(plaintext).unwrap();
        let encrypted2 = manager.encrypt_string(plaintext).unwrap();
        
        // Different nonces should produce different ciphertexts
        assert_ne!(encrypted1, encrypted2);
        
        // But both should decrypt to the same plaintext
        assert_eq!(
            manager.decrypt_string(&encrypted1).unwrap(),
            manager.decrypt_string(&encrypted2).unwrap()
        );
    }
}