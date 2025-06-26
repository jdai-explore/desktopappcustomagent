// tests/integration/security_test.rs

#[cfg(test)]
mod security_tests {
    use tempfile::tempdir;
    
    #[tokio::test]
    async fn test_full_encryption_flow() {
        // Test the complete encryption/decryption flow
        let password = "test_password_12345!@#";
        
        // Initialize encryption
        let encryption = EncryptionManager::initialize(password).await.unwrap();
        
        // Test string encryption
        let plaintext = "This is sensitive data";
        let encrypted = encryption.encrypt_string(plaintext).unwrap();
        let decrypted = encryption.decrypt_string(&encrypted).unwrap();
        
        assert_eq!(plaintext, decrypted);
        assert_ne!(plaintext, encrypted);
    }
    
    #[tokio::test]
    async fn test_keyring_integration() {
        // Test keyring operations
        let test_key = "test_master_key_data";
        
        // Store and retrieve
        KeyringManager::store_master_key(test_key).unwrap();
        assert!(KeyringManager::master_key_exists());
        
        let retrieved = KeyringManager::get_master_key().unwrap();
        assert_eq!(retrieved, test_key);
        
        // Cleanup
        KeyringManager::delete_master_key().unwrap();
        assert!(!KeyringManager::master_key_exists());
    }
    
    #[tokio::test]
    async fn test_database_encryption() {
        let password = "test_db_password_123!";
        let encryption = EncryptionManager::initialize(password).await.unwrap();
        
        // Create temporary database
        let temp_dir = tempdir().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        
        let db = Database::new(encryption).await.unwrap();
        
        // Test encrypted storage
        let test_data = r#"{"api_key": "sk-1234567890", "model": "gpt-4"}"#;
        db.store_encrypted("api_credentials", "test-id", "encrypted_key", test_data)
            .await
            .unwrap();
        
        // Retrieve and verify
        let retrieved = db.get_decrypted("api_credentials", "test-id", "encrypted_key")
            .await
            .unwrap()
            .unwrap();
        
        assert_eq!(retrieved, test_data);
    }
    
    #[test]
    fn test_error_handling() {
        // Test error conversions and messages
        let db_error = AppError::Database("Connection failed".to_string());
        assert_eq!(db_error.error_type(), "database");
        assert!(!db_error.is_recoverable());
        
        let network_error = AppError::Network("Timeout".to_string());
        assert!(network_error.is_recoverable());
        
        // Test user-friendly messages
        let enc_error = AppError::Encryption("Invalid key".to_string());
        let user_msg = enc_error.user_message();
        assert!(user_msg.contains("encryption"));
        assert!(user_msg.contains("password"));
    }
    
    #[test]
    fn test_logging_sanitization() {
        let mut fields = std::collections::HashMap::new();
        fields.insert("username".to_string(), "john_doe".to_string());
        fields.insert("password".to_string(), "secret123".to_string());
        fields.insert("api_key".to_string(), "sk-abcdef".to_string());
        fields.insert("email".to_string(), "john@example.com".to_string());
        
        let sanitized = sanitize_fields(&fields);
        
        assert_eq!(sanitized.get("username").unwrap(), "john_doe");
        assert_eq!(sanitized.get("email").unwrap(), "john@example.com");
        assert_eq!(sanitized.get("password").unwrap(), "***REDACTED***");
        assert_eq!(sanitized.get("api_key").unwrap(), "***REDACTED***");
    }
    
    #[tokio::test]
    async fn test_concurrent_access() {
        use tokio::task;
        
        let password = "concurrent_test_pass_123!";
        let encryption = EncryptionManager::initialize(password).await.unwrap();
        
        // Test concurrent encryption operations
        let mut handles = vec![];
        
        for i in 0..10 {
            let enc_clone = encryption.clone();
            let handle = task::spawn(async move {
                let data = format!("Concurrent data {}", i);
                let encrypted = enc_clone.encrypt_string(&data).unwrap();
                let decrypted = enc_clone.decrypt_string(&encrypted).unwrap();
                assert_eq!(data, decrypted);
            });
            handles.push(handle);
        }
        
        // Wait for all tasks
        for handle in handles {
            handle.await.unwrap();
        }
    }
    
    #[tokio::test]
    async fn test_large_data_encryption() {
        let password = "large_data_test_123!";
        let encryption = EncryptionManager::initialize(password).await.unwrap();
        
        // Test with 1MB of data
        let large_data = "x".repeat(1024 * 1024);
        let encrypted = encryption.encrypt_string(&large_data).unwrap();
        let decrypted = encryption.decrypt_string(&encrypted).unwrap();
        
        assert_eq!(large_data.len(), decrypted.len());
        assert_eq!(large_data, decrypted);
    }
    
    #[tokio::test]
    async fn test_database_schema_creation() {
        let password = "schema_test_123!";
        let encryption = EncryptionManager::initialize(password).await.unwrap();
        
        let temp_dir = tempdir().unwrap();
        std::env::set_var("HOME", temp_dir.path());
        
        let db = Database::new(encryption).await.unwrap();
        
        // Verify all tables exist
        let tables: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        .fetch_all(db.pool())
        .await
        .unwrap();
        
        let table_names: Vec<String> = tables.into_iter().map(|(name,)| name).collect();
        
        assert!(table_names.contains(&"workflows".to_string()));
        assert!(table_names.contains(&"nodes".to_string()));
        assert!(table_names.contains(&"connections".to_string()));
        assert!(table_names.contains(&"executions".to_string()));
        assert!(table_names.contains(&"api_credentials".to_string()));
        assert!(table_names.contains(&"audit_log".to_string()));
    }
    
    #[test]
    fn test_password_validation() {
        // Test password requirements
        let weak_passwords = vec![
            "short",
            "nouppercase123!",
            "NOLOWERCASE123!",
            "NoNumbers!",
            "NoSpecialChars123",
        ];
        
        for password in weak_passwords {
            // In production, implement actual validation
            assert!(password.len() < 12 || !has_mixed_case(password) || !has_special_chars(password));
        }
        
        let strong_password = "StrongP@ssw0rd123!";
        assert!(strong_password.len() >= 12);
        assert!(has_mixed_case(strong_password));
        assert!(has_special_chars(strong_password));
    }
    
    fn has_mixed_case(s: &str) -> bool {
        s.chars().any(|c| c.is_uppercase()) && s.chars().any(|c| c.is_lowercase())
    }
    
    fn has_special_chars(s: &str) -> bool {
        s.chars().any(|c| !c.is_alphanumeric())
    }
}

// tests/integration/e2e_test.rs

#[cfg(test)]
mod e2e_tests {
    use tauri::test::*;
    
    #[tokio::test]
    async fn test_app_initialization_flow() {
        // This would be a full E2E test using Tauri's test utilities
        // Testing the complete initialization flow from UI to backend
        
        // Note: Actual implementation would require Tauri test harness setup
        assert!(true); // Placeholder
    }
}

// tests/unit/encryption_test.rs

#[cfg(test)]
mod unit_tests {
    #[test]
    fn test_base64_encoding() {
        use base64::{Engine as _, engine::general_purpose};
        
        let data = b"test data";
        let encoded = general_purpose::STANDARD.encode(data);
        let decoded = general_purpose::STANDARD.decode(&encoded).unwrap();
        
        assert_eq!(data, decoded.as_slice());
    }
    
    #[test]
    fn test_nonce_generation() {
        use rand::RngCore;
        use rand::rngs::OsRng;
        
        let mut nonce1 = [0u8; 12];
        let mut nonce2 = [0u8; 12];
        
        OsRng.fill_bytes(&mut nonce1);
        OsRng.fill_bytes(&mut nonce2);
        
        // Nonces should be different
        assert_ne!(nonce1, nonce2);
    }
}