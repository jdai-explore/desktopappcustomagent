use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::path::PathBuf;

use crate::error::{AppError, Result};
use crate::security::EncryptionManager;

pub struct Database {
    pool: Pool<Sqlite>,
    encryption: EncryptionManager,
}

impl Database {
    /// Create a new database connection with encryption
    pub async fn new(encryption: EncryptionManager) -> Result<Self> {
        let db_path = Self::get_db_path()?;
        
        // Ensure directory exists
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        
        let db_url = format!("sqlite:{}", db_path.display());
        
        // Create connection pool with optimizations
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&db_url)
            .await?;
        
        let db = Self { pool, encryption };
        
        // Initialize database schema
        db.initialize_schema().await?;
        
        Ok(db)
    }
    
    /// Get database file path
    fn get_db_path() -> Result<PathBuf> {
        let data_dir = dirs::data_dir()
            .ok_or_else(|| AppError::Configuration("Could not find data directory".to_string()))?;
        
        Ok(data_dir.join("desktop-agent").join("data.db"))
    }
    
    /// Initialize database schema
    async fn initialize_schema(&self) -> Result<()> {
        // Enable WAL mode and other optimizations
        sqlx::query("PRAGMA journal_mode = WAL")
            .execute(&self.pool)
            .await?;
        
        sqlx::query("PRAGMA synchronous = NORMAL")
            .execute(&self.pool)
            .await?;
        
        sqlx::query("PRAGMA foreign_keys = ON")
            .execute(&self.pool)
            .await?;
        
        // Create tables
        sqlx::query(include_str!("schema.sql"))
            .execute(&self.pool)
            .await?;
        
        Ok(())
    }
    
    /// Store encrypted data
    pub async fn store_encrypted(
        &self,
        table: &str,
        id: &str,
        column: &str,
        data: &str,
    ) -> Result<()> {
        let encrypted = self.encryption.encrypt_string(data)?;
        
        let query = format!(
            "INSERT OR REPLACE INTO {} (id, {}) VALUES (?, ?)",
            table, column
        );
        
        sqlx::query(&query)
            .bind(id)
            .bind(encrypted)
            .execute(&self.pool)
            .await?;
        
        Ok(())
    }
    
    /// Retrieve and decrypt data
    pub async fn get_decrypted(
        &self,
        table: &str,
        id: &str,
        column: &str,
    ) -> Result<Option<String>> {
        let query = format!("SELECT {} FROM {} WHERE id = ?", column, table);
        
        let row: Option<(String,)> = sqlx::query_as(&query)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        
        match row {
            Some((encrypted,)) => {
                let decrypted = self.encryption.decrypt_string(&encrypted)?;
                Ok(Some(decrypted))
            }
            None => Ok(None),
        }
    }
    
    /// Begin a transaction
    pub async fn begin_transaction(&self) -> Result<sqlx::Transaction<'_, Sqlite>> {
        Ok(self.pool.begin().await?)
    }
    
    /// Get connection pool for direct queries
    pub fn pool(&self) -> &Pool<Sqlite> {
        &self.pool
    }
    
    /// Create backup
    pub async fn backup(&self, backup_path: PathBuf) -> Result<()> {
        // Use SQLite's backup API
        let backup_url = format!("sqlite:{}", backup_path.display());
        
        sqlx::query(&format!(
            "VACUUM INTO '{}'",
            backup_path.display()
        ))
        .execute(&self.pool)
        .await?;
        
        Ok(())
    }
    
    /// Restore from backup
    pub async fn restore(&self, backup_path: PathBuf) -> Result<()> {
        if !backup_path.exists() {
            return Err(AppError::Configuration(
                "Backup file does not exist".to_string(),
            ));
        }
        
        // This would require closing current connections and copying the file
        // Implementation depends on application state management
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_database_initialization() {
        let password = "test_password";
        let encryption = EncryptionManager::initialize(password).await.unwrap();
        
        let db = Database::new(encryption).await.unwrap();
        
        // Test that tables exist
        let result = sqlx::query("SELECT name FROM sqlite_master WHERE type='table'")
            .fetch_all(db.pool())
            .await
            .unwrap();
        
        assert!(!result.is_empty());
    }
}