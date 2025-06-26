use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "message")]
pub enum AppError {
    #[error("Database error: {0}")]
    Database(String),
    
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("Keyring error: {0}")]
    Keyring(String),
    
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    #[error("Workflow error: {0}")]
    Workflow(String),
    
    #[error("Node error: {0}")]
    Node(String),
    
    #[error("Execution error: {0}")]
    Execution(String),
    
    #[error("Validation error: {0}")]
    Validation(String),
    
    #[error("IO error: {0}")]
    Io(String),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Authentication error: {0}")]
    Authentication(String),
    
    #[error("Permission error: {0}")]
    Permission(String),
    
    #[error("Network error: {0}")]
    Network(String),
    
    #[error("Timeout error: {0}")]
    Timeout(String),
    
    #[error("Resource not found: {0}")]
    NotFound(String),
    
    #[error("Resource already exists: {0}")]
    AlreadyExists(String),
    
    #[error("Unknown error: {0}")]
    Unknown(String),
}

// Implement From traits for common error types
impl From<sqlx::Error> for AppError {
    fn from(err: sqlx::Error) -> Self {
        match err {
            sqlx::Error::RowNotFound => AppError::NotFound("Database record not found".to_string()),
            _ => AppError::Database(err.to_string()),
        }
    }
}

impl From<std::io::Error> for AppError {
    fn from(err: std::io::Error) -> Self {
        AppError::Io(err.to_string())
    }
}

impl From<serde_json::Error> for AppError {
    fn from(err: serde_json::Error) -> Self {
        AppError::Serialization(err.to_string())
    }
}

impl From<AppError> for String {
    fn from(error: AppError) -> Self {
        error.to_string()
    }
}

// Implement serde::Serialize for Tauri IPC
impl serde::Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        
        let mut state = serializer.serialize_struct("AppError", 3)?;
        state.serialize_field("error", &true)?;
        state.serialize_field("type", &self.error_type())?;
        state.serialize_field("message", &self.to_string())?;
        state.end()
    }
}

impl AppError {
    /// Get the error type as a string
    pub fn error_type(&self) -> &'static str {
        match self {
            AppError::Database(_) => "database",
            AppError::Encryption(_) => "encryption",
            AppError::Keyring(_) => "keyring",
            AppError::Configuration(_) => "configuration",
            AppError::Workflow(_) => "workflow",
            AppError::Node(_) => "node",
            AppError::Execution(_) => "execution",
            AppError::Validation(_) => "validation",
            AppError::Io(_) => "io",
            AppError::Serialization(_) => "serialization",
            AppError::Authentication(_) => "authentication",
            AppError::Permission(_) => "permission",
            AppError::Network(_) => "network",
            AppError::Timeout(_) => "timeout",
            AppError::NotFound(_) => "not_found",
            AppError::AlreadyExists(_) => "already_exists",
            AppError::Unknown(_) => "unknown",
        }
    }
    
    /// Check if the error is recoverable
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            AppError::Network(_) | AppError::Timeout(_) | AppError::Io(_)
        )
    }
    
    /// Get user-friendly error message
    pub fn user_message(&self) -> String {
        match self {
            AppError::Database(_) => {
                "A database error occurred. Please try again or contact support.".to_string()
            }
            AppError::Encryption(_) => {
                "An encryption error occurred. Please check your password.".to_string()
            }
            AppError::Keyring(_) => {
                "Failed to access secure storage. Please check your system keychain settings.".to_string()
            }
            AppError::Configuration(msg) => msg.clone(),
            AppError::Workflow(msg) => msg.clone(),
            AppError::Node(msg) => msg.clone(),
            AppError::Execution(msg) => msg.clone(),
            AppError::Validation(msg) => msg.clone(),
            AppError::Io(_) => "A file system error occurred. Please check permissions.".to_string(),
            AppError::Serialization(_) => "Failed to process data format.".to_string(),
            AppError::Authentication(_) => "Authentication failed. Please check your credentials.".to_string(),
            AppError::Permission(_) => "You don't have permission to perform this action.".to_string(),
            AppError::Network(_) => "Network error. Please check your connection.".to_string(),
            AppError::Timeout(_) => "Operation timed out. Please try again.".to_string(),
            AppError::NotFound(msg) => format!("Not found: {}", msg),
            AppError::AlreadyExists(msg) => format!("Already exists: {}", msg),
            AppError::Unknown(_) => "An unexpected error occurred.".to_string(),
        }
    }
}

pub type Result<T> = std::result::Result<T, AppError>;