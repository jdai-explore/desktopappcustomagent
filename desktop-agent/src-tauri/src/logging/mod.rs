use std::collections::HashMap;
use std::path::PathBuf;
use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

/// Initialize the logging system
pub fn init_logging(log_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Create log directory if it doesn't exist
    std::fs::create_dir_all(&log_dir)?;
    
    // Set up file appender with daily rotation
    let file_appender = tracing_appender::rolling::daily(log_dir, "desktop-agent.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);
    
    // Configure subscriber with JSON formatting for structured logs
    let file_layer = fmt::layer()
        .with_writer(non_blocking)
        .with_ansi(false)
        .with_target(true)
        .with_thread_ids(true)
        .with_thread_names(true)
        .json();
    
    // Configure console output for development
    let console_layer = fmt::layer()
        .with_target(false)
        .with_thread_ids(false)
        .pretty();
    
    // Set up environment filter
    let env_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| {
            EnvFilter::new("desktop_agent=debug,warn")
        });
    
    // Combine layers
    let subscriber = tracing_subscriber::registry()
        .with(env_filter)
        .with(file_layer);
    
    // Add console layer only in debug mode
    #[cfg(debug_assertions)]
    let subscriber = subscriber.with(console_layer);
    
    // Set as global default
    tracing::subscriber::set_global_default(subscriber)?;
    
    info!("Logging system initialized");
    debug!("Log directory: {:?}", log_dir);
    
    Ok(())
}

/// Trait for sanitizing sensitive data in logs
pub trait Sanitizable {
    fn sanitize(&self) -> String;
}

impl Sanitizable for String {
    fn sanitize(&self) -> String {
        // Default implementation - no sanitization
        self.clone()
    }
}

/// Sensitive string wrapper that sanitizes on display
pub struct SensitiveString(String);

impl SensitiveString {
    pub fn new(value: String) -> Self {
        Self(value)
    }
}

impl std::fmt::Display for SensitiveString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "***REDACTED***")
    }
}

impl std::fmt::Debug for SensitiveString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SensitiveString(***REDACTED***)")
    }
}

/// Sanitize a HashMap of values based on key names
pub fn sanitize_fields(fields: &HashMap<String, String>) -> HashMap<String, String> {
    fields
        .iter()
        .map(|(key, value)| {
            let sanitized_value = if is_sensitive_key(key) {
                "***REDACTED***".to_string()
            } else {
                value.clone()
            };
            (key.clone(), sanitized_value)
        })
        .collect()
}

/// Check if a field name indicates sensitive data
fn is_sensitive_key(key: &str) -> bool {
    let sensitive_patterns = [
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "auth",
        "credential",
        "private",
        "encryption_key",
        "salt",
    ];
    
    let lower_key = key.to_lowercase();
    sensitive_patterns
        .iter()
        .any(|pattern| lower_key.contains(pattern))
}

/// Macro for structured logging with automatic sanitization
#[macro_export]
macro_rules! log_event {
    ($level:expr, $message:expr) => {
        $level!($message);
    };
    
    ($level:expr, $message:expr, $($key:expr => $value:expr),* $(,)?) => {
        {
            let mut fields = std::collections::HashMap::new();
            $(
                fields.insert($key.to_string(), format!("{}", $value));
            )*
            let sanitized = $crate::logging::sanitize_fields(&fields);
            $level!($message, ?sanitized);
        }
    };
}

/// Log an audit event (security-sensitive operations)
pub fn audit_log(
    operation: &str,
    resource_type: Option<&str>,
    resource_id: Option<&str>,
    success: bool,
    metadata: Option<HashMap<String, String>>,
) {
    let sanitized_metadata = metadata.map(|m| sanitize_fields(&m));
    
    info!(
        audit = true,
        operation = operation,
        resource_type = resource_type,
        resource_id = resource_id,
        success = success,
        metadata = ?sanitized_metadata,
        "Audit event"
    );
}

/// Performance logging helper
pub struct PerfTimer {
    operation: String,
    start: std::time::Instant,
    metadata: HashMap<String, String>,
}

impl PerfTimer {
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            start: std::time::Instant::now(),
            metadata: HashMap::new(),
        }
    }
    
    pub fn add_metadata(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.metadata.insert(key.into(), value.into());
    }
}

impl Drop for PerfTimer {
    fn drop(&mut self) {
        let duration = self.start.elapsed();
        debug!(
            performance = true,
            operation = %self.operation,
            duration_ms = duration.as_millis(),
            metadata = ?self.metadata,
            "Performance measurement"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_sensitive_key_detection() {
        assert!(is_sensitive_key("password"));
        assert!(is_sensitive_key("api_key"));
        assert!(is_sensitive_key("API_KEY"));
        assert!(is_sensitive_key("user_password"));
        assert!(!is_sensitive_key("username"));
        assert!(!is_sensitive_key("email"));
    }
    
    #[test]
    fn test_field_sanitization() {
        let mut fields = HashMap::new();
        fields.insert("username".to_string(), "john_doe".to_string());
        fields.insert("password".to_string(), "secret123".to_string());
        fields.insert("api_key".to_string(), "sk-1234567890".to_string());
        
        let sanitized = sanitize_fields(&fields);
        
        assert_eq!(sanitized.get("username").unwrap(), "john_doe");
        assert_eq!(sanitized.get("password").unwrap(), "***REDACTED***");
        assert_eq!(sanitized.get("api_key").unwrap(), "***REDACTED***");
    }
}