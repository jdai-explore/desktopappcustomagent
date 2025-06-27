// src-tauri/src/utils/logging.rs
//! Enhanced logging utilities

use std::path::PathBuf;
use tracing::info;

/// Get the application log directory
pub fn get_log_directory() -> Result<PathBuf, std::io::Error> {
    let app_data_dir = dirs::data_dir()
        .ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Could not find application data directory"
        ))?;
    
    let log_dir = app_data_dir.join("desktop-agent").join("logs");
    
    // Create directory if it doesn't exist
    std::fs::create_dir_all(&log_dir)?;
    
    Ok(log_dir)
}

/// Initialize file logging
pub fn init_file_logging() -> Result<(), Box<dyn std::error::Error>> {
    let log_dir = get_log_directory()?;
    let log_file = log_dir.join("desktop-agent.log");
    
    info!("Logging to file: {:?}", log_file);
    
    // TODO: Add file appender for production logging
    // For now, we'll stick with console logging
    
    Ok(())
}