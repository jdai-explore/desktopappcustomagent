// src-tauri/src/main.rs
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use tauri::{App, Manager};
use tracing::{info, error};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod security;
mod commands;
mod utils;

use commands::*;
use security::SecurityManager;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("Security error: {0}")]
    Security(#[from] security::SecurityError),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("General error: {0}")]
    General(String),
}

impl serde::Serialize for AppError {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::ser::Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

type AppResult<T> = Result<T, AppError>;

#[derive(Clone)]
pub struct AppState {
    pub security: SecurityManager,
}

impl AppState {
    pub async fn new() -> AppResult<Self> {
        info!("Initializing application state...");
        
        // Initialize security manager
        let security = SecurityManager::new().await
            .map_err(|e| AppError::Security(security::SecurityError::Authentication(e.to_string())))?;
        
        info!("Application state initialized successfully");
        
        Ok(Self {
            security,
        })
    }
}

async fn setup_app(app: &mut App) -> Result<(), Box<dyn std::error::Error>> {
    info!("Setting up application...");
    
    // Initialize application state
    let app_state = AppState::new().await?;
    
    // Store state in Tauri's managed state
    app.manage(app_state);
    
    info!("Application setup completed successfully");
    Ok(())
}

fn setup_logging() {
    let log_filter = if cfg!(debug_assertions) {
        "desktop_agent=debug,tauri=info"
    } else {
        "desktop_agent=info,tauri=warn"
    };

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| log_filter.into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn main() {
    // Setup logging first
    setup_logging();
    info!("Starting Desktop Agent...");

    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_fs::init())
        .plugin(tauri_plugin_sql::Builder::default().build())
        .setup(|app| {
            tauri::async_runtime::block_on(setup_app(app))
        })
        .invoke_handler(tauri::generate_handler![
            // Security commands
            test_security_system,
            store_api_key,
            get_api_key,
            delete_api_key,
            list_configured_providers,
            
            // Health check
            health_check
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}