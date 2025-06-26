// Prevents additional console window on Windows in release, DO NOT REMOVE!
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod database;
mod error;
mod keyring;
mod logging;
mod security;

use error::{AppError, Result};
use std::sync::Arc;
use tauri::State;
use tokio::sync::Mutex;

struct AppState {
    db: Arc<Mutex<Option<database::Database>>>,
    encryption: Arc<Mutex<Option<security::EncryptionManager>>>,
}

#[tauri::command]
async fn initialize_app(
    password: String,
    state: State<'_, AppState>,
) -> Result<String> {
    // Initialize encryption
    let encryption_manager = security::EncryptionManager::initialize(&password).await?;
    
    // Initialize database with encryption
    let db = database::Database::new(encryption_manager.clone()).await?;
    
    // Store in app state
    *state.encryption.lock().await = Some(encryption_manager);
    *state.db.lock().await = Some(db);
    
    Ok("Application initialized successfully".to_string())
}

#[tauri::command]
async fn check_initialization_status(state: State<'_, AppState>) -> Result<bool> {
    let has_master_key = keyring::KeyringManager::master_key_exists();
    let db_locked = state.db.lock().await;
    let is_initialized = db_locked.is_some() && has_master_key;
    
    Ok(is_initialized)
}

#[tauri::command]
async fn lock_app(state: State<'_, AppState>) -> Result<()> {
    // Clear sensitive data from memory
    *state.encryption.lock().await = None;
    *state.db.lock().await = None;
    
    Ok(())
}

#[tauri::command]
async fn unlock_app(password: String, state: State<'_, AppState>) -> Result<()> {
    // Verify password and reinitialize
    let encryption_manager = security::EncryptionManager::unlock(&password).await?;
    let db = database::Database::new(encryption_manager.clone()).await?;
    
    *state.encryption.lock().await = Some(encryption_manager);
    *state.db.lock().await = Some(db);
    
    Ok(())
}

fn main() {
    // Initialize logging
    let log_dir = dirs::data_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join("desktop-agent")
        .join("logs");
    
    logging::init_logging(log_dir).expect("Failed to initialize logging");
    
    let app_state = AppState {
        db: Arc::new(Mutex::new(None)),
        encryption: Arc::new(Mutex::new(None)),
    };
    
    tauri::Builder::default()
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            initialize_app,
            check_initialization_status,
            lock_app,
            unlock_app,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}