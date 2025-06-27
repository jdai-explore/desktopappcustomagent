// src-tauri/src/commands/security.rs
//! Tauri commands for security operations

use crate::{AppResult, AppState};
use serde::{Deserialize, Serialize};
use tauri::State;
use tracing::{debug, info};

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityTestResult {
    pub status: String,
    pub encrypted: bool,
    pub keyring_available: bool,
    pub master_key_exists: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiKeyRequest {
    pub provider: String,
    pub api_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiKeyResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvidersResponse {
    pub providers: Vec<String>,
}

/// Test the security system functionality
#[tauri::command]
pub async fn test_security_system(state: State<'_, AppState>) -> AppResult<SecurityTestResult> {
    info!("Testing security system");
    
    // Test basic security functionality
    match state.security.health_check().await {
        Ok(()) => {
            debug!("Security health check passed");
            
            // Get additional info
            let master_key_info = match state.security.master_key.get_master_key_info().await {
                Ok(info) => info,
                Err(_) => crate::security::master_key::MasterKeyInfo {
                    exists: false,
                    cached: false,
                    creation_time: None,
                    key_size: 32,
                    salt_size: 16,
                }
            };
            
            Ok(SecurityTestResult {
                status: "ok".to_string(),
                encrypted: true,
                keyring_available: true,
                master_key_exists: master_key_info.exists,
            })
        }
        Err(e) => {
            debug!("Security health check failed: {}", e);
            Ok(SecurityTestResult {
                status: format!("error: {}", e),
                encrypted: false,
                keyring_available: false,
                master_key_exists: false,
            })
        }
    }
}

/// Store an API key for a provider
#[tauri::command]
pub async fn store_api_key(
    provider: String,
    api_key: String,
    state: State<'_, AppState>
) -> AppResult<ApiKeyResponse> {
    info!("Storing API key for provider: {}", provider);
    
    if provider.trim().is_empty() {
        return Ok(ApiKeyResponse {
            success: false,
            message: "Provider name cannot be empty".to_string(),
        });
    }
    
    if api_key.trim().is_empty() {
        return Ok(ApiKeyResponse {
            success: false,
            message: "API key cannot be empty".to_string(),
        });
    }
    
    match state.security.store_api_key(&provider, &api_key).await {
        Ok(()) => {
            info!("API key stored successfully for provider: {}", provider);
            Ok(ApiKeyResponse {
                success: true,
                message: format!("API key stored successfully for {}", provider),
            })
        }
        Err(e) => {
            debug!("Failed to store API key for {}: {}", provider, e);
            Ok(ApiKeyResponse {
                success: false,
                message: format!("Failed to store API key: {}", e),
            })
        }
    }
}

/// Get an API key for a provider
#[tauri::command]
pub async fn get_api_key(
    provider: String,
    state: State<'_, AppState>
) -> AppResult<Option<String>> {
    debug!("Retrieving API key for provider: {}", provider);
    
    if provider.trim().is_empty() {
        return Ok(None);
    }
    
    match state.security.get_api_key(&provider).await {
        Ok(api_key) => {
            if api_key.is_some() {
                debug!("API key retrieved successfully for provider: {}", provider);
            } else {
                debug!("No API key found for provider: {}", provider);
            }
            Ok(api_key)
        }
        Err(e) => {
            debug!("Failed to retrieve API key for {}: {}", provider, e);
            Ok(None)
        }
    }
}

/// Delete an API key for a provider
#[tauri::command]
pub async fn delete_api_key(
    provider: String,
    state: State<'_, AppState>
) -> AppResult<ApiKeyResponse> {
    info!("Deleting API key for provider: {}", provider);
    
    if provider.trim().is_empty() {
        return Ok(ApiKeyResponse {
            success: false,
            message: "Provider name cannot be empty".to_string(),
        });
    }
    
    match state.security.delete_api_key(&provider).await {
        Ok(deleted) => {
            if deleted {
                info!("API key deleted successfully for provider: {}", provider);
                Ok(ApiKeyResponse {
                    success: true,
                    message: format!("API key deleted successfully for {}", provider),
                })
            } else {
                debug!("No API key found to delete for provider: {}", provider);
                Ok(ApiKeyResponse {
                    success: true,
                    message: format!("No API key found for {}", provider),
                })
            }
        }
        Err(e) => {
            debug!("Failed to delete API key for {}: {}", provider, e);
            Ok(ApiKeyResponse {
                success: false,
                message: format!("Failed to delete API key: {}", e),
            })
        }
    }
}

/// List all configured providers
#[tauri::command]
pub async fn list_configured_providers(
    state: State<'_, AppState>
) -> AppResult<ProvidersResponse> {
    debug!("Listing configured providers");
    
    match state.security.list_configured_providers().await {
        Ok(providers) => {
            debug!("Found {} configured providers", providers.len());
            Ok(ProvidersResponse { providers })
        }
        Err(e) => {
            debug!("Failed to list providers: {}", e);
            Ok(ProvidersResponse { providers: Vec::new() })
        }
    }
}

/// General health check
#[tauri::command]
pub async fn health_check(state: State<'_, AppState>) -> AppResult<String> {
    debug!("Running application health check");
    
    // Test security system
    match state.security.health_check().await {
        Ok(()) => Ok("healthy".to_string()),
        Err(e) => Ok(format!("unhealthy: {}", e)),
    }
}