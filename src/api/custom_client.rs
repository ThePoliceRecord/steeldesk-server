use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    Json,
};
use hbb_common::log;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::api::auth::AuthUser;
use crate::api::users::User;
use crate::database::Database;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomClientConfig {
    /// Display name for this config, e.g. "MyCompany Remote"
    pub name: String,
    /// Server hostname or IP (with optional port)
    pub host: String,
    /// Server public key (base64)
    #[serde(default)]
    pub key: String,
    /// API server URL
    #[serde(default)]
    pub api: String,
    /// Relay server hostname
    #[serde(default)]
    pub relay: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomClientResponse {
    pub id: String,
    pub name: String,
    /// The filename-encoded config string (e.g. "host=server.com,key=PUBKEY,api=https://api.server.com,relay=relay.server.com")
    pub config_string: String,
    /// Suggested filenames per platform
    pub download_filenames: HashMap<String, String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomClientListItem {
    pub id: String,
    pub name: String,
    pub host: String,
    pub key: String,
    pub api: String,
    pub relay: String,
    pub config_string: String,
    pub download_filenames: HashMap<String, String>,
    pub created_at: String,
}

// ---------------------------------------------------------------------------
// Config string generation
// ---------------------------------------------------------------------------

/// Generate a config string from the given fields.
///
/// Format matches what the client's `custom_server.rs` parses:
/// `host=HOST,key=KEY,api=API,relay=RELAY`
///
/// Empty fields are omitted to keep the filename shorter.
pub fn generate_config_string(host: &str, key: &str, api: &str, relay: &str) -> String {
    let mut parts = vec![format!("host={}", host)];
    if !key.is_empty() {
        parts.push(format!("key={}", key));
    }
    if !api.is_empty() {
        parts.push(format!("api={}", api));
    }
    if !relay.is_empty() {
        parts.push(format!("relay={}", relay));
    }
    parts.join(",")
}

/// Generate download filenames for each platform.
///
/// The config is embedded in the binary filename so the client can parse it
/// on startup (see `client/src/custom_server.rs`).
fn generate_download_filenames(config_string: &str) -> HashMap<String, String> {
    let mut filenames = HashMap::new();
    filenames.insert(
        "windows".to_string(),
        format!("steeldesk-{}.exe", config_string),
    );
    filenames.insert(
        "macos".to_string(),
        format!("steeldesk-{}.dmg", config_string),
    );
    filenames.insert(
        "linux".to_string(),
        format!("steeldesk-{}.deb", config_string),
    );
    filenames.insert(
        "android".to_string(),
        format!("steeldesk-{}.apk", config_string),
    );
    filenames
}

// ---------------------------------------------------------------------------
// Admin check (local helper)
// ---------------------------------------------------------------------------

async fn require_admin(
    claims: &crate::api::auth::Claims,
    db: &Database,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    match db.get_user_by_id(&claims.user_id).await {
        Ok(Some(row)) => {
            let caller = User::from(row);
            if !caller.is_admin {
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({"error": "admin access required"})),
                ));
            }
            Ok(())
        }
        _ => Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "user not found"})),
        )),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/custom-client/generate` -- generate a custom client config.
///
/// Accepts a `CustomClientConfig`, saves it to the database, and returns
/// the generated config string plus suggested filenames per platform.
pub async fn generate_custom_client(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<CustomClientConfig>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    // Validate required fields
    if payload.host.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "host is required"})),
        );
    }
    if payload.name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "name is required"})),
        );
    }

    let id = uuid::Uuid::new_v4().to_string();
    let config_string = generate_config_string(&payload.host, &payload.key, &payload.api, &payload.relay);
    let download_filenames = generate_download_filenames(&config_string);

    match db
        .insert_custom_client(&id, &payload.name, &payload.host, &payload.key, &payload.api, &payload.relay)
        .await
    {
        Ok(row) => {
            let resp = CustomClientResponse {
                id: row.id,
                name: row.name,
                config_string,
                download_filenames,
                created_at: row.created_at,
            };
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to insert custom client config: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to save config"})),
            )
        }
    }
}

/// `GET /api/custom-client/configs` -- list all saved custom client configs (admin only).
pub async fn list_custom_clients(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.list_custom_clients().await {
        Ok(rows) => {
            let items: Vec<CustomClientListItem> = rows
                .into_iter()
                .map(|row| {
                    let config_string =
                        generate_config_string(&row.host, &row.key, &row.api, &row.relay);
                    let download_filenames = generate_download_filenames(&config_string);
                    CustomClientListItem {
                        id: row.id,
                        name: row.name,
                        host: row.host,
                        key: row.key,
                        api: row.api,
                        relay: row.relay,
                        config_string,
                        download_filenames,
                        created_at: row.created_at,
                    }
                })
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(items).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list custom clients: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to list configs"})),
            )
        }
    }
}

/// `DELETE /api/custom-client/configs/:id` -- delete a saved custom client config (admin only).
pub async fn delete_custom_client(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.delete_custom_client(&id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "deleted"})),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "config not found"})),
        ),
        Err(e) => {
            log::error!("Failed to delete custom client config: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to delete config"})),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_config_string_all_fields() {
        let s = generate_config_string("server.example.com", "MYKEY123", "https://api.example.com", "relay.example.com");
        assert_eq!(s, "host=server.example.com,key=MYKEY123,api=https://api.example.com,relay=relay.example.com");
    }

    #[test]
    fn test_generate_config_string_host_only() {
        let s = generate_config_string("server.example.com", "", "", "");
        assert_eq!(s, "host=server.example.com");
    }

    #[test]
    fn test_generate_config_string_host_and_key() {
        let s = generate_config_string("10.0.0.1", "Zm9vYmFyLiwyCg==", "", "");
        assert_eq!(s, "host=10.0.0.1,key=Zm9vYmFyLiwyCg==");
    }

    #[test]
    fn test_generate_config_string_host_and_relay() {
        let s = generate_config_string("myhost.com", "", "", "relay.myhost.com");
        assert_eq!(s, "host=myhost.com,relay=relay.myhost.com");
    }

    #[test]
    fn test_generate_config_string_with_port() {
        let s = generate_config_string("myhost.com:21116", "", "", "");
        assert_eq!(s, "host=myhost.com:21116");
    }

    #[test]
    fn test_download_filenames_contains_all_platforms() {
        let filenames = generate_download_filenames("host=server.com");
        assert!(filenames.contains_key("windows"));
        assert!(filenames.contains_key("macos"));
        assert!(filenames.contains_key("linux"));
        assert!(filenames.contains_key("android"));
    }

    #[test]
    fn test_download_filenames_format() {
        let filenames = generate_download_filenames("host=server.com,key=K");
        assert_eq!(filenames["windows"], "steeldesk-host=server.com,key=K.exe");
        assert_eq!(filenames["macos"], "steeldesk-host=server.com,key=K.dmg");
        assert_eq!(filenames["linux"], "steeldesk-host=server.com,key=K.deb");
        assert_eq!(filenames["android"], "steeldesk-host=server.com,key=K.apk");
    }

    #[test]
    fn test_config_string_roundtrip_with_client_parser() {
        // Verify the generated config string is parseable by the client's
        // custom_server.rs logic (simulated here).
        let config = generate_config_string("server.example.net", "Zm9vYmFyLiwyCg==", "https://api.server.com", "relay.server.com");
        let filename = format!("steeldesk-{}.exe", config);

        // Simulate the client parser: strip .exe, find host=, split on comma
        let s = &filename[..filename.len() - 4]; // strip .exe
        assert!(s.contains("host="));

        let stripped = &s[s.to_lowercase().find("host=").unwrap()..];
        let parts: Vec<&str> = stripped.split(',').collect();

        let mut host = String::new();
        let mut key = String::new();
        let mut api = String::new();
        let mut relay = String::new();
        for part in &parts {
            let lower = part.to_lowercase();
            if lower.starts_with("host=") {
                host = part[5..].to_string();
            } else if lower.starts_with("key=") {
                key = part[4..].to_string();
            } else if lower.starts_with("api=") {
                api = part[4..].to_string();
            } else if lower.starts_with("relay=") {
                relay = part[6..].to_string();
            }
        }

        assert_eq!(host, "server.example.net");
        assert_eq!(key, "Zm9vYmFyLiwyCg==");
        assert_eq!(api, "https://api.server.com");
        assert_eq!(relay, "relay.server.com");
    }

    #[test]
    fn test_custom_client_config_deserialize() {
        let json = r#"{"name":"My Company","host":"server.com","key":"K","api":"https://api.server.com","relay":"relay.server.com"}"#;
        let config: CustomClientConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name, "My Company");
        assert_eq!(config.host, "server.com");
        assert_eq!(config.key, "K");
        assert_eq!(config.api, "https://api.server.com");
        assert_eq!(config.relay, "relay.server.com");
    }

    #[test]
    fn test_custom_client_config_deserialize_minimal() {
        let json = r#"{"name":"Test","host":"10.0.0.1"}"#;
        let config: CustomClientConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name, "Test");
        assert_eq!(config.host, "10.0.0.1");
        assert_eq!(config.key, "");
        assert_eq!(config.api, "");
        assert_eq!(config.relay, "");
    }

    #[test]
    fn test_custom_client_response_serialize() {
        let resp = CustomClientResponse {
            id: "abc-123".to_string(),
            name: "Test".to_string(),
            config_string: "host=server.com".to_string(),
            download_filenames: generate_download_filenames("host=server.com"),
            created_at: "2026-01-01 00:00:00".to_string(),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["id"], "abc-123");
        assert_eq!(json["config_string"], "host=server.com");
        assert!(json["download_filenames"]["windows"].as_str().unwrap().ends_with(".exe"));
    }
}
