use axum::{
    extract::{Extension, Path, Query},
    http::StatusCode,
    Json,
};
use hbb_common::log;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::api::auth::{create_token, AuthUser};
use crate::api::roles;
use crate::database::Database;

// ---------------------------------------------------------------------------
// In-memory CSRF state store
// ---------------------------------------------------------------------------

/// Pending OIDC authorization states. Maps `state` -> `provider_id`.
/// In production this should be backed by Redis/DB with TTL; for the
/// skeleton we use a simple in-memory mutex map.
#[derive(Clone, Default)]
pub struct OidcStateStore {
    inner: Arc<Mutex<HashMap<String, String>>>,
}

impl OidcStateStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a new state -> provider_id mapping.
    pub fn insert(&self, state: String, provider_id: String) {
        self.inner.lock().unwrap().insert(state, provider_id);
    }

    /// Remove and return the provider_id for the given state (single-use).
    pub fn take(&self, state: &str) -> Option<String> {
        self.inner.lock().unwrap().remove(state)
    }
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateOidcProviderRequest {
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
    #[serde(default = "default_scopes")]
    pub scopes: String,
}

fn default_scopes() -> String {
    "openid profile email".to_string()
}

/// Public provider info (client_secret is never exposed).
#[derive(Debug, Serialize)]
pub struct OidcProviderResponse {
    pub id: String,
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub scopes: String,
    pub enabled: bool,
    pub created_at: String,
}

impl From<crate::database::OidcProviderRow> for OidcProviderResponse {
    fn from(row: crate::database::OidcProviderRow) -> Self {
        OidcProviderResponse {
            id: row.id,
            name: row.name,
            issuer_url: row.issuer_url,
            client_id: row.client_id,
            scopes: row.scopes,
            enabled: row.enabled != 0,
            created_at: row.created_at,
        }
    }
}

/// Subset of the OIDC discovery document we care about.
#[derive(Debug, Deserialize)]
struct OidcDiscovery {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
}

/// Token response from the OIDC provider.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    id_token: Option<String>,
}

/// Userinfo response from the OIDC provider.
#[derive(Debug, Deserialize)]
struct UserinfoResponse {
    #[serde(default)]
    preferred_username: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    name: Option<String>,
    #[serde(default)]
    sub: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub code: String,
    pub state: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/oidc/providers` -- list configured OIDC providers (public, no auth).
pub async fn list_providers(
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<serde_json::Value>) {
    match db.list_oidc_providers().await {
        Ok(rows) => {
            let providers: Vec<OidcProviderResponse> =
                rows.into_iter().map(OidcProviderResponse::from).collect();
            (StatusCode::OK, Json(serde_json::to_value(providers).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list OIDC providers: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `POST /api/oidc/providers` -- add a new OIDC provider (admin only).
pub async fn create_provider(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<CreateOidcProviderRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::has_permission(&claims.user_id, "users", "edit", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    if payload.name.is_empty() || payload.issuer_url.is_empty() || payload.client_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "name, issuer_url, and client_id are required"})),
        );
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = db
        .insert_oidc_provider(
            &id,
            &payload.name,
            &payload.issuer_url,
            &payload.client_id,
            &payload.client_secret,
            &payload.scopes,
        )
        .await
    {
        log::error!("Failed to insert OIDC provider: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({"id": id, "name": payload.name})),
    )
}

/// `DELETE /api/oidc/providers/:id` -- remove an OIDC provider (admin only).
pub async fn delete_provider(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::has_permission(&claims.user_id, "users", "edit", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    match db.delete_oidc_provider(&id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "provider deleted"})),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "provider not found"})),
        ),
        Err(e) => {
            log::error!("Failed to delete OIDC provider: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `GET /api/oidc/authorize/:provider_id` -- redirect to the OIDC provider's
/// authorization endpoint.
pub async fn authorize(
    Extension(db): Extension<Database>,
    Extension(state_store): Extension<OidcStateStore>,
    Path(provider_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Look up provider
    let provider = match db.get_oidc_provider(&provider_id).await {
        Ok(Some(p)) if p.enabled != 0 => p,
        Ok(Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "provider is disabled"})),
            );
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "provider not found"})),
            );
        }
        Err(e) => {
            log::error!("DB error fetching OIDC provider: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };

    // Discover OIDC endpoints
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        provider.issuer_url.trim_end_matches('/')
    );

    let discovery: OidcDiscovery = match reqwest::Client::new()
        .get(&discovery_url)
        .send()
        .await
    {
        Ok(resp) => match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                log::error!("Failed to parse OIDC discovery doc: {}", e);
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": "failed to parse OIDC discovery document"})),
                );
            }
        },
        Err(e) => {
            log::error!("Failed to fetch OIDC discovery doc: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "failed to reach OIDC provider"})),
            );
        }
    };

    // Generate random state for CSRF protection
    let state = uuid::Uuid::new_v4().to_string();
    state_store.insert(state.clone(), provider_id);

    // Build authorize URL
    let callback_url = "/api/oidc/callback"; // relative; client must know the base URL
    let authorize_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
        discovery.authorization_endpoint,
        urlencoding::encode(&provider.client_id),
        urlencoding::encode(callback_url),
        urlencoding::encode(&provider.scopes),
        urlencoding::encode(&state),
    );

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "authorize_url": authorize_url,
            "state": state,
        })),
    )
}

/// `GET /api/oidc/callback?code=XXX&state=YYY` -- handle the OIDC callback.
///
/// Exchanges the authorization code for tokens, fetches userinfo, provisions
/// the user if needed, and returns a JWT.
pub async fn callback(
    Extension(db): Extension<Database>,
    Extension(state_store): Extension<OidcStateStore>,
    Query(params): Query<CallbackQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Verify state (CSRF protection) and retrieve provider_id
    let provider_id = match state_store.take(&params.state) {
        Some(pid) => pid,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "invalid or expired state parameter"})),
            );
        }
    };

    // Load provider
    let provider = match db.get_oidc_provider(&provider_id).await {
        Ok(Some(p)) => p,
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "OIDC provider not found"})),
            );
        }
    };

    // Discover endpoints
    let discovery_url = format!(
        "{}/.well-known/openid-configuration",
        provider.issuer_url.trim_end_matches('/')
    );
    let discovery: OidcDiscovery = match reqwest::Client::new()
        .get(&discovery_url)
        .send()
        .await
        .and_then(|r| Ok(r))
    {
        Ok(resp) => match resp.json().await {
            Ok(d) => d,
            Err(e) => {
                log::error!("OIDC discovery parse error: {}", e);
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": "failed to parse OIDC discovery document"})),
                );
            }
        },
        Err(e) => {
            log::error!("OIDC discovery fetch error: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "failed to reach OIDC provider"})),
            );
        }
    };

    // Exchange code for token
    let callback_url = "/api/oidc/callback";
    let token_resp = match reqwest::Client::new()
        .post(&discovery.token_endpoint)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", &params.code),
            ("redirect_uri", callback_url),
            ("client_id", &provider.client_id),
            ("client_secret", &provider.client_secret),
        ])
        .send()
        .await
    {
        Ok(resp) => {
            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                log::error!("OIDC token exchange failed ({}): {}", status, body);
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": "OIDC token exchange failed"})),
                );
            }
            match resp.json::<TokenResponse>().await {
                Ok(t) => t,
                Err(e) => {
                    log::error!("Failed to parse OIDC token response: {}", e);
                    return (
                        StatusCode::BAD_GATEWAY,
                        Json(serde_json::json!({"error": "failed to parse OIDC token response"})),
                    );
                }
            }
        }
        Err(e) => {
            log::error!("OIDC token request error: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "failed to contact OIDC token endpoint"})),
            );
        }
    };

    // Fetch userinfo
    let userinfo: UserinfoResponse = match reqwest::Client::new()
        .get(&discovery.userinfo_endpoint)
        .bearer_auth(&token_resp.access_token)
        .send()
        .await
    {
        Ok(resp) => match resp.json().await {
            Ok(u) => u,
            Err(e) => {
                log::error!("Failed to parse OIDC userinfo: {}", e);
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": "failed to parse OIDC userinfo"})),
                );
            }
        },
        Err(e) => {
            log::error!("OIDC userinfo request error: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "failed to contact OIDC userinfo endpoint"})),
            );
        }
    };

    // Determine username and email
    let email = match userinfo.email {
        Some(ref e) if !e.is_empty() => e.clone(),
        _ => match userinfo.sub {
            Some(ref s) => format!("{}@oidc", s),
            None => {
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(serde_json::json!({"error": "OIDC provider did not return email or sub claim"})),
                );
            }
        },
    };

    let username = userinfo
        .preferred_username
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| email.clone());

    // Find or create user
    let user = match db.get_user_by_email(&email).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            // Auto-provision: create user with no usable password (OIDC-only)
            let id = uuid::Uuid::new_v4().to_string();
            // Generate a random unusable password hash — the user cannot log in
            // with password auth because nobody knows this value.
            let unusable_hash = format!("!oidc!{}", uuid::Uuid::new_v4());
            if let Err(e) = db
                .insert_user(&id, &username, &email, &unusable_hash, false)
                .await
            {
                log::error!("Failed to auto-provision OIDC user: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "failed to create user account"})),
                );
            }
            log::info!("Auto-provisioned OIDC user: {} ({})", username, email);
            match db.get_user_by_id(&id).await {
                Ok(Some(row)) => row,
                _ => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(serde_json::json!({"error": "internal server error"})),
                    );
                }
            }
        }
        Err(e) => {
            log::error!("DB error looking up user by email: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };

    // Issue JWT
    let token = match create_token(&user.id, &user.email) {
        Ok(t) => t,
        Err(e) => {
            log::error!("JWT creation failed for OIDC user: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "access_token": token,
            "type": "Bearer",
            "user": {
                "id": user.id,
                "name": user.username,
                "email": user.email,
                "is_admin": user.is_admin != 0,
            }
        })),
    )
}

/// Generate a random state string. Exposed for testing.
pub fn generate_state() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    fn temp_db_path() -> String {
        format!("test_oidc_{}.sqlite3", uuid::Uuid::new_v4())
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_oidc_provider_crud() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Initially empty
        let providers = db.list_oidc_providers().await.unwrap();
        assert!(providers.is_empty());

        // Insert
        let id = uuid::Uuid::new_v4().to_string();
        db.insert_oidc_provider(
            &id,
            "TestIDP",
            "https://idp.example.com",
            "client123",
            "secret456",
            "openid profile email",
        )
        .await
        .unwrap();

        // List
        let providers = db.list_oidc_providers().await.unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].name, "TestIDP");
        assert_eq!(providers[0].issuer_url, "https://idp.example.com");
        assert_eq!(providers[0].client_id, "client123");
        assert_eq!(providers[0].client_secret, "secret456");
        assert_eq!(providers[0].scopes, "openid profile email");
        assert_eq!(providers[0].enabled, 1);

        // Get by ID
        let found = db.get_oidc_provider(&id).await.unwrap().unwrap();
        assert_eq!(found.name, "TestIDP");

        // Delete
        assert!(db.delete_oidc_provider(&id).await.unwrap());
        assert!(db.list_oidc_providers().await.unwrap().is_empty());

        // Delete non-existent
        assert!(!db.delete_oidc_provider(&id).await.unwrap());

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_oidc_provider_response_omits_secret() {
        let row = crate::database::OidcProviderRow {
            id: "p1".into(),
            name: "Test".into(),
            issuer_url: "https://idp.example.com".into(),
            client_id: "cid".into(),
            client_secret: "should-not-appear".into(),
            scopes: "openid".into(),
            enabled: 1,
            created_at: "2024-01-01".into(),
        };
        let resp = OidcProviderResponse::from(row);
        let json = serde_json::to_value(&resp).unwrap();
        assert!(
            json.get("client_secret").is_none(),
            "client_secret must not appear in OidcProviderResponse"
        );
    }

    #[test]
    fn test_state_store_insert_and_take() {
        let store = OidcStateStore::new();
        store.insert("state123".into(), "provider_abc".into());

        // First take succeeds
        assert_eq!(store.take("state123"), Some("provider_abc".to_string()));

        // Second take fails (single-use)
        assert_eq!(store.take("state123"), None);
    }

    #[test]
    fn test_state_store_unknown_state() {
        let store = OidcStateStore::new();
        assert_eq!(store.take("nonexistent"), None);
    }

    #[test]
    fn test_generate_state_uniqueness() {
        let s1 = generate_state();
        let s2 = generate_state();
        assert_ne!(s1, s2, "generated states should be unique");
        assert_eq!(s1.len(), 36, "UUID v4 string should be 36 chars");
    }

    #[tokio::test]
    async fn test_get_user_by_email() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // No user yet
        assert!(db.get_user_by_email("alice@test.com").await.unwrap().is_none());

        // Insert a user
        let id = uuid::Uuid::new_v4().to_string();
        db.insert_user(&id, "alice", "alice@test.com", "!nohash!", false)
            .await
            .unwrap();

        // Now findable by email
        let found = db.get_user_by_email("alice@test.com").await.unwrap().unwrap();
        assert_eq!(found.username, "alice");
        assert_eq!(found.id, id);

        cleanup(&db_path);
    }
}
