use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    Json,
};
use hbb_common::log;
use serde::{Deserialize, Serialize};

use crate::api::auth::{create_token, AuthUser};
use crate::api::roles;
use crate::database::Database;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateLdapConfigRequest {
    pub name: String,
    pub server_url: String,
    #[serde(default)]
    pub bind_dn: String,
    #[serde(default)]
    pub bind_password: String,
    pub base_dn: String,
    #[serde(default = "default_user_filter")]
    pub user_filter: String,
    #[serde(default = "default_email_attr")]
    pub email_attr: String,
    #[serde(default = "default_display_name_attr")]
    pub display_name_attr: String,
}

fn default_user_filter() -> String {
    "(&(objectClass=person)(uid=%s))".to_string()
}

fn default_email_attr() -> String {
    "mail".to_string()
}

fn default_display_name_attr() -> String {
    "cn".to_string()
}

/// Public LDAP config info (bind_password is never exposed).
#[derive(Debug, Serialize)]
pub struct LdapConfigResponse {
    pub id: String,
    pub name: String,
    pub server_url: String,
    pub bind_dn: String,
    pub base_dn: String,
    pub user_filter: String,
    pub email_attr: String,
    pub display_name_attr: String,
    pub enabled: bool,
    pub created_at: String,
}

impl From<crate::database::LdapConfigRow> for LdapConfigResponse {
    fn from(row: crate::database::LdapConfigRow) -> Self {
        LdapConfigResponse {
            id: row.id,
            name: row.name,
            server_url: row.server_url,
            bind_dn: row.bind_dn,
            base_dn: row.base_dn,
            user_filter: row.user_filter,
            email_attr: row.email_attr,
            display_name_attr: row.display_name_attr,
            enabled: row.enabled != 0,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct LdapLoginRequest {
    pub username: String,
    pub password: String,
    pub config_id: String,
}

#[derive(Debug, Deserialize)]
pub struct LdapSyncRequest {
    pub config_id: String,
}

// ---------------------------------------------------------------------------
// Stubbed LDAP client
// ---------------------------------------------------------------------------

/// Represents a user returned from an LDAP directory.
#[derive(Debug, Clone)]
pub struct LdapUser {
    pub dn: String,
    pub username: String,
    pub email: String,
    pub display_name: String,
}

/// Minimal LDAP client that encapsulates connection and bind logic.
///
/// The actual LDAP protocol implementation is stubbed out -- this struct
/// captures the full API surface so that swapping in a real LDAP library
/// (e.g. `ldap3`) requires only filling in the method bodies.
pub struct LdapClient {
    pub server_url: String,
    pub bind_dn: String,
    pub bind_password: String,
}

impl LdapClient {
    pub fn new(server_url: &str, bind_dn: &str, bind_password: &str) -> Self {
        Self {
            server_url: server_url.to_string(),
            bind_dn: bind_dn.to_string(),
            bind_password: bind_password.to_string(),
        }
    }

    /// Authenticate a user against the LDAP directory.
    ///
    /// The intended flow is:
    /// 1. Connect to the LDAP server at `self.server_url`.
    /// 2. Bind with the service account (`self.bind_dn` / `self.bind_password`).
    /// 3. Search for the user under `base_dn` using `filter` (with `%s`
    ///    replaced by the username).
    /// 4. Re-bind with the found user's DN + the provided `password` to
    ///    verify credentials.
    /// 5. Read and return the user's attributes (`email_attr`,
    ///    `display_name_attr`).
    ///
    /// Currently stubbed -- returns an error indicating that the `ldap3`
    /// crate (or equivalent) needs to be integrated.
    pub async fn authenticate(
        &self,
        username: &str,
        _password: &str,
        _base_dn: &str,
        _filter: &str,
        _email_attr: &str,
        _display_name_attr: &str,
    ) -> Result<LdapUser, String> {
        // TODO: Replace with real LDAP protocol implementation.
        // When the `ldap3` crate is added to Cargo.toml, fill in the five
        // steps described above.  The surrounding API handlers, user
        // provisioning, and JWT issuance are fully wired and will work
        // once this method returns `Ok(LdapUser { ... })`.
        log::warn!(
            "LDAP authenticate called for user '{}' against '{}' -- \
             protocol not yet implemented",
            username,
            self.server_url,
        );
        Err("LDAP protocol not yet implemented. \
             Add the ldap3 crate and implement LdapClient::authenticate."
            .to_string())
    }

    /// Search the LDAP directory and return all matching users.
    ///
    /// Used by the sync endpoint to bulk-import users.  Stubbed for now.
    pub async fn search_users(
        &self,
        _base_dn: &str,
        _filter: &str,
        _email_attr: &str,
        _display_name_attr: &str,
    ) -> Result<Vec<LdapUser>, String> {
        log::warn!(
            "LDAP search_users called against '{}' -- protocol not yet implemented",
            self.server_url,
        );
        Err("LDAP protocol not yet implemented. \
             Add the ldap3 crate and implement LdapClient::search_users."
            .to_string())
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/ldap/configs` -- list configured LDAP directories (public info only).
pub async fn list_configs(
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<serde_json::Value>) {
    match db.list_ldap_configs().await {
        Ok(rows) => {
            let configs: Vec<LdapConfigResponse> =
                rows.into_iter().map(LdapConfigResponse::from).collect();
            (StatusCode::OK, Json(serde_json::to_value(configs).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list LDAP configs: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `POST /api/ldap/configs` -- add a new LDAP config (admin only).
pub async fn create_config(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<CreateLdapConfigRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::has_permission(&claims.user_id, "users", "edit", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    if payload.name.is_empty() || payload.server_url.is_empty() || payload.base_dn.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "name, server_url, and base_dn are required"})),
        );
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = db
        .insert_ldap_config(
            &id,
            &payload.name,
            &payload.server_url,
            &payload.bind_dn,
            &payload.bind_password,
            &payload.base_dn,
            &payload.user_filter,
            &payload.email_attr,
            &payload.display_name_attr,
        )
        .await
    {
        log::error!("Failed to insert LDAP config: {}", e);
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

/// `DELETE /api/ldap/configs/:id` -- remove an LDAP config (admin only).
pub async fn delete_config(
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

    match db.delete_ldap_config(&id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "LDAP config deleted"})),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "LDAP config not found"})),
        ),
        Err(e) => {
            log::error!("Failed to delete LDAP config: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `POST /api/ldap/login` -- authenticate a user via LDAP and issue a JWT.
///
/// On successful LDAP authentication the user is auto-provisioned (or
/// updated) in the local database, mirroring the OIDC provisioning flow.
pub async fn login(
    Extension(db): Extension<Database>,
    Json(payload): Json<LdapLoginRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if payload.username.is_empty() || payload.password.is_empty() || payload.config_id.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "username, password, and config_id are required"})),
        );
    }

    // Load the LDAP config
    let config = match db.get_ldap_config(&payload.config_id).await {
        Ok(Some(c)) if c.enabled != 0 => c,
        Ok(Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "LDAP config is disabled"})),
            );
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "LDAP config not found"})),
            );
        }
        Err(e) => {
            log::error!("DB error fetching LDAP config: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };

    // Build the user filter with the username substituted in
    let filter = config.user_filter.replace("%s", &payload.username);

    // Attempt LDAP authentication
    let client = LdapClient::new(&config.server_url, &config.bind_dn, &config.bind_password);
    let ldap_user = match client
        .authenticate(
            &payload.username,
            &payload.password,
            &config.base_dn,
            &filter,
            &config.email_attr,
            &config.display_name_attr,
        )
        .await
    {
        Ok(u) => u,
        Err(e) => {
            log::warn!("LDAP authentication failed for '{}': {}", payload.username, e);
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": format!("LDAP authentication failed: {}", e)})),
            );
        }
    };

    // Find or create user (same pattern as OIDC provisioning)
    let user = match provision_ldap_user(&db, &ldap_user).await {
        Ok(u) => u,
        Err(e) => {
            log::error!("LDAP user provisioning failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to provision user account"})),
            );
        }
    };

    // Issue JWT
    let token = match create_token(&user.id, &user.email) {
        Ok(t) => t,
        Err(e) => {
            log::error!("JWT creation failed for LDAP user: {}", e);
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

/// `POST /api/ldap/sync` -- sync users from an LDAP directory (admin only).
///
/// Searches the LDAP directory using the configured filter and
/// auto-provisions any users not already present in the local database.
pub async fn sync_users(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<LdapSyncRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::has_permission(&claims.user_id, "users", "edit", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    let config = match db.get_ldap_config(&payload.config_id).await {
        Ok(Some(c)) if c.enabled != 0 => c,
        Ok(Some(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "LDAP config is disabled"})),
            );
        }
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "LDAP config not found"})),
            );
        }
        Err(e) => {
            log::error!("DB error fetching LDAP config for sync: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };

    // Use a broad filter for sync (the configured filter with wildcard)
    let sync_filter = config.user_filter.replace("%s", "*");

    let client = LdapClient::new(&config.server_url, &config.bind_dn, &config.bind_password);
    let ldap_users = match client
        .search_users(
            &config.base_dn,
            &sync_filter,
            &config.email_attr,
            &config.display_name_attr,
        )
        .await
    {
        Ok(users) => users,
        Err(e) => {
            log::error!("LDAP sync search failed: {}", e);
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": format!("LDAP search failed: {}", e)})),
            );
        }
    };

    let mut created = 0u64;
    let mut updated = 0u64;
    let mut errors = 0u64;

    for ldap_user in &ldap_users {
        match provision_ldap_user(&db, ldap_user).await {
            Ok(row) => {
                // Check if this was a new user or existing by seeing if
                // username changed (heuristic -- the provisioning function
                // handles both cases).
                if row.username == ldap_user.display_name {
                    updated += 1;
                } else {
                    created += 1;
                }
            }
            Err(e) => {
                log::warn!(
                    "Failed to provision LDAP user '{}': {}",
                    ldap_user.username,
                    e
                );
                errors += 1;
            }
        }
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "total": ldap_users.len(),
            "created": created,
            "updated": updated,
            "errors": errors,
        })),
    )
}

// ---------------------------------------------------------------------------
// User provisioning helper
// ---------------------------------------------------------------------------

/// Find or create a local user account for an LDAP user.
///
/// If a user with the same email already exists, their display name is
/// updated.  Otherwise a new user is created with an unusable password
/// hash (LDAP-only authentication).
async fn provision_ldap_user(
    db: &Database,
    ldap_user: &LdapUser,
) -> Result<crate::database::UserRow, String> {
    let email = if ldap_user.email.is_empty() {
        format!("{}@ldap", ldap_user.username)
    } else {
        ldap_user.email.clone()
    };

    match db.get_user_by_email(&email).await {
        Ok(Some(row)) => {
            // Update display name if it changed
            if row.username != ldap_user.display_name && !ldap_user.display_name.is_empty() {
                let _ = db
                    .update_user(&row.id, Some(&ldap_user.display_name), None, None, None)
                    .await;
            }
            Ok(row)
        }
        Ok(None) => {
            // Auto-provision: create user with unusable password (LDAP-only)
            let id = uuid::Uuid::new_v4().to_string();
            let unusable_hash = format!("!ldap!{}", uuid::Uuid::new_v4());
            let username = if ldap_user.display_name.is_empty() {
                &ldap_user.username
            } else {
                &ldap_user.display_name
            };

            db.insert_user(&id, username, &email, &unusable_hash, false)
                .await
                .map_err(|e| format!("failed to insert LDAP user: {}", e))?;

            log::info!(
                "Auto-provisioned LDAP user: {} ({})",
                username,
                email
            );

            db.get_user_by_id(&id)
                .await
                .map_err(|e| format!("failed to fetch provisioned user: {}", e))?
                .ok_or_else(|| "provisioned user not found after insert".to_string())
        }
        Err(e) => Err(format!("DB error looking up user by email: {}", e)),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use hbb_common::tokio;

    fn temp_db_path() -> String {
        format!("test_ldap_{}.sqlite3", uuid::Uuid::new_v4())
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_ldap_config_crud() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Initially empty
        let configs = db.list_ldap_configs().await.unwrap();
        assert!(configs.is_empty());

        // Insert
        let id = uuid::Uuid::new_v4().to_string();
        db.insert_ldap_config(
            &id,
            "Corporate AD",
            "ldaps://ad.example.com:636",
            "cn=svc,dc=example,dc=com",
            "secret123",
            "dc=example,dc=com",
            "(&(objectClass=person)(sAMAccountName=%s))",
            "mail",
            "displayName",
        )
        .await
        .unwrap();

        // List
        let configs = db.list_ldap_configs().await.unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].name, "Corporate AD");
        assert_eq!(configs[0].server_url, "ldaps://ad.example.com:636");
        assert_eq!(configs[0].bind_dn, "cn=svc,dc=example,dc=com");
        assert_eq!(configs[0].base_dn, "dc=example,dc=com");
        assert_eq!(
            configs[0].user_filter,
            "(&(objectClass=person)(sAMAccountName=%s))"
        );
        assert_eq!(configs[0].email_attr, "mail");
        assert_eq!(configs[0].display_name_attr, "displayName");
        assert_eq!(configs[0].enabled, 1);

        // Get by ID
        let found = db.get_ldap_config(&id).await.unwrap().unwrap();
        assert_eq!(found.name, "Corporate AD");
        assert_eq!(found.bind_password, "secret123");

        // Delete
        assert!(db.delete_ldap_config(&id).await.unwrap());
        assert!(db.list_ldap_configs().await.unwrap().is_empty());

        // Delete non-existent
        assert!(!db.delete_ldap_config(&id).await.unwrap());

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_ldap_config_response_omits_bind_password() {
        let row = crate::database::LdapConfigRow {
            id: "c1".into(),
            name: "Test".into(),
            server_url: "ldap://localhost".into(),
            bind_dn: "cn=admin".into(),
            bind_password: "should-not-appear".into(),
            base_dn: "dc=test".into(),
            user_filter: "(uid=%s)".into(),
            email_attr: "mail".into(),
            display_name_attr: "cn".into(),
            enabled: 1,
            created_at: "2024-01-01".into(),
        };
        let resp = LdapConfigResponse::from(row);
        let json = serde_json::to_value(&resp).unwrap();
        assert!(
            json.get("bind_password").is_none(),
            "bind_password must not appear in LdapConfigResponse"
        );
    }

    #[tokio::test]
    async fn test_ldap_user_provisioning() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let ldap_user = LdapUser {
            dn: "cn=alice,dc=example,dc=com".into(),
            username: "alice".into(),
            email: "alice@example.com".into(),
            display_name: "Alice Smith".into(),
        };

        // First call creates the user
        let user = provision_ldap_user(&db, &ldap_user).await.unwrap();
        assert_eq!(user.username, "Alice Smith");
        assert_eq!(user.email, "alice@example.com");
        assert_eq!(user.is_admin, 0);
        assert!(
            user.password_hash.starts_with("!ldap!"),
            "LDAP users should have unusable password hash"
        );

        // Second call finds the existing user
        let user2 = provision_ldap_user(&db, &ldap_user).await.unwrap();
        assert_eq!(user.id, user2.id, "should return the same user");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_ldap_client_authenticate_stub() {
        let client = LdapClient::new("ldap://localhost", "cn=admin", "pass");
        let result = client
            .authenticate("alice", "pass", "dc=test", "(uid=alice)", "mail", "cn")
            .await;
        assert!(
            result.is_err(),
            "stub should return error until ldap3 is integrated"
        );
    }

    #[tokio::test]
    async fn test_ldap_client_search_stub() {
        let client = LdapClient::new("ldap://localhost", "cn=admin", "pass");
        let result = client
            .search_users("dc=test", "(objectClass=person)", "mail", "cn")
            .await;
        assert!(
            result.is_err(),
            "stub should return error until ldap3 is integrated"
        );
    }

    #[test]
    fn test_ldap_user_filter_substitution() {
        let filter = "(&(objectClass=person)(sAMAccountName=%s))";
        let result = filter.replace("%s", "jdoe");
        assert_eq!(result, "(&(objectClass=person)(sAMAccountName=jdoe))");
    }
}
