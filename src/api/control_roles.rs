use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    Json,
};
use hbb_common::log;
use serde::{Deserialize, Serialize};

use crate::api::auth::AuthUser;
use crate::api::roles;
use crate::database::Database;

// ---------------------------------------------------------------------------
// Control role model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlRole {
    pub id: String,
    pub name: String,
    pub keyboard_mouse: String,
    pub clipboard: String,
    pub file_transfer: String,
    pub audio: String,
    pub terminal: String,
    pub tunnel: String,
    pub recording: String,
    pub block_input: String,
    pub created_at: String,
}

impl From<crate::database::ControlRoleRow> for ControlRole {
    fn from(row: crate::database::ControlRoleRow) -> Self {
        ControlRole {
            id: row.id,
            name: row.name,
            keyboard_mouse: row.keyboard_mouse,
            clipboard: row.clipboard,
            file_transfer: row.file_transfer,
            audio: row.audio,
            terminal: row.terminal,
            tunnel: row.tunnel,
            recording: row.recording,
            block_input: row.block_input,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateControlRoleRequest {
    pub name: String,
    #[serde(default = "default_enable")]
    pub keyboard_mouse: String,
    #[serde(default = "default_enable")]
    pub clipboard: String,
    #[serde(default = "default_enable")]
    pub file_transfer: String,
    #[serde(default = "default_enable")]
    pub audio: String,
    #[serde(default = "default_enable")]
    pub terminal: String,
    #[serde(default = "default_enable")]
    pub tunnel: String,
    #[serde(default = "default_disable")]
    pub recording: String,
    #[serde(default = "default_enable")]
    pub block_input: String,
}

fn default_enable() -> String {
    "enable".to_string()
}

fn default_disable() -> String {
    "disable".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UpdateControlRoleRequest {
    pub name: Option<String>,
    pub keyboard_mouse: Option<String>,
    pub clipboard: Option<String>,
    pub file_transfer: Option<String>,
    pub audio: Option<String>,
    pub terminal: Option<String>,
    pub tunnel: Option<String>,
    pub recording: Option<String>,
    pub block_input: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct AssignControlRoleRequest {
    pub user_id: String,
    pub control_role_id: String,
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

const VALID_CONTROL_VALUES: &[&str] = &["enable", "disable", "client"];

fn validate_control_value(value: &str) -> bool {
    VALID_CONTROL_VALUES.contains(&value)
}

fn validate_create_request(req: &CreateControlRoleRequest) -> Option<&'static str> {
    if req.name.is_empty() {
        return Some("name is required");
    }
    let fields = [
        &req.keyboard_mouse,
        &req.clipboard,
        &req.file_transfer,
        &req.audio,
        &req.terminal,
        &req.tunnel,
        &req.recording,
        &req.block_input,
    ];
    for field in fields {
        if !validate_control_value(field) {
            return Some("control values must be 'enable', 'disable', or 'client'");
        }
    }
    None
}

fn validate_update_request(req: &UpdateControlRoleRequest) -> Option<&'static str> {
    let optional_fields = [
        &req.keyboard_mouse,
        &req.clipboard,
        &req.file_transfer,
        &req.audio,
        &req.terminal,
        &req.tunnel,
        &req.recording,
        &req.block_input,
    ];
    for field in optional_fields {
        if let Some(val) = field {
            if !validate_control_value(val) {
                return Some("control values must be 'enable', 'disable', or 'client'");
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/control-roles` -- create a new control role.
pub async fn create_control_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<CreateControlRoleRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::require_admin(&claims.user_id, &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    if let Some(err) = validate_create_request(&payload) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": err})),
        );
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = db
        .insert_control_role(
            &id,
            &payload.name,
            &payload.keyboard_mouse,
            &payload.clipboard,
            &payload.file_transfer,
            &payload.audio,
            &payload.terminal,
            &payload.tunnel,
            &payload.recording,
            &payload.block_input,
        )
        .await
    {
        log::error!("Failed to insert control role: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    let cr = ControlRole {
        id,
        name: payload.name,
        keyboard_mouse: payload.keyboard_mouse,
        clipboard: payload.clipboard,
        file_transfer: payload.file_transfer,
        audio: payload.audio,
        terminal: payload.terminal,
        tunnel: payload.tunnel,
        recording: payload.recording,
        block_input: payload.block_input,
        created_at: String::new(),
    };
    (StatusCode::CREATED, Json(serde_json::to_value(cr).unwrap()))
}

/// `GET /api/control-roles` -- list all control roles.
pub async fn list_control_roles(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::has_permission(&claims.user_id, "control_roles", "view", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "permission denied"})),
        );
    }

    match db.list_control_roles().await {
        Ok(rows) => {
            let crs: Vec<ControlRole> = rows.into_iter().map(ControlRole::from).collect();
            (StatusCode::OK, Json(serde_json::to_value(crs).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list control roles: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `GET /api/control-roles/:id` -- get control role by ID.
pub async fn get_control_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::has_permission(&claims.user_id, "control_roles", "view", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "permission denied"})),
        );
    }

    match db.get_control_role_by_id(&id).await {
        Ok(Some(row)) => {
            let cr = ControlRole::from(row);
            (StatusCode::OK, Json(serde_json::to_value(cr).unwrap()))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "control role not found"})),
        ),
        Err(e) => {
            log::error!("Failed to get control role: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `PUT /api/control-roles/:id` -- update a control role.
pub async fn update_control_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateControlRoleRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::require_admin(&claims.user_id, &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    if let Some(err) = validate_update_request(&payload) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": err})),
        );
    }

    match db
        .update_control_role(
            &id,
            payload.name.as_deref(),
            payload.keyboard_mouse.as_deref(),
            payload.clipboard.as_deref(),
            payload.file_transfer.as_deref(),
            payload.audio.as_deref(),
            payload.terminal.as_deref(),
            payload.tunnel.as_deref(),
            payload.recording.as_deref(),
            payload.block_input.as_deref(),
        )
        .await
    {
        Ok(true) => match db.get_control_role_by_id(&id).await {
            Ok(Some(row)) => {
                let cr = ControlRole::from(row);
                (StatusCode::OK, Json(serde_json::to_value(cr).unwrap()))
            }
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            ),
        },
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "control role not found"})),
        ),
        Err(e) => {
            log::error!("Failed to update control role: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `DELETE /api/control-roles/:id` -- delete a control role.
pub async fn delete_control_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::require_admin(&claims.user_id, &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    match db.delete_control_role(&id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "control role deleted"})),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "control role not found"})),
        ),
        Err(e) => {
            log::error!("Failed to delete control role: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `POST /api/control-roles/assign` -- assign a control role to a user.
pub async fn assign_control_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<AssignControlRoleRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::require_admin(&claims.user_id, &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    // Verify user exists
    match db.get_user_by_id(&payload.user_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "user not found"})),
            );
        }
        Err(e) => {
            log::error!("DB error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
        Ok(Some(_)) => {}
    }

    // Verify control role exists
    match db.get_control_role_by_id(&payload.control_role_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "control role not found"})),
            );
        }
        Err(e) => {
            log::error!("DB error: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
        Ok(Some(_)) => {}
    }

    if let Err(e) = db
        .assign_control_role_to_user(&payload.user_id, &payload.control_role_id)
        .await
    {
        log::error!("Failed to assign control role: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "control role assigned"})),
    )
}

/// `GET /api/control-roles/effective/:user_id` -- get effective control role for a user.
pub async fn get_effective_control_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(user_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Users can view their own effective control role; admins can view anyone's
    if claims.user_id != user_id
        && !roles::has_permission(&claims.user_id, "control_roles", "view", &db).await
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "permission denied"})),
        );
    }

    // Check direct user assignment first
    match db.get_user_control_role(&user_id).await {
        Ok(Some(row)) => {
            let cr = ControlRole::from(row);
            return (StatusCode::OK, Json(serde_json::to_value(cr).unwrap()));
        }
        Ok(None) => {
            // No control role assigned — return default (all enabled, recording disabled)
            let default = serde_json::json!({
                "id": "",
                "name": "default",
                "keyboard_mouse": "enable",
                "clipboard": "enable",
                "file_transfer": "enable",
                "audio": "enable",
                "terminal": "enable",
                "tunnel": "enable",
                "recording": "disable",
                "block_input": "enable",
                "created_at": ""
            });
            return (StatusCode::OK, Json(default));
        }
        Err(e) => {
            log::error!("Failed to get effective control role: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
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
        format!("test_control_roles_{}.sqlite3", uuid::Uuid::new_v4())
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_control_role_crud() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Create
        let id = uuid::Uuid::new_v4().to_string();
        db.insert_control_role(
            &id, "FullAccess", "enable", "enable", "enable", "enable", "enable", "enable",
            "disable", "enable",
        )
        .await
        .unwrap();

        // Read
        let cr = db.get_control_role_by_id(&id).await.unwrap().unwrap();
        assert_eq!(cr.name, "FullAccess");
        assert_eq!(cr.keyboard_mouse, "enable");
        assert_eq!(cr.recording, "disable");
        assert_eq!(cr.block_input, "enable");

        // Update
        db.update_control_role(
            &id,
            Some("RestrictedAccess"),
            Some("disable"),
            None,
            Some("disable"),
            None,
            None,
            None,
            Some("enable"),
            None,
        )
        .await
        .unwrap();

        let cr = db.get_control_role_by_id(&id).await.unwrap().unwrap();
        assert_eq!(cr.name, "RestrictedAccess");
        assert_eq!(cr.keyboard_mouse, "disable");
        assert_eq!(cr.file_transfer, "disable");
        assert_eq!(cr.recording, "enable");
        assert_eq!(cr.clipboard, "enable"); // unchanged

        // List
        let crs = db.list_control_roles().await.unwrap();
        assert_eq!(crs.len(), 1);

        // Delete
        assert!(db.delete_control_role(&id).await.unwrap());
        assert!(db.get_control_role_by_id(&id).await.unwrap().is_none());
        assert!(!db.delete_control_role(&id).await.unwrap());

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_assign_control_role_to_user() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Create user
        let user_id = uuid::Uuid::new_v4().to_string();
        let hash = bcrypt::hash("pass", 4).unwrap();
        db.insert_user(&user_id, "cruser", "cr@test.com", &hash, false)
            .await
            .unwrap();

        // Create control role
        let cr_id = uuid::Uuid::new_v4().to_string();
        db.insert_control_role(
            &cr_id,
            "ViewOnly",
            "disable",
            "disable",
            "disable",
            "enable",
            "disable",
            "disable",
            "disable",
            "disable",
        )
        .await
        .unwrap();

        // Assign
        db.assign_control_role_to_user(&user_id, &cr_id)
            .await
            .unwrap();

        // Verify
        let effective = db.get_user_control_role(&user_id).await.unwrap().unwrap();
        assert_eq!(effective.name, "ViewOnly");
        assert_eq!(effective.keyboard_mouse, "disable");
        assert_eq!(effective.audio, "enable");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_no_control_role_returns_none() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let result = db
            .get_user_control_role("nonexistent-user")
            .await
            .unwrap();
        assert!(result.is_none());

        cleanup(&db_path);
    }

    #[test]
    fn test_validate_control_values() {
        assert!(validate_control_value("enable"));
        assert!(validate_control_value("disable"));
        assert!(validate_control_value("client"));
        assert!(!validate_control_value("invalid"));
        assert!(!validate_control_value(""));
    }

    #[test]
    fn test_validate_create_request() {
        let valid = CreateControlRoleRequest {
            name: "Test".into(),
            keyboard_mouse: "enable".into(),
            clipboard: "disable".into(),
            file_transfer: "client".into(),
            audio: "enable".into(),
            terminal: "enable".into(),
            tunnel: "enable".into(),
            recording: "disable".into(),
            block_input: "enable".into(),
        };
        assert!(validate_create_request(&valid).is_none());

        let empty_name = CreateControlRoleRequest {
            name: "".into(),
            keyboard_mouse: "enable".into(),
            clipboard: "enable".into(),
            file_transfer: "enable".into(),
            audio: "enable".into(),
            terminal: "enable".into(),
            tunnel: "enable".into(),
            recording: "disable".into(),
            block_input: "enable".into(),
        };
        assert_eq!(validate_create_request(&empty_name), Some("name is required"));

        let bad_value = CreateControlRoleRequest {
            name: "Test".into(),
            keyboard_mouse: "invalid".into(),
            clipboard: "enable".into(),
            file_transfer: "enable".into(),
            audio: "enable".into(),
            terminal: "enable".into(),
            tunnel: "enable".into(),
            recording: "disable".into(),
            block_input: "enable".into(),
        };
        assert!(validate_create_request(&bad_value).is_some());
    }

    #[tokio::test]
    async fn test_control_role_reassignment_replaces() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Create user
        let user_id = uuid::Uuid::new_v4().to_string();
        let hash = bcrypt::hash("pass", 4).unwrap();
        db.insert_user(&user_id, "reassign", "re@test.com", &hash, false)
            .await
            .unwrap();

        // Create two control roles
        let cr1 = uuid::Uuid::new_v4().to_string();
        db.insert_control_role(
            &cr1, "Role1", "enable", "enable", "enable", "enable", "enable", "enable",
            "disable", "enable",
        )
        .await
        .unwrap();

        let cr2 = uuid::Uuid::new_v4().to_string();
        db.insert_control_role(
            &cr2, "Role2", "disable", "disable", "disable", "disable", "disable", "disable",
            "enable", "disable",
        )
        .await
        .unwrap();

        // Assign first
        db.assign_control_role_to_user(&user_id, &cr1)
            .await
            .unwrap();
        let eff = db.get_user_control_role(&user_id).await.unwrap().unwrap();
        assert_eq!(eff.name, "Role1");

        // Reassign to second (should replace)
        db.assign_control_role_to_user(&user_id, &cr2)
            .await
            .unwrap();
        let eff = db.get_user_control_role(&user_id).await.unwrap().unwrap();
        assert_eq!(eff.name, "Role2");

        cleanup(&db_path);
    }
}
