use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    Json,
};
use hbb_common::log;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::api::auth::AuthUser;
use crate::database::Database;

// ---------------------------------------------------------------------------
// Role model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    pub id: String,
    pub name: String,
    pub scope: String,
    pub permissions: HashMap<String, String>,
    pub created_at: String,
}

impl From<crate::database::RoleRow> for Role {
    fn from(row: crate::database::RoleRow) -> Self {
        let permissions: HashMap<String, String> =
            serde_json::from_str(&row.permissions).unwrap_or_default();
        Role {
            id: row.id,
            name: row.name,
            scope: row.scope,
            permissions,
            created_at: row.created_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default)]
    pub permissions: HashMap<String, String>,
}

fn default_scope() -> String {
    "individual".to_string()
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub scope: Option<String>,
    pub permissions: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
pub struct AssignRoleRequest {
    pub user_id: String,
    pub role_id: String,
}

#[derive(Debug, Deserialize)]
pub struct RemoveRoleRequest {
    pub user_id: String,
    pub role_id: String,
}

// ---------------------------------------------------------------------------
// Default role initialization
// ---------------------------------------------------------------------------

/// Permissions for the Admin role: full access to everything.
fn admin_permissions() -> HashMap<String, String> {
    let mut p = HashMap::new();
    p.insert("users".into(), "edit".into());
    p.insert("devices".into(), "edit".into());
    p.insert("audit".into(), "edit".into());
    p.insert("strategies".into(), "edit".into());
    p.insert("groups".into(), "edit".into());
    p.insert("address_book".into(), "edit".into());
    p.insert("roles".into(), "edit".into());
    p.insert("control_roles".into(), "edit".into());
    p
}

/// Permissions for the Operator role: device + user management within groups.
fn operator_permissions() -> HashMap<String, String> {
    let mut p = HashMap::new();
    p.insert("users".into(), "view".into());
    p.insert("devices".into(), "edit".into());
    p.insert("audit".into(), "view".into());
    p.insert("strategies".into(), "view".into());
    p.insert("groups".into(), "edit".into());
    p.insert("address_book".into(), "edit".into());
    p.insert("roles".into(), "view".into());
    p.insert("control_roles".into(), "view".into());
    p
}

/// Permissions for the Viewer role: read-only access to own data.
fn viewer_permissions() -> HashMap<String, String> {
    let mut p = HashMap::new();
    p.insert("users".into(), "view".into());
    p.insert("devices".into(), "view".into());
    p.insert("audit".into(), "none".into());
    p.insert("strategies".into(), "none".into());
    p.insert("groups".into(), "view".into());
    p.insert("address_book".into(), "view".into());
    p.insert("roles".into(), "none".into());
    p.insert("control_roles".into(), "none".into());
    p
}

/// Initialize default roles (Admin, Operator, Viewer) if they don't exist.
pub async fn init_default_roles(db: &Database) {
    let defaults = vec![
        ("Admin", "global", admin_permissions()),
        ("Operator", "group", operator_permissions()),
        ("Viewer", "individual", viewer_permissions()),
    ];

    for (name, scope, perms) in defaults {
        match db.get_role_by_name(name).await {
            Ok(Some(_)) => continue,
            Ok(None) => {}
            Err(e) => {
                log::error!("Failed to check for default role '{}': {}", name, e);
                continue;
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        let perms_json = serde_json::to_string(&perms).unwrap_or_else(|_| "{}".to_string());
        if let Err(e) = db.insert_role(&id, name, scope, &perms_json).await {
            log::error!("Failed to create default role '{}': {}", name, e);
        } else {
            log::info!("Default role '{}' created (scope={})", name, scope);
        }
    }
}

// ---------------------------------------------------------------------------
// Permission checking
// ---------------------------------------------------------------------------

/// Check if a user has the required permission level for a given resource.
///
/// Permission levels: "edit" > "view" > "none"
/// A user with "edit" automatically satisfies a "view" requirement.
///
/// If the user has the legacy `is_admin` flag set, they have full access.
/// Otherwise, permissions are determined by the user's assigned roles.
pub async fn has_permission(
    user_id: &str,
    resource: &str,
    action: &str,
    db: &Database,
) -> bool {
    // Check legacy is_admin flag first for backwards compatibility
    if let Ok(Some(user_row)) = db.get_user_by_id(user_id).await {
        if user_row.is_admin != 0 {
            return true;
        }
    }

    // Check role-based permissions
    let roles = match db.get_user_roles(user_id).await {
        Ok(r) => r,
        Err(_) => return false,
    };

    for role_row in roles {
        let role = Role::from(role_row);
        if let Some(perm_level) = role.permissions.get(resource) {
            if permission_satisfies(perm_level, action) {
                return true;
            }
        }
    }

    false
}

/// Check if `has_level` satisfies `required_level`.
/// "edit" satisfies both "edit" and "view".
/// "view" satisfies only "view".
/// "none" satisfies nothing.
fn permission_satisfies(has_level: &str, required_level: &str) -> bool {
    match required_level {
        "view" => has_level == "view" || has_level == "edit",
        "edit" => has_level == "edit",
        _ => false,
    }
}

/// Check admin-level permission: user must have "edit" on "roles" resource
/// (i.e., they are an Admin or have explicit roles management permission).
pub async fn require_admin(user_id: &str, db: &Database) -> bool {
    has_permission(user_id, "roles", "edit", db).await
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/roles` -- create a new role.
pub async fn create_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<CreateRoleRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_admin(&claims.user_id, &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    if payload.name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "name is required"})),
        );
    }

    // Validate scope
    if !["global", "individual", "group"].contains(&payload.scope.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "scope must be 'global', 'individual', or 'group'"})),
        );
    }

    // Check for duplicate name
    match db.get_role_by_name(&payload.name).await {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "role name already exists"})),
            );
        }
        Err(e) => {
            log::error!("DB error checking role name: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
        Ok(None) => {}
    }

    let id = uuid::Uuid::new_v4().to_string();
    let perms_json = serde_json::to_string(&payload.permissions)
        .unwrap_or_else(|_| "{}".to_string());

    if let Err(e) = db.insert_role(&id, &payload.name, &payload.scope, &perms_json).await {
        log::error!("Failed to insert role: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    let role = Role {
        id,
        name: payload.name,
        scope: payload.scope,
        permissions: payload.permissions,
        created_at: String::new(),
    };
    (StatusCode::CREATED, Json(serde_json::to_value(role).unwrap()))
}

/// `GET /api/roles` -- list all roles.
pub async fn list_roles(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !has_permission(&claims.user_id, "roles", "view", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "permission denied"})),
        );
    }

    match db.list_roles().await {
        Ok(rows) => {
            let roles: Vec<Role> = rows.into_iter().map(Role::from).collect();
            (StatusCode::OK, Json(serde_json::to_value(roles).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list roles: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `GET /api/roles/:id` -- get role by ID.
pub async fn get_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !has_permission(&claims.user_id, "roles", "view", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "permission denied"})),
        );
    }

    match db.get_role_by_id(&id).await {
        Ok(Some(row)) => {
            let role = Role::from(row);
            (StatusCode::OK, Json(serde_json::to_value(role).unwrap()))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "role not found"})),
        ),
        Err(e) => {
            log::error!("Failed to get role: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `PUT /api/roles/:id` -- update a role.
pub async fn update_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateRoleRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_admin(&claims.user_id, &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    // Validate scope if provided
    if let Some(ref scope) = payload.scope {
        if !["global", "individual", "group"].contains(&scope.as_str()) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "scope must be 'global', 'individual', or 'group'"})),
            );
        }
    }

    let perms_json = payload
        .permissions
        .as_ref()
        .map(|p| serde_json::to_string(p).unwrap_or_else(|_| "{}".to_string()));

    match db
        .update_role(
            &id,
            payload.name.as_deref(),
            payload.scope.as_deref(),
            perms_json.as_deref(),
        )
        .await
    {
        Ok(true) => {
            match db.get_role_by_id(&id).await {
                Ok(Some(row)) => {
                    let role = Role::from(row);
                    (StatusCode::OK, Json(serde_json::to_value(role).unwrap()))
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal server error"})),
                ),
            }
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "role not found"})),
        ),
        Err(e) => {
            log::error!("Failed to update role: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `DELETE /api/roles/:id` -- delete a role.
pub async fn delete_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_admin(&claims.user_id, &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    match db.delete_role(&id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "role deleted"})),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "role not found"})),
        ),
        Err(e) => {
            log::error!("Failed to delete role: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `POST /api/roles/assign` -- assign a role to a user.
pub async fn assign_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<AssignRoleRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_admin(&claims.user_id, &db).await {
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

    // Verify role exists
    match db.get_role_by_id(&payload.role_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "role not found"})),
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

    if let Err(e) = db.assign_role_to_user(&payload.user_id, &payload.role_id).await {
        log::error!("Failed to assign role: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "role assigned"})),
    )
}

/// `POST /api/roles/remove` -- remove a role from a user.
pub async fn remove_role(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<RemoveRoleRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !require_admin(&claims.user_id, &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    match db.remove_role_from_user(&payload.user_id, &payload.role_id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "role removed"})),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "assignment not found"})),
        ),
        Err(e) => {
            log::error!("Failed to remove role: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `GET /api/roles/user/:user_id` -- get roles assigned to a user.
pub async fn get_user_roles(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(user_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Users can view their own roles; admins can view anyone's
    if claims.user_id != user_id && !require_admin(&claims.user_id, &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "permission denied"})),
        );
    }

    match db.get_user_roles(&user_id).await {
        Ok(rows) => {
            let roles: Vec<Role> = rows.into_iter().map(Role::from).collect();
            (StatusCode::OK, Json(serde_json::to_value(roles).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to get user roles: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
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
    use hbb_common::tokio;

    fn temp_db_path() -> String {
        format!("test_roles_{}.sqlite3", uuid::Uuid::new_v4())
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_default_roles_created() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        init_default_roles(&db).await;

        let roles = db.list_roles().await.unwrap();
        assert_eq!(roles.len(), 3, "should have Admin, Operator, Viewer");

        let names: Vec<&str> = roles.iter().map(|r| r.name.as_str()).collect();
        assert!(names.contains(&"Admin"));
        assert!(names.contains(&"Operator"));
        assert!(names.contains(&"Viewer"));

        // Check Admin scope
        let admin_role = roles.iter().find(|r| r.name == "Admin").unwrap();
        assert_eq!(admin_role.scope, "global");

        // Check Operator scope
        let op_role = roles.iter().find(|r| r.name == "Operator").unwrap();
        assert_eq!(op_role.scope, "group");

        // Check Viewer scope
        let viewer_role = roles.iter().find(|r| r.name == "Viewer").unwrap();
        assert_eq!(viewer_role.scope, "individual");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_default_roles_idempotent() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        init_default_roles(&db).await;
        init_default_roles(&db).await; // call again

        let roles = db.list_roles().await.unwrap();
        assert_eq!(roles.len(), 3, "should still have exactly 3 default roles");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_role_crud() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Create
        let id = uuid::Uuid::new_v4().to_string();
        let mut perms = HashMap::new();
        perms.insert("users".to_string(), "view".to_string());
        let perms_json = serde_json::to_string(&perms).unwrap();
        db.insert_role(&id, "TestRole", "group", &perms_json)
            .await
            .unwrap();

        // Read
        let role = db.get_role_by_id(&id).await.unwrap().unwrap();
        assert_eq!(role.name, "TestRole");
        assert_eq!(role.scope, "group");

        // Read by name
        let role = db.get_role_by_name("TestRole").await.unwrap().unwrap();
        assert_eq!(role.id, id);

        // Update
        db.update_role(&id, Some("UpdatedRole"), Some("global"), None)
            .await
            .unwrap();
        let role = db.get_role_by_id(&id).await.unwrap().unwrap();
        assert_eq!(role.name, "UpdatedRole");
        assert_eq!(role.scope, "global");

        // List
        let roles = db.list_roles().await.unwrap();
        assert_eq!(roles.len(), 1);

        // Delete
        assert!(db.delete_role(&id).await.unwrap());
        assert!(db.get_role_by_id(&id).await.unwrap().is_none());
        assert!(!db.delete_role(&id).await.unwrap()); // already deleted

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_assign_and_get_user_roles() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Create a user
        let user_id = uuid::Uuid::new_v4().to_string();
        let hash = bcrypt::hash("pass", 4).unwrap();
        db.insert_user(&user_id, "roleuser", "role@test.com", &hash, false)
            .await
            .unwrap();

        // Create a role
        let role_id = uuid::Uuid::new_v4().to_string();
        db.insert_role(&role_id, "CustomRole", "group", r#"{"users":"view"}"#)
            .await
            .unwrap();

        // Assign
        db.assign_role_to_user(&user_id, &role_id).await.unwrap();

        // Get user roles
        let roles = db.get_user_roles(&user_id).await.unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(roles[0].name, "CustomRole");

        // Remove
        assert!(db.remove_role_from_user(&user_id, &role_id).await.unwrap());
        let roles = db.get_user_roles(&user_id).await.unwrap();
        assert_eq!(roles.len(), 0);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_permission_checking_with_roles() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();
        init_default_roles(&db).await;

        // Create a non-admin user
        let user_id = uuid::Uuid::new_v4().to_string();
        let hash = bcrypt::hash("pass", 4).unwrap();
        db.insert_user(&user_id, "permuser", "perm@test.com", &hash, false)
            .await
            .unwrap();

        // Without any role, user should have no permissions
        assert!(!has_permission(&user_id, "users", "view", &db).await);
        assert!(!has_permission(&user_id, "users", "edit", &db).await);

        // Assign Viewer role
        let viewer = db.get_role_by_name("Viewer").await.unwrap().unwrap();
        db.assign_role_to_user(&user_id, &viewer.id).await.unwrap();

        // Viewer has "view" on users, so "view" should pass, "edit" should fail
        assert!(has_permission(&user_id, "users", "view", &db).await);
        assert!(!has_permission(&user_id, "users", "edit", &db).await);

        // Viewer has "none" on audit, so both should fail
        assert!(!has_permission(&user_id, "audit", "view", &db).await);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_permission_checking_is_admin_override() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Create an admin user (legacy is_admin flag)
        let user_id = uuid::Uuid::new_v4().to_string();
        let hash = bcrypt::hash("pass", 4).unwrap();
        db.insert_user(&user_id, "legacyadmin", "la@test.com", &hash, true)
            .await
            .unwrap();

        // Admin should have access to everything, even without explicit roles
        assert!(has_permission(&user_id, "users", "edit", &db).await);
        assert!(has_permission(&user_id, "roles", "edit", &db).await);
        assert!(has_permission(&user_id, "audit", "edit", &db).await);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_permission_edit_satisfies_view() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();
        init_default_roles(&db).await;

        // Create user and assign Admin role (has "edit" on everything)
        let user_id = uuid::Uuid::new_v4().to_string();
        let hash = bcrypt::hash("pass", 4).unwrap();
        db.insert_user(&user_id, "edituser", "eu@test.com", &hash, false)
            .await
            .unwrap();

        let admin_role = db.get_role_by_name("Admin").await.unwrap().unwrap();
        db.assign_role_to_user(&user_id, &admin_role.id).await.unwrap();

        // "edit" should satisfy "view"
        assert!(has_permission(&user_id, "users", "view", &db).await);
        assert!(has_permission(&user_id, "users", "edit", &db).await);

        cleanup(&db_path);
    }

    #[test]
    fn test_permission_satisfies_logic() {
        // "edit" satisfies "edit"
        assert!(permission_satisfies("edit", "edit"));
        // "edit" satisfies "view"
        assert!(permission_satisfies("edit", "view"));
        // "view" satisfies "view"
        assert!(permission_satisfies("view", "view"));
        // "view" does NOT satisfy "edit"
        assert!(!permission_satisfies("view", "edit"));
        // "none" satisfies nothing
        assert!(!permission_satisfies("none", "view"));
        assert!(!permission_satisfies("none", "edit"));
    }

    #[tokio::test]
    async fn test_duplicate_role_name_rejected() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let id1 = uuid::Uuid::new_v4().to_string();
        db.insert_role(&id1, "DupRole", "global", "{}").await.unwrap();

        let id2 = uuid::Uuid::new_v4().to_string();
        let result = db.insert_role(&id2, "DupRole", "global", "{}").await;
        assert!(result.is_err(), "duplicate role name should be rejected");

        cleanup(&db_path);
    }
}
