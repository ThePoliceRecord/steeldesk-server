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
// User model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub email: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub is_admin: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub is_admin: bool,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub is_admin: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
    pub is_admin: bool,
}

impl From<&User> for UserResponse {
    fn from(u: &User) -> Self {
        UserResponse {
            id: u.id.clone(),
            username: u.username.clone(),
            email: u.email.clone(),
            is_admin: u.is_admin,
        }
    }
}

impl From<crate::database::UserRow> for User {
    fn from(row: crate::database::UserRow) -> Self {
        User {
            id: row.id,
            username: row.username,
            email: row.email,
            password_hash: row.password_hash,
            is_admin: row.is_admin != 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Default admin initialization
// ---------------------------------------------------------------------------

/// Initialize the default admin user in the database. Must be called at startup.
pub async fn init_default_admin(db: &Database) {
    match db.get_user_by_username("admin").await {
        Ok(Some(_)) => return, // already exists
        Ok(None) => {}
        Err(e) => {
            log::error!("Failed to check for default admin: {}", e);
            return;
        }
    }
    let hash = bcrypt::hash("admin123", bcrypt::DEFAULT_COST)
        .expect("bcrypt hash should not fail for default admin password");
    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = db
        .insert_user(&id, "admin", "admin@rustdesk.local", &hash, true)
        .await
    {
        log::error!("Failed to create default admin: {}", e);
        return;
    }
    log::warn!("Default admin user created (admin / admin123) -- change the password!");
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/users` -- create a new user.
pub async fn create_user(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<CreateUserRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Only users with "edit" permission on "users" can create users
    if !roles::has_permission(&claims.user_id, "users", "edit", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    if payload.username.is_empty() || payload.email.is_empty() || payload.password.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "username, email, and password are required"})),
        );
    }

    // Check for duplicate username
    match db.get_user_by_username(&payload.username).await {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({"error": "username already exists"})),
            );
        }
        Err(e) => {
            log::error!("DB error checking username: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
        Ok(None) => {}
    }

    let hash = match bcrypt::hash(&payload.password, bcrypt::DEFAULT_COST) {
        Ok(h) => h,
        Err(e) => {
            log::error!("bcrypt hash failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };

    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = db
        .insert_user(&id, &payload.username, &payload.email, &hash, payload.is_admin)
        .await
    {
        log::error!("Failed to insert user: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    let user = User {
        id,
        username: payload.username,
        email: payload.email,
        password_hash: hash,
        is_admin: payload.is_admin,
    };
    let resp = UserResponse::from(&user);
    (StatusCode::CREATED, Json(serde_json::to_value(resp).unwrap()))
}

/// `GET /api/users` -- list all users (requires "view" permission on "users").
pub async fn list_users(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::has_permission(&claims.user_id, "users", "view", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    match db.list_users().await {
        Ok(rows) => {
            let users: Vec<UserResponse> = rows
                .iter()
                .map(|row| {
                    let u = User::from(row.clone());
                    UserResponse::from(&u)
                })
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(users).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list users: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `GET /api/users/:id` -- get user by ID.
pub async fn get_user(
    AuthUser(_claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match db.get_user_by_id(&id).await {
        Ok(Some(row)) => {
            let user = User::from(row);
            let resp = UserResponse::from(&user);
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "user not found"})),
        ),
        Err(e) => {
            log::error!("Failed to get user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `PUT /api/users/:id` -- update user.
pub async fn update_user(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateUserRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Users can update themselves; users with "edit" permission on "users" can update anyone
    if claims.user_id != id
        && !roles::has_permission(&claims.user_id, "users", "edit", &db).await
    {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    let new_hash = match &payload.password {
        Some(password) => match bcrypt::hash(password, bcrypt::DEFAULT_COST) {
            Ok(h) => Some(h),
            Err(e) => {
                log::error!("bcrypt hash failed: {}", e);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal server error"})),
                );
            }
        },
        None => None,
    };

    match db
        .update_user(
            &id,
            payload.username.as_deref(),
            payload.email.as_deref(),
            new_hash.as_deref(),
            payload.is_admin,
        )
        .await
    {
        Ok(true) => {
            // Fetch the updated user
            match db.get_user_by_id(&id).await {
                Ok(Some(row)) => {
                    let user = User::from(row);
                    let resp = UserResponse::from(&user);
                    (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({"error": "internal server error"})),
                ),
            }
        }
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "user not found"})),
        ),
        Err(e) => {
            log::error!("Failed to update user: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `DELETE /api/users/:id` -- delete user.
pub async fn delete_user(
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

    match db.delete_user(&id).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"message": "user deleted"}))),
        Ok(false) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "user not found"}))),
        Err(e) => {
            log::error!("Failed to delete user: {}", e);
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
        format!("test_users_{}.sqlite3", uuid::Uuid::new_v4())
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_user_crud_persists() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Insert
        let hash = bcrypt::hash("pass123", 4).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        db.insert_user(&id, "alice", "alice@test.com", &hash, false)
            .await
            .unwrap();

        // Find by username
        let found = db.get_user_by_username("alice").await.unwrap().unwrap();
        assert_eq!(found.username, "alice");
        assert_eq!(found.email, "alice@test.com");
        assert_eq!(found.is_admin, 0);

        // Find by id
        let found = db.get_user_by_id(&id).await.unwrap().unwrap();
        assert_eq!(found.username, "alice");

        // Update
        db.update_user(&id, Some("alice_updated"), None, None, Some(true))
            .await
            .unwrap();
        let found = db.get_user_by_id(&id).await.unwrap().unwrap();
        assert_eq!(found.username, "alice_updated");
        assert_eq!(found.is_admin, 1);
        assert_eq!(found.email, "alice@test.com"); // unchanged

        // Delete
        assert!(db.delete_user(&id).await.unwrap());
        assert!(db.get_user_by_id(&id).await.unwrap().is_none());
        assert!(!db.delete_user(&id).await.unwrap()); // already deleted

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_user_list() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let hash = bcrypt::hash("pass", 4).unwrap();
        for name in &["user1", "user2", "user3"] {
            let id = uuid::Uuid::new_v4().to_string();
            db.insert_user(&id, name, &format!("{}@test.com", name), &hash, false)
                .await
                .unwrap();
        }

        let users = db.list_users().await.unwrap();
        assert_eq!(users.len(), 3);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_default_admin_creation() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        init_default_admin(&db).await;
        let admin = db.get_user_by_username("admin").await.unwrap().unwrap();
        assert_eq!(admin.is_admin, 1);
        assert_eq!(admin.email, "admin@rustdesk.local");
        assert!(bcrypt::verify("admin123", &admin.password_hash).unwrap());

        // Idempotent: calling again should not create a duplicate
        init_default_admin(&db).await;
        let users = db.list_users().await.unwrap();
        assert_eq!(users.len(), 1, "should not create duplicate admin");

        cleanup(&db_path);
    }

    #[test]
    fn test_user_response_omits_password_hash() {
        let user = User {
            id: "1".into(),
            username: "test".into(),
            email: "test@test.com".into(),
            password_hash: "secret".into(),
            is_admin: false,
        };
        let json = serde_json::to_value(&user).unwrap();
        assert!(json.get("password_hash").is_none(), "password_hash should not be serialized");
    }

    #[test]
    fn test_bcrypt_verify_correct_password() {
        let hash = bcrypt::hash("mypassword", 4).unwrap();
        assert!(bcrypt::verify("mypassword", &hash).unwrap());
    }

    #[test]
    fn test_bcrypt_verify_wrong_password() {
        let hash = bcrypt::hash("mypassword", 4).unwrap();
        assert!(!bcrypt::verify("wrongpassword", &hash).unwrap());
    }

    #[tokio::test]
    async fn test_duplicate_username_rejected() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let hash = bcrypt::hash("pass", 4).unwrap();
        let id1 = uuid::Uuid::new_v4().to_string();
        db.insert_user(&id1, "dupuser", "d@test.com", &hash, false)
            .await
            .unwrap();

        let id2 = uuid::Uuid::new_v4().to_string();
        let result = db
            .insert_user(&id2, "dupuser", "d2@test.com", &hash, false)
            .await;
        assert!(result.is_err(), "duplicate username should be rejected");

        cleanup(&db_path);
    }
}
