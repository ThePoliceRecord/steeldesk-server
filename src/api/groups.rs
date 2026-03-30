use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    Json,
};
use hbb_common::log;
use serde::{Deserialize, Serialize};

use crate::api::auth::AuthUser;
use crate::api::users::User;
use crate::database::Database;

// ---------------------------------------------------------------------------
// Group models
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupResponse {
    pub id: String,
    pub name: String,
    pub parent_id: String,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateGroupRequest {
    pub name: String,
    #[serde(default)]
    pub parent_id: String,
}

#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub id: String,
}

#[derive(Debug, Serialize)]
pub struct MemberResponse {
    pub id: String,
    pub group_id: String,
}

// ---------------------------------------------------------------------------
// Admin check helper
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
// User group handlers
// ---------------------------------------------------------------------------

/// `POST /api/user-groups` -- create a user group.
pub async fn create_user_group(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<CreateGroupRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    if payload.name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "name is required"})),
        );
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = db.insert_user_group(&id, &payload.name, &payload.parent_id).await {
        log::error!("Failed to create user group: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    let resp = GroupResponse {
        id,
        name: payload.name,
        parent_id: payload.parent_id,
        created_at: String::new(),
    };
    (StatusCode::CREATED, Json(serde_json::to_value(resp).unwrap()))
}

/// `GET /api/user-groups` -- list user groups.
pub async fn list_user_groups(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.list_user_groups().await {
        Ok(rows) => {
            let groups: Vec<GroupResponse> = rows
                .iter()
                .map(|r| GroupResponse {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    parent_id: r.parent_id.clone(),
                    created_at: r.created_at.clone(),
                })
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(groups).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list user groups: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `DELETE /api/user-groups/:id` -- delete a user group.
pub async fn delete_user_group(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.delete_user_group(&id).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"message": "group deleted"}))),
        Ok(false) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "group not found"}))),
        Err(e) => {
            log::error!("Failed to delete user group: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `POST /api/user-groups/:id/members` -- add user to group.
pub async fn add_user_group_member(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(group_id): Path<String>,
    Json(payload): Json<AddMemberRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    // Verify the group exists
    match db.get_user_group_by_id(&group_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "group not found"})),
            );
        }
        Err(e) => {
            log::error!("Failed to check group: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
        Ok(Some(_)) => {}
    }

    if let Err(e) = db.add_user_to_group(&payload.id, &group_id).await {
        log::error!("Failed to add user to group: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "user added to group"})),
    )
}

/// `DELETE /api/user-groups/:id/members/:user_id` -- remove user from group.
pub async fn remove_user_group_member(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path((group_id, user_id)): Path<(String, String)>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.remove_user_from_group(&user_id, &group_id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "user removed from group"})),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "membership not found"})),
        ),
        Err(e) => {
            log::error!("Failed to remove user from group: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `GET /api/user-groups/:id/members` -- list group members.
pub async fn list_user_group_members(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(group_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.list_user_group_members(&group_id).await {
        Ok(rows) => {
            let members: Vec<MemberResponse> = rows
                .iter()
                .map(|r| MemberResponse {
                    id: r.user_id.clone(),
                    group_id: r.group_id.clone(),
                })
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(members).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list group members: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Device group handlers
// ---------------------------------------------------------------------------

/// `POST /api/device-groups` -- create a device group.
pub async fn create_device_group(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<CreateGroupRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    if payload.name.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "name is required"})),
        );
    }

    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = db.insert_device_group(&id, &payload.name, &payload.parent_id).await {
        log::error!("Failed to create device group: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    let resp = GroupResponse {
        id,
        name: payload.name,
        parent_id: payload.parent_id,
        created_at: String::new(),
    };
    (StatusCode::CREATED, Json(serde_json::to_value(resp).unwrap()))
}

/// `GET /api/device-groups` -- list device groups.
pub async fn list_device_groups(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.list_device_groups().await {
        Ok(rows) => {
            let groups: Vec<GroupResponse> = rows
                .iter()
                .map(|r| GroupResponse {
                    id: r.id.clone(),
                    name: r.name.clone(),
                    parent_id: r.parent_id.clone(),
                    created_at: r.created_at.clone(),
                })
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(groups).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list device groups: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `DELETE /api/device-groups/:id` -- delete a device group.
pub async fn delete_device_group(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.delete_device_group(&id).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"message": "group deleted"}))),
        Ok(false) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "group not found"}))),
        Err(e) => {
            log::error!("Failed to delete device group: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `POST /api/device-groups/:id/members` -- add device to group.
pub async fn add_device_group_member(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(group_id): Path<String>,
    Json(payload): Json<AddMemberRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    // Verify the group exists
    match db.get_device_group_by_id(&group_id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "group not found"})),
            );
        }
        Err(e) => {
            log::error!("Failed to check group: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
        Ok(Some(_)) => {}
    }

    if let Err(e) = db.add_device_to_group(&payload.id, &group_id).await {
        log::error!("Failed to add device to group: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    (
        StatusCode::OK,
        Json(serde_json::json!({"message": "device added to group"})),
    )
}

/// `DELETE /api/device-groups/:id/members/:device_id` -- remove device from group.
pub async fn remove_device_group_member(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path((group_id, device_id)): Path<(String, String)>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.remove_device_from_group(&device_id, &group_id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "device removed from group"})),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "membership not found"})),
        ),
        Err(e) => {
            log::error!("Failed to remove device from group: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `GET /api/device-groups/:id/members` -- list device group members.
pub async fn list_device_group_members(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(group_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.list_device_group_members(&group_id).await {
        Ok(rows) => {
            let members: Vec<MemberResponse> = rows
                .iter()
                .map(|r| MemberResponse {
                    id: r.device_id.clone(),
                    group_id: r.group_id.clone(),
                })
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(members).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list device group members: {}", e);
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
        format!("test_groups_{}.sqlite3", uuid::Uuid::new_v4())
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    // -----------------------------------------------------------------------
    // User group DB-level tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_user_group_crud() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Create
        let id = uuid::Uuid::new_v4().to_string();
        db.insert_user_group(&id, "Engineering", "").await.unwrap();

        // List
        let groups = db.list_user_groups().await.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "Engineering");

        // Get by ID
        let g = db.get_user_group_by_id(&id).await.unwrap().unwrap();
        assert_eq!(g.name, "Engineering");

        // Delete
        assert!(db.delete_user_group(&id).await.unwrap());
        assert!(db.get_user_group_by_id(&id).await.unwrap().is_none());
        assert!(!db.delete_user_group(&id).await.unwrap()); // already gone

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_user_group_members() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let gid = uuid::Uuid::new_v4().to_string();
        db.insert_user_group(&gid, "Team", "").await.unwrap();

        // Add members
        db.add_user_to_group("user1", &gid).await.unwrap();
        db.add_user_to_group("user2", &gid).await.unwrap();

        // Idempotent add
        db.add_user_to_group("user1", &gid).await.unwrap();

        let members = db.list_user_group_members(&gid).await.unwrap();
        assert_eq!(members.len(), 2);

        // Remove
        assert!(db.remove_user_from_group("user1", &gid).await.unwrap());
        assert!(!db.remove_user_from_group("user1", &gid).await.unwrap()); // already removed

        let members = db.list_user_group_members(&gid).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].user_id, "user2");

        // Delete group should also remove memberships
        db.delete_user_group(&gid).await.unwrap();
        let members = db.list_user_group_members(&gid).await.unwrap();
        assert!(members.is_empty());

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_user_group_with_parent() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let parent_id = uuid::Uuid::new_v4().to_string();
        db.insert_user_group(&parent_id, "Engineering", "").await.unwrap();

        let child_id = uuid::Uuid::new_v4().to_string();
        db.insert_user_group(&child_id, "Frontend", &parent_id).await.unwrap();

        let child = db.get_user_group_by_id(&child_id).await.unwrap().unwrap();
        assert_eq!(child.parent_id, parent_id);

        cleanup(&db_path);
    }

    // -----------------------------------------------------------------------
    // Device group DB-level tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_device_group_crud() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let id = uuid::Uuid::new_v4().to_string();
        db.insert_device_group(&id, "Office Devices", "").await.unwrap();

        let groups = db.list_device_groups().await.unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].name, "Office Devices");

        assert!(db.delete_device_group(&id).await.unwrap());
        assert!(db.list_device_groups().await.unwrap().is_empty());

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_device_group_members() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let gid = uuid::Uuid::new_v4().to_string();
        db.insert_device_group(&gid, "Laptops", "").await.unwrap();

        db.add_device_to_group("dev1", &gid).await.unwrap();
        db.add_device_to_group("dev2", &gid).await.unwrap();
        db.add_device_to_group("dev1", &gid).await.unwrap(); // idempotent

        let members = db.list_device_group_members(&gid).await.unwrap();
        assert_eq!(members.len(), 2);

        assert!(db.remove_device_from_group("dev1", &gid).await.unwrap());
        let members = db.list_device_group_members(&gid).await.unwrap();
        assert_eq!(members.len(), 1);

        cleanup(&db_path);
    }

    // -----------------------------------------------------------------------
    // HTTP-level tests (using the router)
    // -----------------------------------------------------------------------

    use axum::body::Body;
    use axum::http::{header, Request};
    use axum::body::HttpBody;
    use tower::ServiceExt;

    async fn body_bytes(resp: axum::http::Response<axum::body::BoxBody>) -> Vec<u8> {
        let mut body = resp.into_body();
        let mut buf = Vec::new();
        while let Some(chunk) = body.data().await {
            buf.extend_from_slice(&chunk.unwrap());
        }
        buf
    }

    async fn app_and_db() -> (axum::Router, Database, String) {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();
        crate::api::users::init_default_admin(&db).await;
        let router = crate::api::build_router(db.clone()).await;
        (router, db, db_path)
    }

    async fn admin_token(db: &Database) -> String {
        let admin = db.get_user_by_username("admin").await.unwrap().unwrap();
        crate::api::auth::create_token(&admin.id, &admin.email).unwrap()
    }

    #[tokio::test]
    async fn test_user_group_endpoints() {
        let (_router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        // Create user group
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/user-groups")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(r#"{"name":"Engineering"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let group_id = json["id"].as_str().unwrap().to_string();
        assert_eq!(json["name"], "Engineering");

        // List user groups
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .uri("/api/user-groups")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);

        // Add member
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/user-groups/{}/members", group_id))
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(r#"{"id":"user123"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // List members
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/user-groups/{}/members", group_id))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);

        // Remove member
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/user-groups/{}/members/user123", group_id))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Delete group
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/user-groups/{}", group_id))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_device_group_endpoints() {
        let (_router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        // Create device group
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/device-groups")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(r#"{"name":"Servers"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let group_id = json["id"].as_str().unwrap().to_string();

        // Add device member
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/device-groups/{}/members", group_id))
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(r#"{"id":"device_abc"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // List device groups
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .uri("/api/device-groups")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Delete device group
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/device-groups/{}", group_id))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_user_group_requires_admin() {
        let (router, db, db_path) = app_and_db().await;
        let hash = bcrypt::hash("pass", 4).unwrap();
        let uid = uuid::Uuid::new_v4().to_string();
        db.insert_user(&uid, "regular", "r@test.com", &hash, false)
            .await
            .unwrap();
        let token = crate::api::auth::create_token(&uid, "r@test.com").unwrap();

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/user-groups")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(r#"{"name":"Forbidden"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_user_group_requires_auth() {
        let (router, _db, db_path) = app_and_db().await;

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/user-groups")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_user_group_create_empty_name_rejected() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/user-groups")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(r#"{"name":""}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_add_member_to_nonexistent_group() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/user-groups/nonexistent/members")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(r#"{"id":"user1"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_delete_nonexistent_user_group() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/user-groups/nonexistent-id")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        cleanup(&db_path);
    }
}
