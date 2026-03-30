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
// Strategy models
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategyResponse {
    pub id: String,
    pub name: String,
    pub settings: serde_json::Value,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateStrategyRequest {
    pub name: String,
    #[serde(default = "default_settings")]
    pub settings: serde_json::Value,
}

fn default_settings() -> serde_json::Value {
    serde_json::json!({})
}

#[derive(Debug, Deserialize)]
pub struct UpdateStrategyRequest {
    pub name: Option<String>,
    pub settings: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct AssignStrategyRequest {
    pub target_type: String,
    pub target_id: String,
}

#[derive(Debug, Serialize)]
pub struct AssignmentResponse {
    pub strategy_id: String,
    pub target_type: String,
    pub target_id: String,
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

fn row_to_response(row: &crate::database::StrategyRow) -> StrategyResponse {
    let settings: serde_json::Value =
        serde_json::from_str(&row.settings).unwrap_or_else(|_| serde_json::json!({}));
    StrategyResponse {
        id: row.id.clone(),
        name: row.name.clone(),
        settings,
        created_at: row.created_at.clone(),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/strategies` -- create a strategy.
pub async fn create_strategy(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<CreateStrategyRequest>,
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

    let settings_str = serde_json::to_string(&payload.settings).unwrap_or_else(|_| "{}".into());
    let id = uuid::Uuid::new_v4().to_string();
    if let Err(e) = db.insert_strategy(&id, &payload.name, &settings_str).await {
        log::error!("Failed to create strategy: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    let resp = StrategyResponse {
        id,
        name: payload.name,
        settings: payload.settings,
        created_at: String::new(),
    };
    (StatusCode::CREATED, Json(serde_json::to_value(resp).unwrap()))
}

/// `GET /api/strategies` -- list all strategies.
pub async fn list_strategies(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.list_strategies().await {
        Ok(rows) => {
            let strategies: Vec<StrategyResponse> = rows.iter().map(row_to_response).collect();
            (StatusCode::OK, Json(serde_json::to_value(strategies).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list strategies: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `GET /api/strategies/:id` -- get a strategy by ID.
pub async fn get_strategy(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.get_strategy_by_id(&id).await {
        Ok(Some(row)) => {
            let resp = row_to_response(&row);
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "strategy not found"})),
        ),
        Err(e) => {
            log::error!("Failed to get strategy: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `PUT /api/strategies/:id` -- update a strategy.
pub async fn update_strategy(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
    Json(payload): Json<UpdateStrategyRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    let settings_str = payload
        .settings
        .as_ref()
        .map(|s| serde_json::to_string(s).unwrap_or_else(|_| "{}".into()));

    match db
        .update_strategy(&id, payload.name.as_deref(), settings_str.as_deref())
        .await
    {
        Ok(true) => {
            match db.get_strategy_by_id(&id).await {
                Ok(Some(row)) => {
                    let resp = row_to_response(&row);
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
            Json(serde_json::json!({"error": "strategy not found"})),
        ),
        Err(e) => {
            log::error!("Failed to update strategy: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `DELETE /api/strategies/:id` -- delete a strategy.
pub async fn delete_strategy(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.delete_strategy(&id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "strategy deleted"})),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "strategy not found"})),
        ),
        Err(e) => {
            log::error!("Failed to delete strategy: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `POST /api/strategies/:id/assign` -- assign strategy to a target.
pub async fn assign_strategy(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
    Json(payload): Json<AssignStrategyRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    // Verify strategy exists
    match db.get_strategy_by_id(&id).await {
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "strategy not found"})),
            );
        }
        Err(e) => {
            log::error!("Failed to check strategy: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
        Ok(Some(_)) => {}
    }

    // Validate target_type
    let valid_types = ["user", "device", "user_group", "device_group"];
    if !valid_types.contains(&payload.target_type.as_str()) {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "target_type must be one of: user, device, user_group, device_group"})),
        );
    }

    if let Err(e) = db
        .assign_strategy(&id, &payload.target_type, &payload.target_id)
        .await
    {
        log::error!("Failed to assign strategy: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "internal server error"})),
        );
    }

    let resp = AssignmentResponse {
        strategy_id: id,
        target_type: payload.target_type,
        target_id: payload.target_id,
    };
    (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
}

/// `GET /api/strategies/effective/:target_type/:target_id` -- get effective strategy.
pub async fn get_effective_strategy(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path((target_type, target_id)): Path<(String, String)>,
) -> (StatusCode, Json<serde_json::Value>) {
    if let Err(e) = require_admin(&claims, &db).await {
        return e;
    }

    match db.get_effective_strategy(&target_type, &target_id).await {
        Ok(Some(row)) => {
            let resp = row_to_response(&row);
            (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "no effective strategy found"})),
        ),
        Err(e) => {
            log::error!("Failed to get effective strategy: {}", e);
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
        format!("test_strategies_{}.sqlite3", uuid::Uuid::new_v4())
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    // -----------------------------------------------------------------------
    // DB-level tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_strategy_crud() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let id = uuid::Uuid::new_v4().to_string();
        let settings = r#"{"allow_remote_desktop":true,"clipboard_enabled":false}"#;
        db.insert_strategy(&id, "Strict Policy", settings).await.unwrap();

        // Get by ID
        let s = db.get_strategy_by_id(&id).await.unwrap().unwrap();
        assert_eq!(s.name, "Strict Policy");
        assert_eq!(s.settings, settings);

        // List
        let list = db.list_strategies().await.unwrap();
        assert_eq!(list.len(), 1);

        // Update
        let new_settings = r#"{"allow_remote_desktop":false}"#;
        assert!(db.update_strategy(&id, Some("Updated Policy"), Some(new_settings)).await.unwrap());
        let s = db.get_strategy_by_id(&id).await.unwrap().unwrap();
        assert_eq!(s.name, "Updated Policy");
        assert_eq!(s.settings, new_settings);

        // Delete
        assert!(db.delete_strategy(&id).await.unwrap());
        assert!(db.get_strategy_by_id(&id).await.unwrap().is_none());
        assert!(!db.delete_strategy(&id).await.unwrap());

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_strategy_assignment() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let sid = uuid::Uuid::new_v4().to_string();
        db.insert_strategy(&sid, "Policy A", "{}").await.unwrap();

        // Assign to user
        db.assign_strategy(&sid, "user", "user1").await.unwrap();

        let assignments = db.list_strategy_assignments(&sid).await.unwrap();
        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].target_type, "user");
        assert_eq!(assignments[0].target_id, "user1");

        // Reassign (replace) same target
        db.assign_strategy(&sid, "user", "user1").await.unwrap();
        let assignments = db.list_strategy_assignments(&sid).await.unwrap();
        assert_eq!(assignments.len(), 1); // still 1, not 2

        // Delete strategy should clean up assignments
        db.delete_strategy(&sid).await.unwrap();
        let assignments = db.list_strategy_assignments(&sid).await.unwrap();
        assert!(assignments.is_empty());

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_effective_strategy_direct() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let sid = uuid::Uuid::new_v4().to_string();
        db.insert_strategy(&sid, "Direct Policy", r#"{"key":"value"}"#).await.unwrap();
        db.assign_strategy(&sid, "user", "user1").await.unwrap();

        let effective = db.get_effective_strategy("user", "user1").await.unwrap().unwrap();
        assert_eq!(effective.name, "Direct Policy");

        // No strategy for user2
        assert!(db.get_effective_strategy("user", "user2").await.unwrap().is_none());

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_effective_strategy_via_group() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Create a user group and add a user
        let gid = uuid::Uuid::new_v4().to_string();
        db.insert_user_group(&gid, "Engineers", "").await.unwrap();
        db.add_user_to_group("user1", &gid).await.unwrap();

        // Create a strategy and assign it to the group
        let sid = uuid::Uuid::new_v4().to_string();
        db.insert_strategy(&sid, "Group Policy", r#"{"group":true}"#).await.unwrap();
        db.assign_strategy(&sid, "user_group", &gid).await.unwrap();

        // user1 should inherit the strategy via group membership
        let effective = db.get_effective_strategy("user", "user1").await.unwrap().unwrap();
        assert_eq!(effective.name, "Group Policy");

        // user2 (not in group) should have no strategy
        assert!(db.get_effective_strategy("user", "user2").await.unwrap().is_none());

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_effective_strategy_direct_overrides_group() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        // Setup: user in group with group strategy
        let gid = uuid::Uuid::new_v4().to_string();
        db.insert_user_group(&gid, "Team", "").await.unwrap();
        db.add_user_to_group("user1", &gid).await.unwrap();

        let group_sid = uuid::Uuid::new_v4().to_string();
        db.insert_strategy(&group_sid, "Group Policy", "{}").await.unwrap();
        db.assign_strategy(&group_sid, "user_group", &gid).await.unwrap();

        // Also assign a direct strategy to user1
        let direct_sid = uuid::Uuid::new_v4().to_string();
        db.insert_strategy(&direct_sid, "Direct Policy", "{}").await.unwrap();
        db.assign_strategy(&direct_sid, "user", "user1").await.unwrap();

        // Direct should take precedence
        let effective = db.get_effective_strategy("user", "user1").await.unwrap().unwrap();
        assert_eq!(effective.name, "Direct Policy");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_effective_strategy_device_group() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let gid = uuid::Uuid::new_v4().to_string();
        db.insert_device_group(&gid, "Servers", "").await.unwrap();
        db.add_device_to_group("dev1", &gid).await.unwrap();

        let sid = uuid::Uuid::new_v4().to_string();
        db.insert_strategy(&sid, "Server Policy", "{}").await.unwrap();
        db.assign_strategy(&sid, "device_group", &gid).await.unwrap();

        let effective = db.get_effective_strategy("device", "dev1").await.unwrap().unwrap();
        assert_eq!(effective.name, "Server Policy");

        cleanup(&db_path);
    }

    // -----------------------------------------------------------------------
    // HTTP-level tests
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
    async fn test_strategy_endpoints_crud() {
        let (_router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        // Create
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/strategies")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"name":"Test Policy","settings":{"clipboard":false}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let strategy_id = json["id"].as_str().unwrap().to_string();
        assert_eq!(json["name"], "Test Policy");
        assert_eq!(json["settings"]["clipboard"], false);

        // List
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .uri("/api/strategies")
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

        // Get by ID
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/strategies/{}", strategy_id))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "Test Policy");

        // Update
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&format!("/api/strategies/{}", strategy_id))
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"name":"Updated Policy","settings":{"clipboard":true}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "Updated Policy");
        assert_eq!(json["settings"]["clipboard"], true);

        // Delete
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/strategies/{}", strategy_id))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify deleted
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/strategies/{}", strategy_id))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_strategy_assign_endpoint() {
        let (_router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        // Create a strategy
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/strategies")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(r#"{"name":"Assign Test"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let strategy_id = json["id"].as_str().unwrap().to_string();

        // Assign to user
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/strategies/{}/assign", strategy_id))
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"target_type":"user","target_id":"user123"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["target_type"], "user");
        assert_eq!(json["target_id"], "user123");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_strategy_assign_invalid_target_type() {
        let (_router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        // Create a strategy
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/strategies")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(r#"{"name":"Invalid Target"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let strategy_id = json["id"].as_str().unwrap().to_string();

        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/strategies/{}/assign", strategy_id))
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"target_type":"invalid","target_id":"x"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_strategy_assign_nonexistent_strategy() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/strategies/nonexistent/assign")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"target_type":"user","target_id":"u1"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_effective_strategy_endpoint() {
        let (_router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        // Create strategy and assign to user
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/strategies")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"name":"Effective Test","settings":{"a":1}}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let strategy_id = json["id"].as_str().unwrap().to_string();

        // Assign
        crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(&format!("/api/strategies/{}/assign", strategy_id))
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"target_type":"user","target_id":"user_eff"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        // Get effective
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .uri("/api/strategies/effective/user/user_eff")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "Effective Test");
        assert_eq!(json["settings"]["a"], 1);

        // No effective for unknown user
        let resp = crate::api::build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .uri("/api/strategies/effective/user/unknown")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_strategy_requires_admin() {
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
                    .uri("/api/strategies")
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
    async fn test_strategy_requires_auth() {
        let (router, _db, db_path) = app_and_db().await;

        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/strategies")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_strategy_create_empty_name_rejected() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/strategies")
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
    async fn test_strategy_update_nonexistent() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        let resp = router
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri("/api/strategies/nonexistent")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(r#"{"name":"Updated"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        cleanup(&db_path);
    }
}
