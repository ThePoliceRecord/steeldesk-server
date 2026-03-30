pub mod address_book;
pub mod audit;
pub mod auth;
pub mod control_roles;
pub mod groups;
pub mod heartbeat;
pub mod oidc;
pub mod recordings;
pub mod roles;
pub mod strategies;
pub mod users;

use axum::{
    extract::Extension,
    http::StatusCode,
    routing::{delete, get, get_service, post, put},
    Json, Router,
};
use hbb_common::log;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;

use crate::api::auth::{create_token, AuthUser};
use crate::api::users::User;
use crate::database::Database;

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    #[serde(rename = "access_token")]
    pub access_token: String,
    #[serde(rename = "type")]
    pub token_type: String,
    pub user: UserInfo,
}

#[derive(Debug, Serialize, Clone)]
pub struct UserInfo {
    pub id: String,
    pub name: String,
    pub email: String,
    #[serde(rename = "is_admin")]
    pub is_admin: bool,
}

#[derive(Debug, Serialize)]
pub struct PeerListResponse {
    pub total: u64,
    pub data: Vec<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Handler implementations
// ---------------------------------------------------------------------------

/// `GET /api/health` -- basic health check.
async fn health() -> (StatusCode, &'static str) {
    (StatusCode::OK, "OK")
}

/// `POST /api/login` -- validate credentials against the user store.
async fn login(
    Extension(db): Extension<Database>,
    Json(payload): Json<LoginRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Ensure default admin exists
    users::init_default_admin(&db).await;

    let user = match db.get_user_by_username(&payload.username).await {
        Ok(Some(row)) => User::from(row),
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": "invalid username or password"})),
            );
        }
        Err(e) => {
            log::error!("DB error during login: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };

    let valid = match bcrypt::verify(&payload.password, &user.password_hash) {
        Ok(v) => v,
        Err(e) => {
            log::error!("bcrypt verify failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };

    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "invalid username or password"})),
        );
    }

    let token = match create_token(&user.id, &user.email) {
        Ok(t) => t,
        Err(e) => {
            log::error!("JWT creation failed: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    };

    let resp = LoginResponse {
        access_token: token,
        token_type: "Bearer".into(),
        user: UserInfo {
            id: user.id.clone(),
            name: user.username.clone(),
            email: user.email.clone(),
            is_admin: user.is_admin,
        },
    };

    (StatusCode::OK, Json(serde_json::to_value(resp).unwrap()))
}

/// `POST /api/currentUser` -- returns the authenticated user's info.
async fn current_user(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<UserInfo>) {
    if let Ok(Some(row)) = db.get_user_by_id(&claims.user_id).await {
        let user = User::from(row);
        return (
            StatusCode::OK,
            Json(UserInfo {
                id: user.id,
                name: user.username,
                email: user.email,
                is_admin: user.is_admin,
            }),
        );
    }

    // Fallback: user exists in JWT but was deleted from store
    (
        StatusCode::OK,
        Json(UserInfo {
            id: claims.user_id,
            name: claims.email.split('@').next().unwrap_or("user").to_string(),
            email: claims.email,
            is_admin: false,
        }),
    )
}

/// `GET /api/peers` -- stub returning an empty peer list.
async fn list_peers(AuthUser(_claims): AuthUser) -> (StatusCode, Json<PeerListResponse>) {
    (
        StatusCode::OK,
        Json(PeerListResponse {
            total: 0,
            data: vec![],
        }),
    )
}

// ---------------------------------------------------------------------------
// Router construction
// ---------------------------------------------------------------------------

/// Build the complete axum [`Router`] for the Pro API.
pub async fn build_router(db: Database) -> Router {
    // Ensure default admin user and roles are initialized
    users::init_default_admin(&db).await;
    roles::init_default_roles(&db).await;

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    Router::new()
        // Health check
        .route("/api/health", get(health))
        // Heartbeat: support both GET (health-probe style) and POST (client heartbeat)
        .route(
            "/api/heartbeat",
            get(heartbeat::heartbeat_get).post(heartbeat::heartbeat),
        )
        // Auth (unauthenticated)
        .route("/api/login", post(login))
        // Protected endpoints
        .route("/api/currentUser", post(current_user))
        .route("/api/peers", get(list_peers))
        // User management
        .route("/api/users", get(users::list_users).post(users::create_user))
        .route(
            "/api/users/:id",
            get(users::get_user)
                .put(users::update_user)
                .delete(users::delete_user),
        )
        // Address book
        .route(
            "/api/ab",
            get(address_book::get_ab).post(address_book::update_ab),
        )
        .route("/api/ab/entries/:id", delete(address_book::delete_ab_entry))
        // Audit
        .route("/api/audit/conn", post(audit::post_conn_audit).get(audit::get_conn_audit))
        .route("/api/audit/file", post(audit::post_file_audit))
        // Recordings
        .route("/api/recordings/upload", post(recordings::upload_recording))
        .route("/api/recordings", get(recordings::list_recordings))
        .route(
            "/api/recordings/:id",
            get(recordings::get_recording).delete(recordings::delete_recording),
        )
        .route(
            "/api/recordings/:id/download",
            get(recordings::download_recording),
        )
        // User groups
        .route(
            "/api/user-groups",
            get(groups::list_user_groups).post(groups::create_user_group),
        )
        .route("/api/user-groups/:id", delete(groups::delete_user_group))
        .route(
            "/api/user-groups/:id/members",
            get(groups::list_user_group_members).post(groups::add_user_group_member),
        )
        .route(
            "/api/user-groups/:id/members/:user_id",
            delete(groups::remove_user_group_member),
        )
        // Device groups
        .route(
            "/api/device-groups",
            get(groups::list_device_groups).post(groups::create_device_group),
        )
        .route("/api/device-groups/:id", delete(groups::delete_device_group))
        .route(
            "/api/device-groups/:id/members",
            get(groups::list_device_group_members).post(groups::add_device_group_member),
        )
        .route(
            "/api/device-groups/:id/members/:device_id",
            delete(groups::remove_device_group_member),
        )
        // Strategies
        .route(
            "/api/strategies",
            get(strategies::list_strategies).post(strategies::create_strategy),
        )
        .route(
            "/api/strategies/effective/:target_type/:target_id",
            get(strategies::get_effective_strategy),
        )
        .route(
            "/api/strategies/:id",
            get(strategies::get_strategy)
                .put(strategies::update_strategy)
                .delete(strategies::delete_strategy),
        )
        .route(
            "/api/strategies/:id/assign",
            post(strategies::assign_strategy),
        )
        // Roles (RBAC)
        .route(
            "/api/roles",
            get(roles::list_roles).post(roles::create_role),
        )
        .route(
            "/api/roles/:id",
            get(roles::get_role)
                .put(roles::update_role)
                .delete(roles::delete_role),
        )
        .route("/api/roles/assign", post(roles::assign_role))
        .route("/api/roles/remove", post(roles::remove_role))
        .route("/api/roles/user/:user_id", get(roles::get_user_roles))
        // Control roles
        .route(
            "/api/control-roles",
            get(control_roles::list_control_roles).post(control_roles::create_control_role),
        )
        .route(
            "/api/control-roles/:id",
            get(control_roles::get_control_role)
                .put(control_roles::update_control_role)
                .delete(control_roles::delete_control_role),
        )
        .route(
            "/api/control-roles/assign",
            post(control_roles::assign_control_role),
        )
        .route(
            "/api/control-roles/effective/:user_id",
            get(control_roles::get_effective_control_role),
        )
        // Web console static files
        .nest(
            "/console",
            get_service(ServeDir::new("web-console")).handle_error(
                |err: std::io::Error| async move {
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("IO error: {}", err))
                },
            ),
        )
        // OIDC / SSO
        .route(
            "/api/oidc/providers",
            get(oidc::list_providers).post(oidc::create_provider),
        )
        .route(
            "/api/oidc/providers/:id",
            delete(oidc::delete_provider),
        )
        .route("/api/oidc/authorize/:provider_id", get(oidc::authorize))
        .route("/api/oidc/callback", get(oidc::callback))
        // Shared state
        .layer(Extension(oidc::OidcStateStore::new()))
        .layer(Extension(db))
        // Middleware
        .layer(cors)
}

/// Start the Pro API HTTP server on `port` (default 21114).
///
/// This function is designed to be spawned inside an existing tokio runtime
/// (e.g., the same runtime that runs hbbs).  It runs until the server is
/// shut down or the task is cancelled.
pub async fn start_api_server(port: u16) -> hbb_common::ResultType<()> {
    let db = Database::new("db_v2.sqlite3").await?;
    let app = build_router(db).await;
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    log::info!("Pro API server listening on http://{}", addr);

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request};
    use hbb_common::tokio;
    use tower::ServiceExt; // for `oneshot`

    fn temp_db_path() -> String {
        format!("test_api_{}.sqlite3", uuid::Uuid::new_v4())
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    /// Create a fresh database and router for each test.
    async fn app_and_db() -> (Router, Database, String) {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();
        users::init_default_admin(&db).await;
        let router = build_router(db.clone()).await;
        (router, db, db_path)
    }

    /// Helper: get admin token for the default admin user.
    async fn admin_token(db: &Database) -> String {
        let admin = db.get_user_by_username("admin").await.unwrap().unwrap();
        auth::create_token(&admin.id, &admin.email).unwrap()
    }

    /// Helper: create a non-admin user and return (user_id, token).
    async fn create_non_admin_user(db: &Database, username: &str) -> (String, String) {
        let hash = bcrypt::hash("userpass", 4).unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        db.insert_user(&id, username, &format!("{}@test.com", username), &hash, false)
            .await
            .unwrap();
        let token = auth::create_token(&id, &format!("{}@test.com", username)).unwrap();
        (id, token)
    }

    /// Helper: read the full response body as bytes.
    async fn body_bytes(
        resp: axum::http::Response<axum::body::BoxBody>,
    ) -> Vec<u8> {
        use axum::body::HttpBody;
        let mut body = resp.into_body();
        let mut buf = Vec::new();
        while let Some(chunk) = body.data().await {
            buf.extend_from_slice(&chunk.unwrap());
        }
        buf
    }

    // =====================================================================
    // Health check
    // =====================================================================

    #[tokio::test]
    async fn test_health_endpoint() {
        let (router, _db, db_path) = app_and_db().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        cleanup(&db_path);
    }

    // =====================================================================
    // Heartbeat
    // =====================================================================

    #[tokio::test]
    async fn test_heartbeat_returns_is_pro_true() {
        let (router, _db, db_path) = app_and_db().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/heartbeat")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["is_pro"], true, "heartbeat must return is_pro=true");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_heartbeat_get() {
        let (router, _db, db_path) = app_and_db().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/heartbeat")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["is_pro"], true);
        cleanup(&db_path);
    }

    // =====================================================================
    // Login -- correct credentials
    // =====================================================================

    #[tokio::test]
    async fn test_login_returns_valid_jwt() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        // Verify admin token is valid
        let claims = auth::validate_token(&token).expect("admin token must be valid");
        assert_eq!(claims.email, "admin@rustdesk.local");

        // Now test login endpoint
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"admin","password":"admin123"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

        let access_token = json["access_token"]
            .as_str()
            .expect("access_token must be a string");
        assert!(!access_token.is_empty(), "token must not be empty");

        let claims = auth::validate_token(access_token).expect("returned token must be valid");
        assert_eq!(claims.email, "admin@rustdesk.local");
        cleanup(&db_path);
    }

    // =====================================================================
    // Login -- incorrect credentials
    // =====================================================================

    #[tokio::test]
    async fn test_login_wrong_password() {
        let (router, _db, db_path) = app_and_db().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"admin","password":"wrongpassword"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["error"].as_str().unwrap().contains("invalid"));
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_login_nonexistent_user() {
        let (router, _db, db_path) = app_and_db().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"nosuchuser","password":"anything"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        cleanup(&db_path);
    }

    // =====================================================================
    // Protected endpoints reject unauthenticated requests
    // =====================================================================

    #[tokio::test]
    async fn test_current_user_rejects_no_token() {
        let (router, _db, db_path) = app_and_db().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/currentUser")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "currentUser without token must return 401"
        );
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_peers_rejects_no_token() {
        let (router, _db, db_path) = app_and_db().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/peers")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_ab_rejects_no_token() {
        let (router, _db, db_path) = app_and_db().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/ab")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        cleanup(&db_path);
    }

    // =====================================================================
    // currentUser with valid token
    // =====================================================================

    #[tokio::test]
    async fn test_current_user_with_valid_token() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/currentUser")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["email"], "admin@rustdesk.local");
        assert_eq!(json["name"], "admin");
        assert_eq!(json["is_admin"], true);
        cleanup(&db_path);
    }

    // =====================================================================
    // CORS headers
    // =====================================================================

    #[tokio::test]
    async fn test_cors_headers_present() {
        let (router, _db, db_path) = app_and_db().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("OPTIONS")
                    .uri("/api/heartbeat")
                    .header("Origin", "http://example.com")
                    .header("Access-Control-Request-Method", "POST")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.headers().contains_key("access-control-allow-origin"),
            "CORS allow-origin header must be present"
        );
        cleanup(&db_path);
    }

    // =====================================================================
    // Full login -> currentUser flow
    // =====================================================================

    #[tokio::test]
    async fn test_login_then_current_user_flow() {
        let (_router, db, db_path) = app_and_db().await;

        // Step 1: login with correct credentials
        let login_resp = build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/login")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"username":"admin","password":"admin123"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(login_resp.status(), StatusCode::OK);
        let body = body_bytes(login_resp).await;
        let login_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let token = login_json["access_token"].as_str().unwrap();

        // Step 2: use token to call currentUser
        let user_resp = build_router(db).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/currentUser")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(user_resp.status(), StatusCode::OK);
        let body = body_bytes(user_resp).await;
        let user_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(user_json["name"], "admin");
        assert_eq!(user_json["email"], "admin@rustdesk.local");
        cleanup(&db_path);
    }

    // =====================================================================
    // User CRUD operations
    // =====================================================================

    #[tokio::test]
    async fn test_create_user() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"username":"newuser","email":"new@test.com","password":"pass123"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], "newuser");
        assert_eq!(json["email"], "new@test.com");
        assert!(json.get("password_hash").is_none(), "password hash must not leak");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_list_users_admin() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/users")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert!(arr.len() >= 1, "should have at least the admin user");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_list_users_non_admin_rejected() {
        let (router, db, db_path) = app_and_db().await;
        let (_uid, token) = create_non_admin_user(&db, "regularjoe").await;
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/users")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_get_user_by_id() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        let admin = db.get_user_by_username("admin").await.unwrap().unwrap();
        let resp = router
            .oneshot(
                Request::builder()
                    .uri(&format!("/api/users/{}", admin.id))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], "admin");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_get_user_not_found() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/users/nonexistent-uuid")
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
    async fn test_update_user() {
        let (_router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        let admin = db.get_user_by_username("admin").await.unwrap().unwrap();
        let resp = build_router(db).await
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(&format!("/api/users/{}", admin.id))
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"username":"admin_updated"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["username"], "admin_updated");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_delete_user() {
        let (_router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        // Create a user to delete
        let (uid, _) = create_non_admin_user(&db, "todelete").await;

        let resp = build_router(db).await
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/users/{}", uid))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "user deleted");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_create_user_non_admin_rejected() {
        let (router, db, db_path) = app_and_db().await;
        let (_uid, token) = create_non_admin_user(&db, "nonadmin_creator").await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/users")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"username":"newuser2","email":"n2@test.com","password":"pass"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_delete_user_non_admin_rejected() {
        let (router, db, db_path) = app_and_db().await;
        let admin = db.get_user_by_username("admin").await.unwrap().unwrap();
        let (_uid, token) = create_non_admin_user(&db, "nonadmin_deleter").await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri(&format!("/api/users/{}", admin.id))
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        cleanup(&db_path);
    }

    // =====================================================================
    // Address book CRUD with auth
    // =====================================================================

    #[tokio::test]
    async fn test_ab_get_empty() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/ab")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["entries"].as_array().unwrap().is_empty());
        assert!(json["tags"].as_array().unwrap().is_empty());
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_ab_post_and_get() {
        let (_router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        // POST address book
        let resp = build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/ab")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token.clone()))
                    .body(Body::from(
                        r#"{"entries":[{"id":"e1","peer_id":"peer1","alias":"My PC","tags":["home"],"hash":"abc"}],"tags":["home"]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // GET address book (same DB, new router)
        let resp = build_router(db).await
            .oneshot(
                Request::builder()
                    .uri("/api/ab")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["entries"].as_array().unwrap().len(), 1);
        assert_eq!(json["entries"][0]["peer_id"], "peer1");
        // Tags are derived from entries in the DB path
        assert!(json["tags"].as_array().unwrap().contains(&serde_json::json!("home")));
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_ab_delete_entry() {
        let (_router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        // First, create an address book with two entries
        let resp = build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/ab")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token.clone()))
                    .body(Body::from(
                        r#"{"entries":[{"id":"e1","peer_id":"p1","alias":"","tags":[],"hash":""},{"id":"e2","peer_id":"p2","alias":"","tags":[],"hash":""}],"tags":[]}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Delete entry e1
        let resp = build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/ab/entries/e1")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token.clone()))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Verify only e2 remains
        let resp = build_router(db).await
            .oneshot(
                Request::builder()
                    .uri("/api/ab")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let entries = json["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0]["id"], "e2");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_ab_delete_nonexistent_entry() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/ab/entries/nonexistent")
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
    async fn test_ab_requires_auth() {
        let (router, _db, db_path) = app_and_db().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/ab")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"entries":[],"tags":[]}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        cleanup(&db_path);
    }

    // =====================================================================
    // Audit log post and query
    // =====================================================================

    #[tokio::test]
    async fn test_audit_conn_post() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/audit/conn")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"from_peer":"peer_a","to_peer":"peer_b","conn_type":"remote_desktop"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["from_peer"], "peer_a");
        assert_eq!(json["conn_type"], "remote_desktop");
        assert!(json["timestamp"].as_str().is_some(), "timestamp should be present");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_audit_file_post() {
        let (router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/audit/file")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::from(
                        r#"{"from_peer":"peer_x","to_peer":"peer_y","note":"test.txt"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["conn_type"], "file_transfer");
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_audit_conn_get_admin() {
        let (_router, db, db_path) = app_and_db().await;
        let token = admin_token(&db).await;

        // Post an audit entry first
        let post_resp = build_router(db.clone()).await
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/audit/conn")
                    .header("content-type", "application/json")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token.clone()))
                    .body(Body::from(
                        r#"{"from_peer":"a","to_peer":"b"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_resp.status(), StatusCode::CREATED);

        // Get audit logs
        let resp = build_router(db).await
            .oneshot(
                Request::builder()
                    .uri("/api/audit/conn")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_bytes(resp).await;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.as_array().unwrap().len() >= 1);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_audit_conn_get_non_admin_rejected() {
        let (router, db, db_path) = app_and_db().await;
        let (_uid, token) = create_non_admin_user(&db, "auditviewer").await;
        let resp = router
            .oneshot(
                Request::builder()
                    .uri("/api/audit/conn")
                    .header(header::AUTHORIZATION, format!("Bearer {}", token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_audit_requires_auth() {
        let (router, _db, db_path) = app_and_db().await;
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/audit/conn")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        r#"{"from_peer":"a","to_peer":"b"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        cleanup(&db_path);
    }
}
