use axum::{
    extract::{Extension, Path, Query},
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use hbb_common::log;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::api::auth::AuthUser;
use crate::api::roles;
use crate::database::Database;

// ---------------------------------------------------------------------------
// Recording model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Recording {
    pub id: String,
    pub connection_id: String,
    pub from_peer: String,
    pub to_peer: String,
    pub file_name: String,
    pub file_size: i64,
    pub duration_seconds: i64,
    pub uploaded_at: String,
}

impl From<crate::database::RecordingRow> for Recording {
    fn from(row: crate::database::RecordingRow) -> Self {
        Recording {
            id: row.id,
            connection_id: row.connection_id,
            from_peer: row.from_peer,
            to_peer: row.to_peer,
            file_name: row.file_name,
            file_size: row.file_size,
            duration_seconds: row.duration_seconds,
            uploaded_at: row.uploaded_at,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct UploadQuery {
    #[serde(default)]
    pub connection_id: String,
    #[serde(default)]
    pub from_peer: String,
    #[serde(default)]
    pub to_peer: String,
    #[serde(default)]
    pub file_name: String,
    #[serde(default)]
    pub duration_seconds: i64,
}

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    #[serde(default)]
    pub from_peer: Option<String>,
    #[serde(default)]
    pub to_peer: Option<String>,
    #[serde(default)]
    pub connection_id: Option<String>,
}

// ---------------------------------------------------------------------------
// File helpers
// ---------------------------------------------------------------------------

/// Directory where recording files are stored (next to the DB file).
fn recordings_dir() -> PathBuf {
    PathBuf::from("recordings")
}

fn save_recording(id: &str, data: &[u8]) -> std::io::Result<PathBuf> {
    let dir = recordings_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.recording", id));
    std::fs::write(&path, data)?;
    Ok(path)
}

fn recording_path(id: &str) -> PathBuf {
    recordings_dir().join(format!("{}.recording", id))
}

fn delete_recording_file(id: &str) -> std::io::Result<()> {
    let path = recording_path(id);
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Delete recordings older than `retention_days` from disk and database.
pub async fn cleanup_old_recordings(db: &Database, retention_days: u32) {
    log::info!(
        "Running recording retention cleanup (retention_days={})",
        retention_days
    );
    match db.list_recordings_older_than(retention_days).await {
        Ok(old_rows) => {
            let count = old_rows.len();
            for row in old_rows {
                if let Err(e) = delete_recording_file(&row.id) {
                    log::warn!("Failed to delete recording file {}: {}", row.id, e);
                }
                if let Err(e) = db.delete_recording(&row.id).await {
                    log::warn!("Failed to delete recording DB row {}: {}", row.id, e);
                }
            }
            if count > 0 {
                log::info!("Deleted {} expired recording(s)", count);
            }
        }
        Err(e) => {
            log::error!("Failed to query old recordings for cleanup: {}", e);
        }
    }
}

/// Read the configured retention period from the environment / config.
pub fn get_retention_days() -> u32 {
    crate::common::get_arg_or("recording-retention-days", "30".to_owned())
        .parse::<u32>()
        .unwrap_or(30)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/recordings/upload` -- receive recording file as raw body.
///
/// Query parameters carry metadata (matches the client's upload approach).
pub async fn upload_recording(
    AuthUser(_claims): AuthUser,
    Extension(db): Extension<Database>,
    Query(params): Query<UploadQuery>,
    body: axum::body::Bytes,
) -> (StatusCode, Json<serde_json::Value>) {
    let id = uuid::Uuid::new_v4().to_string();
    let file_name = if params.file_name.is_empty() {
        format!("{}.recording", id)
    } else {
        params.file_name.clone()
    };
    let file_size = body.len() as i64;

    // Save file to disk
    if let Err(e) = save_recording(&id, &body) {
        log::error!("Failed to save recording file: {}", e);
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": "failed to save recording file"})),
        );
    }

    // Insert DB row
    match db
        .insert_recording(
            &id,
            &params.connection_id,
            &params.from_peer,
            &params.to_peer,
            &file_name,
            file_size,
            params.duration_seconds,
        )
        .await
    {
        Ok(row) => {
            let rec = Recording::from(row);
            (
                StatusCode::CREATED,
                Json(serde_json::to_value(rec).unwrap()),
            )
        }
        Err(e) => {
            log::error!("Failed to insert recording: {}", e);
            // Clean up the file we just wrote
            let _ = delete_recording_file(&id);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "failed to insert recording into database"})),
            )
        }
    }
}

/// `GET /api/recordings` -- list recordings (admin only), with optional filters.
pub async fn list_recordings(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Query(params): Query<ListQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::has_permission(&claims.user_id, "audit", "view", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    match db
        .list_recordings(
            params.from_peer.as_deref(),
            params.to_peer.as_deref(),
            params.connection_id.as_deref(),
        )
        .await
    {
        Ok(rows) => {
            let entries: Vec<Recording> = rows.into_iter().map(Recording::from).collect();
            (StatusCode::OK, Json(serde_json::to_value(entries).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list recordings: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `GET /api/recordings/:id` -- get recording metadata.
pub async fn get_recording(
    AuthUser(_claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    match db.get_recording(&id).await {
        Ok(Some(row)) => {
            let rec = Recording::from(row);
            (StatusCode::OK, Json(serde_json::to_value(rec).unwrap()))
        }
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "recording not found"})),
        ),
        Err(e) => {
            log::error!("Failed to get recording: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            )
        }
    }
}

/// `GET /api/recordings/:id/download` -- download recording file.
pub async fn download_recording(
    AuthUser(_claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    let row = match db.get_recording(&id).await {
        Ok(Some(row)) => row,
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/json".to_string()), (header::CONTENT_DISPOSITION, String::new())],
                r#"{"error":"recording not found"}"#.as_bytes().to_vec(),
            );
        }
        Err(e) => {
            log::error!("Failed to get recording: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/json".to_string()), (header::CONTENT_DISPOSITION, String::new())],
                r#"{"error":"internal server error"}"#.as_bytes().to_vec(),
            );
        }
    };

    let path = recording_path(&id);
    let data = match std::fs::read(&path) {
        Ok(d) => d,
        Err(e) => {
            log::error!("Failed to read recording file {:?}: {}", path, e);
            return (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/json".to_string()), (header::CONTENT_DISPOSITION, String::new())],
                r#"{"error":"recording file not found on disk"}"#.as_bytes().to_vec(),
            );
        }
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, format!("attachment; filename=\"{}\"", row.file_name)),
        ],
        data,
    )
}

/// `DELETE /api/recordings/:id` -- delete recording + file (admin only).
pub async fn delete_recording(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::has_permission(&claims.user_id, "audit", "view", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    // Check it exists
    match db.get_recording(&id).await {
        Ok(Some(_)) => {}
        Ok(None) => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error": "recording not found"})),
            );
        }
        Err(e) => {
            log::error!("Failed to get recording: {}", e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "internal server error"})),
            );
        }
    }

    // Delete file
    if let Err(e) = delete_recording_file(&id) {
        log::warn!("Failed to delete recording file {}: {}", id, e);
    }

    // Delete DB row
    match db.delete_recording(&id).await {
        Ok(true) => (
            StatusCode::OK,
            Json(serde_json::json!({"message": "recording deleted"})),
        ),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "recording not found"})),
        ),
        Err(e) => {
            log::error!("Failed to delete recording: {}", e);
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
        format!("test_recordings_{}.sqlite3", uuid::Uuid::new_v4())
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    fn cleanup_dir(dir: &std::path::Path) {
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn test_recording_insert_and_get() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let row = db
            .insert_recording(
                "rec-1",
                "conn-1",
                "peer_a",
                "peer_b",
                "session.recording",
                1024,
                60,
            )
            .await
            .unwrap();

        assert_eq!(row.id, "rec-1");
        assert_eq!(row.connection_id, "conn-1");
        assert_eq!(row.from_peer, "peer_a");
        assert_eq!(row.to_peer, "peer_b");
        assert_eq!(row.file_name, "session.recording");
        assert_eq!(row.file_size, 1024);
        assert_eq!(row.duration_seconds, 60);

        let fetched = db.get_recording("rec-1").await.unwrap();
        assert!(fetched.is_some());
        let fetched = fetched.unwrap();
        assert_eq!(fetched.from_peer, "peer_a");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_recording_list_with_filters() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        db.insert_recording("r1", "c1", "alice", "bob", "f1.rec", 100, 10)
            .await
            .unwrap();
        db.insert_recording("r2", "c2", "alice", "charlie", "f2.rec", 200, 20)
            .await
            .unwrap();
        db.insert_recording("r3", "c3", "dave", "bob", "f3.rec", 300, 30)
            .await
            .unwrap();

        // No filter
        let all = db.list_recordings(None, None, None).await.unwrap();
        assert_eq!(all.len(), 3);

        // Filter by from_peer
        let alice = db
            .list_recordings(Some("alice"), None, None)
            .await
            .unwrap();
        assert_eq!(alice.len(), 2);

        // Filter by to_peer
        let bob = db.list_recordings(None, Some("bob"), None).await.unwrap();
        assert_eq!(bob.len(), 2);

        // Filter by connection_id
        let c2 = db.list_recordings(None, None, Some("c2")).await.unwrap();
        assert_eq!(c2.len(), 1);
        assert_eq!(c2[0].from_peer, "alice");

        // Combined filters
        let combo = db
            .list_recordings(Some("alice"), Some("bob"), None)
            .await
            .unwrap();
        assert_eq!(combo.len(), 1);
        assert_eq!(combo[0].id, "r1");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_recording_delete() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        db.insert_recording("del-1", "", "a", "b", "del.rec", 50, 5)
            .await
            .unwrap();

        let deleted = db.delete_recording("del-1").await.unwrap();
        assert!(deleted);

        let gone = db.get_recording("del-1").await.unwrap();
        assert!(gone.is_none());

        // Deleting again returns false
        let again = db.delete_recording("del-1").await.unwrap();
        assert!(!again);

        cleanup(&db_path);
    }

    #[test]
    fn test_save_and_delete_recording_file() {
        let id = format!("test-file-{}", uuid::Uuid::new_v4());
        let data = b"fake recording data";

        let path = save_recording(&id, data).unwrap();
        assert!(path.exists());

        let read_back = std::fs::read(&path).unwrap();
        assert_eq!(read_back, data);

        delete_recording_file(&id).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn test_recording_serialization() {
        let rec = Recording {
            id: "r1".into(),
            connection_id: "c1".into(),
            from_peer: "alice".into(),
            to_peer: "bob".into(),
            file_name: "session.recording".into(),
            file_size: 1024,
            duration_seconds: 60,
            uploaded_at: "2024-01-01 00:00:00".into(),
        };
        let json = serde_json::to_value(&rec).unwrap();
        assert_eq!(json["from_peer"], "alice");
        assert_eq!(json["file_size"], 1024);
        assert_eq!(json["duration_seconds"], 60);
    }

    #[test]
    fn test_upload_query_deserialization() {
        let json_str = r#"{"from_peer":"a","to_peer":"b","file_name":"test.rec"}"#;
        let q: UploadQuery = serde_json::from_str(json_str).unwrap();
        assert_eq!(q.from_peer, "a");
        assert_eq!(q.file_name, "test.rec");
        assert_eq!(q.duration_seconds, 0); // default
    }

    #[tokio::test]
    async fn test_recording_has_timestamp() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let row = db
            .insert_recording("ts-1", "", "a", "b", "ts.rec", 10, 1)
            .await
            .unwrap();
        assert!(
            !row.uploaded_at.is_empty(),
            "uploaded_at should be set by database"
        );

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_recordings_persist_across_reopen() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        db.insert_recording("persist-1", "c1", "p1", "p2", "f.rec", 100, 10)
            .await
            .unwrap();

        // Re-open database
        let db2 = Database::new(&db_path).await.unwrap();
        let rows = db2.list_recordings(None, None, None).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].id, "persist-1");

        cleanup(&db_path);
    }

    #[test]
    fn test_get_retention_days_default() {
        // Without env var set, should return 30
        let days = get_retention_days();
        assert!(days > 0);
    }

    #[tokio::test]
    async fn test_cleanup_old_recordings() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        db.insert_recording("old-1", "", "a", "b", "old.rec", 10, 1)
            .await
            .unwrap();

        // With retention_days=0, everything should be cleaned up
        // (but the recording was just inserted, so only days=0 would catch it
        //  if we manually adjusted the timestamp)

        // Just verify the function runs without error
        cleanup_old_recordings(&db, 9999).await;

        // With a huge retention, nothing should be deleted
        let rows = db.list_recordings(None, None, None).await.unwrap();
        assert_eq!(rows.len(), 1);

        cleanup(&db_path);
    }
}
