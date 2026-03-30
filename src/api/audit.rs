use axum::{
    extract::Extension,
    http::StatusCode,
    Json,
};
use hbb_common::log;
use serde::{Deserialize, Serialize};

use crate::api::auth::AuthUser;
use crate::api::roles;
use crate::database::Database;

// ---------------------------------------------------------------------------
// Audit entry model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: i64,
    pub from_peer: String,
    pub to_peer: String,
    pub conn_type: String,
    pub timestamp: String,
    #[serde(default)]
    pub note: String,
}

impl From<crate::database::AuditRow> for AuditEntry {
    fn from(row: crate::database::AuditRow) -> Self {
        AuditEntry {
            id: row.id,
            from_peer: row.from_peer,
            to_peer: row.to_peer,
            conn_type: row.conn_type,
            timestamp: row.timestamp,
            note: row.note,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ConnAuditRequest {
    pub from_peer: String,
    pub to_peer: String,
    #[serde(default = "default_conn_type")]
    pub conn_type: String,
    #[serde(default)]
    pub note: String,
}

fn default_conn_type() -> String {
    "remote_desktop".to_string()
}

#[derive(Debug, Deserialize)]
pub struct FileAuditRequest {
    pub from_peer: String,
    pub to_peer: String,
    #[serde(default)]
    pub note: String,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `POST /api/audit/conn` -- receive a connection audit event.
pub async fn post_conn_audit(
    AuthUser(_claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<ConnAuditRequest>,
) -> (StatusCode, Json<AuditEntry>) {
    match db
        .insert_audit_log(
            &payload.from_peer,
            &payload.to_peer,
            &payload.conn_type,
            &payload.note,
        )
        .await
    {
        Ok(row) => (StatusCode::CREATED, Json(AuditEntry::from(row))),
        Err(e) => {
            log::error!("Failed to insert audit log: {}", e);
            // Return a minimal entry on error
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuditEntry {
                    id: 0,
                    from_peer: payload.from_peer,
                    to_peer: payload.to_peer,
                    conn_type: payload.conn_type,
                    timestamp: String::new(),
                    note: payload.note,
                }),
            )
        }
    }
}

/// `POST /api/audit/file` -- receive a file transfer audit event.
pub async fn post_file_audit(
    AuthUser(_claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<FileAuditRequest>,
) -> (StatusCode, Json<AuditEntry>) {
    match db
        .insert_audit_log(
            &payload.from_peer,
            &payload.to_peer,
            "file_transfer",
            &payload.note,
        )
        .await
    {
        Ok(row) => (StatusCode::CREATED, Json(AuditEntry::from(row))),
        Err(e) => {
            log::error!("Failed to insert file audit log: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(AuditEntry {
                    id: 0,
                    from_peer: payload.from_peer,
                    to_peer: payload.to_peer,
                    conn_type: "file_transfer".to_string(),
                    timestamp: String::new(),
                    note: payload.note,
                }),
            )
        }
    }
}

/// `GET /api/audit/conn` -- query connection audit log (requires "view" on "audit").
pub async fn get_conn_audit(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<serde_json::Value>) {
    if !roles::has_permission(&claims.user_id, "audit", "view", &db).await {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error": "admin access required"})),
        );
    }

    match db.list_audit_logs().await {
        Ok(rows) => {
            let entries: Vec<AuditEntry> = rows.into_iter().map(AuditEntry::from).collect();
            (StatusCode::OK, Json(serde_json::to_value(entries).unwrap()))
        }
        Err(e) => {
            log::error!("Failed to list audit logs: {}", e);
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
        format!("test_audit_{}.sqlite3", uuid::Uuid::new_v4())
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn test_audit_insert_and_list() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let e1 = db
            .insert_audit_log("peer_a", "peer_b", "remote_desktop", "")
            .await
            .unwrap();
        let e2 = db
            .insert_audit_log("peer_c", "peer_d", "file_transfer", "sent file")
            .await
            .unwrap();

        assert_eq!(e1.id, 1);
        assert_eq!(e2.id, 2);

        let logs = db.list_audit_logs().await.unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].from_peer, "peer_a");
        assert_eq!(logs[0].conn_type, "remote_desktop");
        assert_eq!(logs[1].conn_type, "file_transfer");
        assert_eq!(logs[1].note, "sent file");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_audit_entry_has_timestamp() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let entry = db
            .insert_audit_log("a", "b", "test", "")
            .await
            .unwrap();
        assert!(!entry.timestamp.is_empty(), "timestamp should be set by database");

        cleanup(&db_path);
    }

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            id: 1,
            from_peer: "peer_a".into(),
            to_peer: "peer_b".into(),
            conn_type: "remote_desktop".into(),
            timestamp: "2024-01-01 00:00:00".into(),
            note: "test".into(),
        };
        let json = serde_json::to_value(&entry).unwrap();
        assert_eq!(json["from_peer"], "peer_a");
        assert_eq!(json["conn_type"], "remote_desktop");
    }

    #[test]
    fn test_conn_audit_request_deserialization() {
        let json_str = r#"{"from_peer":"a","to_peer":"b"}"#;
        let req: ConnAuditRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.from_peer, "a");
        assert_eq!(req.conn_type, "remote_desktop"); // default
    }

    #[test]
    fn test_file_audit_request_deserialization() {
        let json_str = r#"{"from_peer":"a","to_peer":"b","note":"myfile.txt"}"#;
        let req: FileAuditRequest = serde_json::from_str(json_str).unwrap();
        assert_eq!(req.from_peer, "a");
        assert_eq!(req.note, "myfile.txt");
    }

    #[tokio::test]
    async fn test_audit_logs_persist() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        db.insert_audit_log("p1", "p2", "remote_desktop", "note1")
            .await
            .unwrap();
        db.insert_audit_log("p3", "p4", "file_transfer", "note2")
            .await
            .unwrap();

        // Re-open the database to verify persistence
        let db2 = Database::new(&db_path).await.unwrap();
        let logs = db2.list_audit_logs().await.unwrap();
        assert_eq!(logs.len(), 2);
        assert_eq!(logs[0].from_peer, "p1");
        assert_eq!(logs[1].note, "note2");

        cleanup(&db_path);
    }
}
