use axum::{
    extract::{Extension, Path},
    http::StatusCode,
    Json,
};
use hbb_common::log;
use serde::{Deserialize, Serialize};

use crate::api::auth::AuthUser;
use crate::database::{AbRow, Database};

// ---------------------------------------------------------------------------
// Address book model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AbEntry {
    pub id: String,
    pub peer_id: String,
    #[serde(default)]
    pub alias: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub hash: String,
}

#[derive(Debug, Serialize)]
pub struct AbResponse {
    pub entries: Vec<AbEntry>,
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateAbRequest {
    #[serde(default)]
    pub entries: Vec<AbEntry>,
    #[serde(default)]
    pub tags: Vec<String>,
}

/// Convert a database row into an AbEntry.
fn ab_entry_from_row(row: &AbRow) -> AbEntry {
    let tags: Vec<String> = serde_json::from_str(&row.tags).unwrap_or_default();
    AbEntry {
        id: row.id.clone(),
        peer_id: row.peer_id.clone(),
        alias: row.alias.clone(),
        tags,
        hash: row.hash.clone(),
    }
}

/// Convert an AbEntry into a database row (user_id filled by caller).
fn ab_row_from_entry(entry: &AbEntry, user_id: &str) -> AbRow {
    AbRow {
        id: entry.id.clone(),
        user_id: user_id.to_string(),
        peer_id: entry.peer_id.clone(),
        alias: entry.alias.clone(),
        tags: serde_json::to_string(&entry.tags).unwrap_or_else(|_| "[]".to_string()),
        hash: entry.hash.clone(),
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// `GET /api/ab` -- get current user's address book.
pub async fn get_ab(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
) -> (StatusCode, Json<AbResponse>) {
    let user_id = claims.user_id.clone();
    match db.get_address_book_entries(&user_id).await {
        Ok(rows) => {
            let entries: Vec<AbEntry> = rows.iter().map(ab_entry_from_row).collect();
            // Collect unique tags from all entries
            let mut all_tags: Vec<String> = entries
                .iter()
                .flat_map(|e| e.tags.clone())
                .collect();
            all_tags.sort();
            all_tags.dedup();
            (StatusCode::OK, Json(AbResponse { entries, tags: all_tags }))
        }
        Err(e) => {
            log::error!("Failed to get address book: {}", e);
            (StatusCode::OK, Json(AbResponse { entries: vec![], tags: vec![] }))
        }
    }
}

/// `POST /api/ab` -- create or update current user's address book.
pub async fn update_ab(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Json(payload): Json<UpdateAbRequest>,
) -> (StatusCode, Json<AbResponse>) {
    let user_id = claims.user_id.clone();
    let rows: Vec<AbRow> = payload
        .entries
        .iter()
        .map(|e| ab_row_from_entry(e, &user_id))
        .collect();

    if let Err(e) = db.replace_address_book(&user_id, &rows).await {
        log::error!("Failed to update address book: {}", e);
    }

    // Return what we just saved, plus the tags from the request
    let entries: Vec<AbEntry> = payload.entries;
    let tags = payload.tags;
    (StatusCode::OK, Json(AbResponse { entries, tags }))
}

/// `DELETE /api/ab/entries/:id` -- delete an entry from the current user's address book.
pub async fn delete_ab_entry(
    AuthUser(claims): AuthUser,
    Extension(db): Extension<Database>,
    Path(entry_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let user_id = claims.user_id.clone();
    match db.delete_address_book_entry(&user_id, &entry_id).await {
        Ok(true) => (StatusCode::OK, Json(serde_json::json!({"message": "entry deleted"}))),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "entry not found"})),
        ),
        Err(e) => {
            log::error!("Failed to delete address book entry: {}", e);
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
        format!("test_ab_{}.sqlite3", uuid::Uuid::new_v4())
    }

    fn cleanup(path: &str) {
        let _ = std::fs::remove_file(path);
    }

    /// Create a test user in the DB, returning the user ID.
    async fn create_test_user(db: &Database, name: &str) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let hash = bcrypt::hash("pass", 4).unwrap();
        db.insert_user(&id, name, &format!("{}@test.com", name), &hash, false)
            .await
            .unwrap();
        id
    }

    #[tokio::test]
    async fn test_address_book_empty_by_default() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let uid = create_test_user(&db, "user1").await;
        let entries = db.get_address_book_entries(&uid).await.unwrap();
        assert!(entries.is_empty());

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_address_book_insert_and_retrieve() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let uid = create_test_user(&db, "user1").await;
        let entry = AbEntry {
            id: "e1".into(),
            peer_id: "peer123".into(),
            alias: "My PC".into(),
            tags: vec!["home".into()],
            hash: "abc".into(),
        };
        let rows = vec![ab_row_from_entry(&entry, &uid)];
        db.replace_address_book(&uid, &rows).await.unwrap();

        let result = db.get_address_book_entries(&uid).await.unwrap();
        assert_eq!(result.len(), 1);
        let e = ab_entry_from_row(&result[0]);
        assert_eq!(e.peer_id, "peer123");
        assert_eq!(e.alias, "My PC");
        assert_eq!(e.tags, vec!["home".to_string()]);

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_address_book_delete_entry() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let uid = create_test_user(&db, "user1").await;
        let entries = vec![
            ab_row_from_entry(
                &AbEntry { id: "e1".into(), peer_id: "peer1".into(), alias: "".into(), tags: vec![], hash: "".into() },
                &uid,
            ),
            ab_row_from_entry(
                &AbEntry { id: "e2".into(), peer_id: "peer2".into(), alias: "".into(), tags: vec![], hash: "".into() },
                &uid,
            ),
        ];
        db.replace_address_book(&uid, &entries).await.unwrap();

        assert!(db.delete_address_book_entry(&uid, "e1").await.unwrap());
        let remaining = db.get_address_book_entries(&uid).await.unwrap();
        assert_eq!(remaining.len(), 1);
        assert_eq!(remaining[0].id, "e2");

        cleanup(&db_path);
    }

    #[tokio::test]
    async fn test_address_book_per_user_isolation() {
        let db_path = temp_db_path();
        let db = Database::new(&db_path).await.unwrap();

        let uid1 = create_test_user(&db, "user1").await;
        let uid2 = create_test_user(&db, "user2").await;
        let e1 = vec![ab_row_from_entry(
            &AbEntry { id: "u1e1".into(), peer_id: "peer_u1".into(), alias: "".into(), tags: vec![], hash: "".into() },
            &uid1,
        )];
        let e2 = vec![ab_row_from_entry(
            &AbEntry { id: "u2e1".into(), peer_id: "peer_u2".into(), alias: "".into(), tags: vec![], hash: "".into() },
            &uid2,
        )];
        db.replace_address_book(&uid1, &e1).await.unwrap();
        db.replace_address_book(&uid2, &e2).await.unwrap();

        let u1 = db.get_address_book_entries(&uid1).await.unwrap();
        let u2 = db.get_address_book_entries(&uid2).await.unwrap();
        assert_eq!(u1[0].peer_id, "peer_u1");
        assert_eq!(u2[0].peer_id, "peer_u2");

        cleanup(&db_path);
    }

    #[test]
    fn test_ab_entry_deserialization_defaults() {
        let json_str = r#"{"id":"e1","peer_id":"p1"}"#;
        let entry: AbEntry = serde_json::from_str(json_str).unwrap();
        assert_eq!(entry.id, "e1");
        assert_eq!(entry.peer_id, "p1");
        assert_eq!(entry.alias, "");
        assert!(entry.tags.is_empty());
        assert_eq!(entry.hash, "");
    }

    #[test]
    fn test_ab_response_serialization() {
        let resp = AbResponse {
            entries: vec![AbEntry {
                id: "e1".into(),
                peer_id: "peer1".into(),
                alias: "Test".into(),
                tags: vec!["tag1".into()],
                hash: "h1".into(),
            }],
            tags: vec!["tag1".into()],
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["entries"][0]["peer_id"], "peer1");
        assert_eq!(json["tags"][0], "tag1");
    }
}
