use axum::{http::StatusCode, Json};
use serde::{Deserialize, Serialize};

/// Response shape for `POST /api/heartbeat`.
///
/// The client reads `is_pro` from this response to unlock Pro UI features
/// (address-book sync, group management, strategy polling, session-recording
/// upload, CM hiding).  Additional fields are included so the response
/// matches the shape the RustDesk client already knows how to parse; they
/// are set to sensible defaults for now.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct HeartbeatResponse {
    /// The critical flag: when `true`, the client enables all Pro features.
    #[serde(rename = "is_pro")]
    pub is_pro: bool,

    /// Modified time of the user record (0 = never modified).
    #[serde(rename = "modified_at", skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<i64>,
}

/// `POST /api/heartbeat` — client heartbeat.
///
/// The only truly required field is `is_pro: true`.  Returning it unlocks the
/// client's Pro UI without any further server-side work.
pub async fn heartbeat() -> (StatusCode, Json<HeartbeatResponse>) {
    let resp = HeartbeatResponse {
        is_pro: true,
        modified_at: Some(0),
    };
    (StatusCode::OK, Json(resp))
}

// Also support GET for convenience / health-probe compatibility.
pub async fn heartbeat_get() -> (StatusCode, Json<HeartbeatResponse>) {
    heartbeat().await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    use hbb_common::tokio;

    #[tokio::test]
    async fn test_heartbeat_returns_is_pro_true() {
        let (status, Json(body)) = heartbeat().await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_pro, "heartbeat must return is_pro = true");
    }

    #[test]
    fn test_heartbeat_response_json_shape() {
        let resp = HeartbeatResponse {
            is_pro: true,
            modified_at: Some(0),
        };
        let json = serde_json::to_value(&resp).unwrap();
        assert_eq!(json["is_pro"], true);
        assert_eq!(json["modified_at"], 0);
    }

    #[test]
    fn test_heartbeat_response_deserializes() {
        let json_str = r#"{"is_pro":true,"modified_at":0}"#;
        let resp: HeartbeatResponse = serde_json::from_str(json_str).unwrap();
        assert!(resp.is_pro);
        assert_eq!(resp.modified_at, Some(0));
    }
}
