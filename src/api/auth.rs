use axum::{
    async_trait,
    extract::{FromRequest, RequestParts},
    http::StatusCode,
};
use chrono::Utc;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

/// JWT secret. In production this should come from configuration / environment.
/// For the skeleton we use a compile-time constant; `jwt_secret()` is the
/// single place to swap it out later.
pub fn jwt_secret() -> &'static [u8] {
    static SECRET: &[u8] = b"rustdesk-pro-api-secret-change-me";
    let env_secret = option_env!("RUSTDESK_API_JWT_SECRET");
    match env_secret {
        Some(s) if !s.is_empty() => s.as_bytes(),
        _ => SECRET,
    }
}

/// Claims embedded in every JWT.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Claims {
    /// User ID (UUID string primary key).
    pub user_id: String,
    /// User email address.
    pub email: String,
    /// Expiration time (UTC epoch seconds).
    pub exp: i64,
}

/// Token lifetime: 24 hours.
const TOKEN_LIFETIME_SECS: i64 = 24 * 60 * 60;

/// Create a signed JWT for the given user.
pub fn create_token(user_id: &str, email: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let claims = Claims {
        user_id: user_id.to_string(),
        email: email.to_string(),
        exp: Utc::now().timestamp() + TOKEN_LIFETIME_SECS,
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret()),
    )
}

/// Validate a JWT and return the embedded claims.
pub fn validate_token(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(jwt_secret()),
        &Validation::default(),
    )?;
    Ok(token_data.claims)
}

/// Axum extractor that validates the `Authorization: Bearer <token>` header
/// and yields the authenticated [`Claims`].
///
/// Routes that include `AuthUser` in their handler signature are automatically
/// protected; requests without a valid token receive `401 Unauthorized`.
#[derive(Debug, Clone)]
pub struct AuthUser(pub Claims);

#[async_trait]
impl<B: Send> FromRequest<B> for AuthUser {
    type Rejection = (StatusCode, &'static str);

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let auth_header = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok());

        let token = match auth_header {
            Some(h) if h.starts_with("Bearer ") => &h[7..],
            _ => return Err((StatusCode::UNAUTHORIZED, "Missing or invalid Authorization header")),
        };

        let claims = validate_token(token)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "Invalid or expired token"))?;

        Ok(AuthUser(claims))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_validate_token() {
        let token = create_token("42", "test@example.com").expect("token creation should succeed");
        let claims = validate_token(&token).expect("token validation should succeed");
        assert_eq!(claims.user_id, "42");
        assert_eq!(claims.email, "test@example.com");
        assert!(claims.exp > Utc::now().timestamp());
    }

    #[test]
    fn test_validate_token_rejects_garbage() {
        let result = validate_token("not.a.valid.jwt");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_token_rejects_expired() {
        // Manually build a token that expired in the past.
        let claims = Claims {
            user_id: "1".into(),
            email: "expired@example.com".into(),
            exp: Utc::now().timestamp() - 3600, // 1 hour ago
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(jwt_secret()),
        )
        .unwrap();
        let result = validate_token(&token);
        assert!(result.is_err(), "expired token should be rejected");
    }

    #[test]
    fn test_claims_round_trip_fields() {
        let token = create_token("99", "admin@rustdesk.local").unwrap();
        let claims = validate_token(&token).unwrap();
        assert_eq!(claims.user_id, "99");
        assert_eq!(claims.email, "admin@rustdesk.local");
    }

    #[test]
    fn test_token_with_wrong_secret_rejected() {
        let token = create_token("1", "user@test.com").unwrap();
        // Try to decode with a different secret
        let result = decode::<Claims>(
            &token,
            &DecodingKey::from_secret(b"wrong-secret"),
            &Validation::default(),
        );
        assert!(result.is_err(), "token signed with different secret should be rejected");
    }
}
