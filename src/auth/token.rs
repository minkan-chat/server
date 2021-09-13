use async_graphql::SimpleObject;
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::Session;

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
/// Claims
///
/// Represents the different field in the JWT
pub struct Claims {
    /// expires at unix timestamp
    exp: i64,
    /// issued at unix timestamp
    iat: i64,
    /// the user this session belongs to
    sub: Uuid,
    /// not valid before unix timestamp
    nbf: i64,
    /// the id of this token (used for deny_list)
    jti: Uuid,
    /// the session id
    sid: Uuid,
    /// if its a refresh token or not
    rft: bool,
}

#[derive(SimpleObject)]
/// TokenPair
///
/// Contains a access token and the refresh token to request the next ``TokenPair``
#[non_exhaustive]
pub struct TokenPair {
    /// The token that is used for authentication in the [``Authorization`` header][1].
    /// The format is ``Authorization: Bearer <token>``.
    ///
    /// [1]: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization
    access_token: String,
    /// The token used as ``token`` in the ``refreshToken`` mutation
    refresh_token: String,

    /// the corresponding [``Session``] object
    session: Session,
}

impl TokenPair {
    /// Generate a new TokenPair from a [``Session``]
    ///
    /// # Panics
    ///
    /// panics if the [``encode``] method returns [``Err``]. Should only be the case, if the key is malformed
    // TODO: mid-prio: benchmark to see if this takes too long and blocks
    pub async fn new(session: Session, key: &EncodingKey) -> Self {
        let now = Utc::now();
        let future = (now + Duration::hours(12)).timestamp();
        let now = now.timestamp();

        let header = Header::new(Algorithm::EdDSA);

        let claims = Claims {
            exp: future,
            iat: now,
            jti: uuid::Uuid::new_v4(),
            sid: session.session_id,
            nbf: now,
            rft: false,
            sub: session.user_id,
        };

        let access_token = encode(&header, &claims, key).expect("cannot encode access token");

        let claims = Claims {
            exp: future,
            iat: now,
            jti: uuid::Uuid::new_v4(),
            sid: session.session_id,
            nbf: now,
            rft: true,
            sub: session.user_id,
        };

        let refresh_token = encode(&header, &claims, key).expect("cannot encode refresh token");

        Self {
            access_token,
            refresh_token,
            session,
        }
    }
}
