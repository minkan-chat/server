use super::Session;
use crate::{
    actors::User,
    fallible::{Error, ExpiredRefreshToken, InvalidRefreshToken, InvalidSignature},
    loader::TokenExpiryLoader,
    result_type,
};
use async_graphql::{dataloader::DataLoader, SimpleObject};
use chrono::{DateTime, Duration, Utc};
use jsonwebtoken::{
    decode, encode, errors::ErrorKind, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

result_type!(RefreshTokenResult, TokenPair);

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
/// Claims
///
/// Represents the different field in the JWT
pub struct Claims {
    /// expires at unix timestamp
    pub exp: i64,
    /// issued at unix timestamp
    pub iat: i64,
    /// the user this session belongs to
    pub sub: Uuid,
    /// not valid before unix timestamp
    pub nbf: i64,
    /// the id of this token (used for deny_list)
    pub jti: Uuid,
    /// the session id
    pub sid: Uuid,
    /// if its a refresh token or not
    pub rft: bool,
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

    pub async fn refresh(
        token: String,
        keys: (&EncodingKey, &DecodingKey),
        db: &Pool<Postgres>,
        loader: &DataLoader<TokenExpiryLoader>,
    ) -> Result<Self, Error> {
        lazy_static! {
            static ref VALIDATION: Validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        }

        let token = decode::<Claims>(&token, keys.1, &VALIDATION).map_err(|e| match e.kind() {
            ErrorKind::InvalidSignature => Error::InvalidSignature(InvalidSignature {
                description: "jwt has an invalid signature".to_string(),
                hint: None,
            }),
            ErrorKind::ExpiredSignature => Error::ExpiredRefreshToken(ExpiredRefreshToken {
                description: "refresh token is expired".to_string(),
                hint: Some(
                    concat!(
                        "if you have client-side checks ",
                        "for expiration to avoid ",
                        "unnecessary requests, make sure ",
                        "that your local time is correct"
                    )
                    .to_string(),
                ),
            }),
            _ => Error::InvalidRefreshToken(InvalidRefreshToken {
                description: "not a valid jwt token".to_string(),
                hint: None,
            }),
        })?;

        if !token.claims.rft {
            return Err(Error::InvalidRefreshToken(InvalidRefreshToken {
                description: "not a refresh token".to_string(),
                hint: Some("check the ``rft`` claim".to_string()),
            }));
        }

        let token_expiry: DateTime<Utc> = loader.load_one(token.claims.sub).await.unwrap().unwrap();

        if token_expiry.timestamp() > token.claims.iat {
            return Err(Error::ExpiredRefreshToken(ExpiredRefreshToken {
                description: "user's token expiry is higher than iat".to_string(),
                hint: None,
            }));
        }

        if sqlx::query!(
            r#"
        SELECT exists(SELECT 1 FROM denied_tokens WHERE token_id = $1) AS "exists!"
        "#,
            token.claims.jti
        )
        .fetch_one(db)
        .await
        .map_err(|_| Error::Unexpected("database error getting token expiry".into()))?
        .exists
        {
            User::from(token.claims.sub)
                .set_token_expiry(None, db)
                .await;
            return Err(Error::ExpiredRefreshToken(ExpiredRefreshToken {
                description: "refresh token is expired".to_string(),
                hint: None,
            }));
        }

        Ok(Self::new(token.claims.into(), keys.0).await)
    }
}
