use actix_web::{http::header::Header, HttpRequest};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use async_graphql::{guard::Guard, Context, Request};
use async_trait::async_trait;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use lazy_static::lazy_static;
use moka::future::Cache;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use crate::auth::token::Claims;

/// AuthenticationGuard
///
/// makes sure that there is a valid JWT in the request.
/// [``crate::auth::token::Claims``] can be safely
/// recieved via [``Context``]
pub struct AuthenticationGuard;

#[async_trait]
impl Guard for AuthenticationGuard {
    async fn check(&self, ctx: &Context<'_>) -> async_graphql::Result<()> {
        match ctx.data::<Claims>() {
            Ok(_) => Ok(()),
            Err(_) => Err("not authenticated".into()),
        }
    }
}

impl AuthenticationGuard {
    /// Tries to parse and validate a JWT
    /// Looks the token expiry up in the cache or loads it from the database
    pub async fn parse(
        req: Request,
        http_request: &HttpRequest,
        key: &DecodingKey,
        tec: &Cache<Uuid, i64>,
        db: &Pool<Postgres>,
    ) -> Request {
        let token = Authorization::<Bearer>::parse(http_request);
        if let Ok(token) = token {
            lazy_static! {
                static ref VALIDATION: Validation = Validation::new(Algorithm::HS256);
            }
            if let Ok(token) = decode::<Claims>(token.as_ref().token(), key, &VALIDATION) {
                // early return because refresh tokens are not authentication tokens
                if token.claims.rft {
                    return req;
                }

                let db = db.clone(); // #12
                let user_id = token.claims.sub; // needed because of #12 and on success, we move ownership into the request's context
                let token_expiry = tec
                    .get_or_insert_with(token.claims.sub, async move {
                        sqlx::query!(
                            r#"
                    SELECT token_expiry FROM users WHERE user_id = $1
                    "#,
                            user_id,
                        )
                        .fetch_one(&db)
                        .await
                        .unwrap()
                        .token_expiry
                        .timestamp()
                    })
                    .await;

                // if the token was issued before the user's token expiry (kill switch)
                // the token expiry is checked while decoding
                if token.claims.iat > token_expiry {
                    return req.data(token.claims);
                }
            }
        }

        req
    }
}
