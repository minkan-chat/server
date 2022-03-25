use std::{collections::HashSet, hash::Hash, str::FromStr};

use chrono::Utc;
use openidconnect::{
    core::{
        CoreGenderClaim, CoreJsonWebKey, CoreJsonWebKeyType, CoreJsonWebKeyUse,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm,
    },
    AdditionalClaims, Audience, IdToken, IdTokenClaims, IdTokenVerifier,
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// A pair of an [`Identity`] and a [`Session`]
pub struct Identifier {
    identity: Identity,
    session: Session,
}

impl Identifier {
    /// Load an [`Identifer`] from a authentication token
    pub async fn load(
        token: &str,
        verifier: &IdTokenVerifier<
            '_,
            CoreJwsSigningAlgorithm,
            CoreJsonWebKeyType,
            CoreJsonWebKeyUse,
            CoreJsonWebKey,
        >,
        audiences: &HashSet<Audience>,
        pool: &PgPool,
    ) -> anyhow::Result<Self> {
        let token: IdTokenClaims<Session, CoreGenderClaim> = IdToken::<
            Session,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
            CoreJsonWebKeyType,
        >::from_str(token)?
        .into_claims(verifier, |_: Option<&_>| Ok(()))?;

        // ensure the token is intended for us
        anyhow::ensure!(
            token.audiences().iter().any(|a| audiences.contains(a)),
            "invalid audience"
        );
        // ensure the token is not expired
        anyhow::ensure!(token.expiration() > Utc::now(), "token expired");

        // use the `preferred_username` claim as username or else fallback to
        // the `sub` claim. A user can update their username later via the graphql api
        let username = token
            .preferred_username()
            .map(|name| name.as_str())
            .unwrap_or_else(|| token.subject().as_str());

        // if the database returns the id (one optional)
        sqlx::query!(
            r#"
            WITH info AS (
                -- a session is considered valid if it is not in the revoked_sessions table 
                -- e.g. the result from this select is null
                SELECT (SELECT id FROM revoked_sessions WHERE id=$1 LIMIT 1) IS NULL AS valid
            ),
            i AS (
                -- insert user if unknown
                INSERT INTO users(id, username) VALUES ($2, $3) ON CONFLICT DO NOTHING
            ),
            ii AS (
                -- insert session if unknown and not revoked
                INSERT INTO sessions(id, user_id) SELECT $1, $2 WHERE (SELECT valid FROM info) ON CONFLICT DO NOTHING
            )
            -- select the session if it is valid / not revoked
            SELECT id FROM sessions WHERE id=$1 AND (SELECT valid FROM info)
            "#,
            token.additional_claims().sid,
            token.subject().as_str(),
            username,
        )
        .fetch_optional(pool)
        .await?
        .ok_or(anyhow::anyhow!("session revoked"))?;

        Ok(Identifier {
            identity: Identity {
                subject: token.subject().to_string(),
            },
            session: Session {
                sid: token.additional_claims().sid.to_owned(),
            },
        })
    }
}

/// The minimal information we get from the OpenID Connect provider.
#[derive(Debug, Hash, PartialEq, Eq)]
pub struct Identity {
    /// `sub` claim
    subject: String,
}

/// A session is (or at least should) be bound to an installation of minkan on
/// the enduser's device. For example, if the user installed a desktop app for
/// minkan, the session should stay the same for that installation (even with
/// refresh token rotation). This allows us to keep track for how long we need
/// to store a message.
///
/// It uses the `sid` claim in the OpenID Connect tokens.
#[derive(Debug, Deserialize, Serialize, Hash, PartialEq, Eq)]
pub struct Session {
    sid: String,
}

impl AdditionalClaims for Session {}
