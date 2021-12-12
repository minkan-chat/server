//! This module handles authentication with the openid connect provider

use crate::config::Config;
use actix_web::{
    cookie::{Cookie, SameSite},
    error::{InternalError, UrlGenerationError},
    get,
    http::StatusCode,
    web::Data,
    HttpResponse,
};
use openidconnect::{
    core::CoreAuthenticationFlow, CsrfToken, Nonce, PkceCodeChallenge, PkceCodeVerifier,
};
use redis::{aio::ConnectionManager, AsyncCommands};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

#[derive(Serialize, Deserialize)]
/// Struct used to serialize and deserialize a state mapped to a nonce and pkce
struct StateStore {
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
}

#[get("/login")]
/// Redirects the User-Agent (browser) to the openid connect identity provider
/// for authentication
async fn login_redirect(
    config: Data<Config>,
    redis: Data<Mutex<ConnectionManager>>,
) -> actix_web::Result<HttpResponse> {
    // recieve the client
    let client = config
        .openid_connect
        .clone()
        .load_client()
        .await
        .map_err(|e| {
            InternalError::new(
                format!(
                    "cannot recieve openid connect identity provider client: {}",
                    e
                ),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?;

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let (auth_url, state, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .set_pkce_challenge(pkce_challenge)
        .url();

    // hash the nonce and state
    // they are returned as httpOnly cookies so javascript cannot steal them
    // after a succesful login, the hashes are compared to the state returned
    // from the identity provider and the nonce is compared with the nonce in
    // the token
    let nonce_hash = base64::encode(Sha256::digest(nonce.secret()));
    let state_hash = base64::encode(Sha256::digest(state.secret()));

    let redis_state = serde_json::to_string(&StateStore {
        nonce,
        pkce_verifier,
    })?;

    // get the ConnectionManager
    let mut redis = redis.lock().await;
    // the state is connected with the pkce_verifier to request the id token
    // the nonce is used to bind a token to a state
    let _: () = redis
        // expires in 5 minutes
        .set_ex(state.secret(), redis_state, 60 * 5)
        .await
        .map_err(|e| {
            InternalError::new(
                format!("cannot store in redis cache: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        })?;

    // the host used as base for the cookie `Domain` attribute
    let host: &str = config
        .openid_connect
        .redirect_url
        .host_str()
        .ok_or(UrlGenerationError::ParseError(url::ParseError::EmptyHost))?;

    /// prevents code duplication for state and nonce cookie
    fn cookie_secure<'a>(
        name: &'a str,
        value: &'a str,
        host: &'a str,
        path: &'a str,
    ) -> Cookie<'a> {
        Cookie::build(name, value)
            // because only the redirect_url must be able to read these cookies
            // the domain as well as the path can be set to exactly that
            .domain(host)
            .path(path)
            // from https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite#strict :
            // > Cookies will only be sent in a first-party context and not be
            // > sent along with requests initiated by third party websites.
            // Because the redirect to the callback url is made by a third party
            // website (the identity provider), we cannot use SameSite::Secure
            // instead, we use SameSite::Lax:
            // > Cookies are not sent on normal cross-site subrequests (for
            // > example to load images or frames into a third party site), but
            // > are sent when a **user is navigating to the origin site**
            // > (i.e., when following a link).
            .same_site(SameSite::Lax)
            .secure(true)
            // the cookie does not need to be accessible for javascript
            .http_only(true)
            .finish()
    }

    // the `Path` attribute for the cookie
    let path = config.openid_connect.redirect_url.path();
    let nonce = cookie_secure("oidc_nonce", &nonce_hash, host, path);
    let state = cookie_secure("oidc_state", &state_hash, host, path);
    // create the cookies
    Ok(HttpResponse::Found()
        .insert_header(("Location", auth_url.as_str()))
        .cookie(nonce)
        .cookie(state)
        .finish())
}
