use crate::models::graphql::{
    mutations::helpers::{
        insert_user, parse_cert, parse_signature, validate_challenge, validate_username,
    },
    types::{
        AuthenticatedUser, InvalidCertificate, InvalidChallenge, InvalidSignature,
        PrivateCertificate, SignupError,
    },
};
use jsonwebtoken::EncodingKey;
use moka::future::Cache;
use regex::Regex;

use super::{
    scalars::Bytes,
    types::{
        AuthenticationCredentialsUserInput, AuthenticationResult, SignupResult, SignupUserInput,
    },
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};
use async_graphql::{Context, Object, ID};
use sequoia_openpgp::{packet::Signature, parse::Parse, Cert};
use sqlx::PgPool;

mod helpers {

    use std::str::FromStr;

    use chrono::{DateTime, Duration, Utc};
    use jsonwebtoken::{encode, EncodingKey, Header};
    use lazy_static::lazy_static;
    use log::{debug, info, warn};
    use moka::future::Cache;
    use sequoia_openpgp::serialize::SerializeInto;
    use serde::{Deserialize, Serialize};

    use crate::models::graphql::types::{CertificateTaken, InvalidUsername, UsernameUnavailable};

    use super::*;
    // Write tests for helper methods

    #[cfg(test)]
    mod tests {
        use sequoia_openpgp::serialize::MarshalInto;

        use crate::models::graphql::{
            mutations::helpers::{parse_cert, parse_signature, validate_challenge},
            scalars::Bytes,
        };

        // TODO: get external verified test vectors

        const CLIENT_CERT_ARMOR: &[u8] = include_bytes!("../../../other/test_keys/client.asc");
        const CLIENT_CERT: &[u8] = include_bytes!("../../../other/test_keys/client.pgp");
        const CLIENT_CERT_FINGERPRINT: &str = "E5614CD3EAB9A60B1DB9F221E9AE9ECA69251D3F";

        const CLIENT_KEYRING_ARMOR: &[u8] =
            include_bytes!("../../../other/test_keys/client_keyring.asc");
        const CLIENT_KEYRING: &[u8] = include_bytes!("../../../other/test_keys/client_keyring.pgp");

        const CHALLENGE: &str = "ba7b10e7-bcb3-4c4a-9a10-b132a08f3b92";
        const INVALID_CHALLENGE: &str = "f1e3a8aa-e1ab-46ec-bff2-22f19a7c2137";

        // TODO: get better source for the test vector
        const SIGNATURE: &[u8] = include_bytes!("../../../other/test_keys/challenge_signature.pgp");

        // the signature itself is valid but made by another user's key
        const INVALID_SIGNATURE: &[u8] =
            include_bytes!("../../../other/test_keys/invalid_challenge_signature.pgp");

        #[test]
        fn test_parse_cert() {
            // cert bytes but armor
            let mut e = vec![];
            let cert_bytes_armor = Bytes(bytes::Bytes::from_static(CLIENT_CERT_ARMOR));
            let cert_bytes_armor = parse_cert(&cert_bytes_armor, &mut e)
                .unwrap_or_else(|| panic!("Failed to parse armor cert"));
            assert_eq!(
                CLIENT_CERT_FINGERPRINT,
                cert_bytes_armor.fingerprint().to_hex(),
                "Fingerprint not matched, check test cert!"
            );
            assert!(
                e.is_empty(),
                "parse_cert with armor completed fine but added an error anyway"
            );

            // cert bytes
            let cert_bytes = Bytes(bytes::Bytes::from_static(CLIENT_CERT));
            let cert_bytes =
                parse_cert(&cert_bytes, &mut e).unwrap_or_else(|| panic!("Failed to parse cert"));
            assert_eq!(
                CLIENT_CERT_FINGERPRINT,
                cert_bytes.fingerprint().to_hex(),
                "Fingerprint not matched, check test cert!"
            );

            // client keyring (multiple certs) in armor
            let cert_keyring_armor = Bytes(bytes::Bytes::from_static(CLIENT_KEYRING_ARMOR));
            let cert_keyring_armor = parse_cert(&cert_keyring_armor, &mut e);
            assert!(
                cert_keyring_armor.is_none(),
                "parse_cert did accept a keyring!"
            );
            assert_eq!(
                1,
                e.len(),
                "parse_cert failed to parse the cert but did not add an error"
            );

            e.clear();

            let cert_keyring = Bytes(bytes::Bytes::from_static(CLIENT_KEYRING));
            let cert_keyring = parse_cert(&cert_keyring, &mut e);
            assert!(cert_keyring.is_none(), "parse_cert parsed a cert keyring!");
            assert_eq!(
                1,
                e.len(),
                "parse_cert failed to parse the cert but did not add an error"
            );
        }

        #[test]
        fn test_parse_signature() {
            let mut e = vec![];
            let sig = Bytes(bytes::Bytes::from_static(SIGNATURE));
            let sig = parse_signature(&sig, &mut e)
                .unwrap_or_else(|| panic!("Failed to parse signature, check test signature file!"));

            assert_eq!(
                sig.to_vec().unwrap(),
                SIGNATURE,
                "Parsed signature not equal to test signature"
            );

            assert!(
                e.is_empty(),
                "parse_signature successful but still added an error"
            );

            // simulate malformed signature
            let malformed_sig = parse_signature(
                &Bytes(bytes::Bytes::from_static(&[0x1u8, 0x2u8, 0x3u8])),
                &mut e,
            );

            assert!(
                malformed_sig.is_none(),
                "parse_signature parsed a malformed signature"
            );

            assert_eq!(
                1,
                e.len(),
                "parse_signature failed to parse a signature but didn't add an error"
            );
        }

        #[test]
        fn test_validate_challenge() {
            let mut e = vec![];
            let mut sig = parse_signature(&Bytes(bytes::Bytes::from_static(SIGNATURE)), &mut e)
                .unwrap_or_else(|| {
                    panic!("parse_signature failed to parse valid signature, check test signature!")
                });
            assert!(e.is_empty());

            let cert = parse_cert(&Bytes(bytes::Bytes::from_static(&CLIENT_CERT)), &mut e)
                .unwrap_or_else(|| {
                    panic!("parse_cert failed to parse test certificate, check test cert!")
                });
            assert!(e.is_empty());

            let valid = validate_challenge(CHALLENGE, &mut sig, &cert, &mut &mut e);
            assert!(
                valid,
                "validate_challenge said challenge signature is invalid but it should be valid"
            );
            assert!(e.is_empty());

            let invalid = validate_challenge(INVALID_CHALLENGE, &mut sig, &cert, &mut e);
            assert!(
                !invalid,
                "validate_challenge validate a invalid challenge as valid!"
            );
            assert_eq!(e.len(), 1);

            e.clear();

            // a signature that is for another challenge
            let mut sig =
                parse_signature(&Bytes(bytes::Bytes::from_static(INVALID_SIGNATURE)), &mut e)
                    .unwrap_or_else(|| {
                        panic!("parse_signature failed to parse a cryptically valid signature")
                    });
            assert!(e.is_empty());

            let invalid = validate_challenge(CHALLENGE, &mut sig, &cert, &mut e);
            assert!(
                !invalid,
                "validate_challenge validated a signature from another challenge as valid"
            );
            assert_eq!(1, e.len());
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    struct Claims {
        exp: i64,
        iat: i64,
        nbf: i64,
        sub: uuid::Uuid,
        jti: uuid::Uuid,
        // if the token is a refresh token
        rft: bool,
    }

    /// returns (access token, first refresh token)
    pub(super) async fn create_session(
        key: &EncodingKey,
        user_id: uuid::Uuid,
        session_name: Option<&str>,
        db: &PgPool,
    ) -> (String, String) {
        let now: DateTime<Utc> = Utc::now();
        let session_id: uuid::Uuid = sqlx::query!(
            r#"
        INSERT INTO session_info (
            user_id,
            session_name
        ) VALUES ($1, $2)
        RETURNING session_id
        "#,
            user_id,
            session_name,
        )
        .fetch_one(db)
        .await
        .expect("The database should return a session id")
        .session_id;

        let claims = Claims {
            exp: (now + Duration::hours(12)).timestamp(),
            iat: now.timestamp(),
            jti: session_id,
            nbf: now.timestamp(),
            rft: false,
            sub: user_id,
        };

        let access_token =
            encode(&Header::default(), &claims, key).expect("Failed to create access token");

        let claims = Claims {
            exp: (now + Duration::hours(7)).timestamp(),
            iat: now.timestamp(),
            jti: session_id,
            nbf: now.timestamp(),
            rft: true,
            sub: user_id,
        };

        let refresh_token =
            encode(&Header::default(), &claims, key).expect("Failed to create refresh token");

        (access_token, refresh_token)
    }

    pub(super) async fn get_token_expiry(user_id: uuid::Uuid, ctx: &Context<'_>) -> i64 {
        let cache = ctx.data::<Cache<uuid::Uuid, i64>>().unwrap();
        cache
            .get_or_insert_with(user_id, async {
                let db = ctx.data::<PgPool>().unwrap();
                debug!("Getting token expiry for {}", &user_id);
                let r = sqlx::query!(
                    r#"
            SELECT token_expiry FROM users WHERE user_id = $1
            "#,
                    user_id
                )
                .fetch_one(db)
                .await;

                r.expect("The database didn't return a token_expiry")
                    .token_expiry
                    .timestamp()
            })
            .await
    }
    /// Returns true of the challenge is valid
    pub(super) fn validate_challenge(
        challenge: &str,
        signature: &mut Signature,
        cert: &Cert,
        errors: &mut Vec<SignupError>,
    ) -> bool {
        match signature.verify_message(cert.primary_key().key(), challenge) {
            Ok(_) => true,
            Err(_) => {
                errors.push(
                    SignupError::InvalidSignature(
                        InvalidSignature {
                            description: format!("Signature for challenge `{}` is invalid. Note: You have to generate a new challenge.", &challenge)
                        }
                    )
                );
                false
            }
        }
    }

    pub(super) fn parse_signature(sig: &Bytes, errors: &mut Vec<SignupError>) -> Option<Signature> {
        match Signature::from_bytes(&sig.0) {
            Ok(sig) => Some(sig),
            Err(_) => {
                errors.push(SignupError::InvalidSignature(InvalidSignature {
                    description: "Failed to parse signature. Note: Signature not checked."
                        .to_string(),
                }));
                None
            }
        }
    }

    /// Helper method to parse a [``sequoia_openpgp::cert::Cert``] and add the GraphQL errors if needed
    pub(super) fn parse_cert(cert: &Bytes, errors: &mut Vec<SignupError>) -> Option<Cert> {
        // TODO: add cert policy/check that the Certificate has C E A S keys that all work with the signal/mls protocol
        // TODO: make sure to remove certifications from other users.
        if let Ok(cert) = Cert::from_bytes(&cert.0) {
            if cert.is_tsk() {
                return Some(cert);
            } else {
                errors.push(SignupError::InvalidCertificate(InvalidCertificate {
                    description: "Certificate is valid but has no encrypted secret parts. Note: Signature not checked."
                        .to_string(),
                }))
            }
        } else {
            errors.push(SignupError::InvalidCertificate(InvalidCertificate {
                description: "Failed to parse certificate. Note: Signature not checked."
                    .to_string(),
            }));
        }
        None
    }

    /// Adds the user or an error to the Result
    pub(super) async fn insert_user(
        user: SignupUserInput,
        result: &mut SignupResult,
        cert: Cert,
        db: &PgPool,
        key: &EncodingKey,
    ) {
        let r = sqlx::query!(
            // insert the user into the users table, let the database generate a uuid,
            // insert the public certificate into the pubkeys table with the uuid as
            // primary key and at the end return the uuid generated by the database
            r#"
            WITH user_result AS (
                INSERT INTO users ( username, hash, enc_cert ) 
                VALUES ( $1, $2, $3 )
                RETURNING user_id
            )
            INSERT INTO pub_certs ( user_id, cert_fingerprint, pub_cert ) VALUES (
                ( SELECT user_id from user_result ), $4, $5
            ) RETURNING (SELECT user_id FROM user_result)
            "#,
            user.name,
            hash_password(&user.hash).await,
            &cert.as_tsk().to_vec().unwrap(),
            cert.fingerprint().to_hex(),
            cert.to_vec().unwrap(),
        )
        .fetch_one(db)
        .await;

        // please tell me there is a better way to do this
        match r {
            Ok(r) => {
                let id = ID(r
                    .user_id
                    .expect("The database should return an id")
                    .to_string());
                // construct the user for the result
                info!(
                    "Registered new user `{}` with ID `{}` and certificate fingerprint `{}`.",
                    user.name,
                    id.to_string(),
                    cert.fingerprint().to_spaced_hex(),
                );
                let (access_token, refresh_token) =
                    create_session(key, uuid::Uuid::from_str(id.as_str()).unwrap(), None, db).await;
                result.user = Some(AuthenticatedUser {
                    id,
                    certificate: PrivateCertificate { cert: cert },
                    name: user.name,
                    access_token,
                    refresh_token,
                });
            }
            Err(e) => {
                match e {
                    sqlx::Error::Database(e) => {
                        // we use Postgres so this shouldn't panic. If it does, there's something really wrong.
                        let e = e.downcast_ref::<sqlx::postgres::PgDatabaseError>();
                        match (e.code(), e.constraint()) {
                            // 23505 = unique_violation (https://www.postgresql.org/docs/9.4/errcodes-appendix.html)
                            ("23505", Some("users_enc_cert_key")) => {
                                result.errors.push(SignupError::CertificateTaken(
                                    CertificateTaken {
                                        description: "Another user has the same Certificate! Note: Username not checked."
                                            .to_string(),
                                    },
                                ));
                            }
                            ("23505", Some("users_username_key")) => result.errors.push(
                                SignupError::UsernameUnavailable(UsernameUnavailable {
                                    description: format!("Username `{}` is unavailable", user.name),
                                }),
                            ),
                            ("23505", Some("pub_certs_cert_fingerprint_key")) => result
                                .errors
                                .push(SignupError::CertificateTaken(CertificateTaken {
                                    description:
                                        "Another user's certificate has the same fingerprint!"
                                            .to_string(),
                                })),
                            ("23505", Some("pub_certs_pub_cert_key")) => result.errors.push(
                                SignupError::CertificateTaken(CertificateTaken {
                                    description: "Another user has the same public certificate."
                                        .to_string(),
                                }),
                            ),
                            _ => {
                                warn!("Unknown database error: {}", e);
                            }
                        }
                    }
                    _ => warn!("Unknown sqlx error: {}", e),
                }
            }
        }
    }

    pub(super) fn validate_username(username: &str, errors: &mut Vec<SignupError>) {
        let username = username.to_lowercase();

        lazy_static! {
            static ref RE: Regex = Regex::new("^[a-z0-9_]{3,16}$").unwrap();
        }

        if !RE.is_match(&username) {
            errors.push(SignupError::InvalidUsername(InvalidUsername {
                description:
                    "Username contains invalid characters. Only letters, numbers and underscores are allowed (3-16)."
                        .to_string(),
            }))
        }
    }

    /// returns a PHC string ($argon2id$=19$...). Note: The string contains the salt.
    pub(super) async fn hash_password(master_password_hash: &Bytes) -> String {
        // TODO: spawn thread because hashing takes 9-14ms
        let salt = SaltString::generate(&mut rand::rngs::OsRng);

        lazy_static! {
            static ref ARGON2: Argon2<'static> = Argon2::default();
        }

        ARGON2
            .hash_password_simple(&master_password_hash.0, &salt)
            .unwrap()
            .to_string()
    }
}
pub(crate) struct Mutation;

#[Object]
/// The mutation root
impl Mutation {
    /// The clients sends a SignupUserInput to the server with all information
    async fn signup(&self, ctx: &Context<'_>, user: SignupUserInput) -> SignupResult {
        let challenges = ctx.data::<Cache<String, ()>>().unwrap();
        let mut result = SignupResult {
            user: None,
            errors: vec![],
        };

        validate_username(&user.name, &mut result.errors);

        if challenges.get(&user.challenge).is_none() {
            result
                .errors
                .push(SignupError::InvalidChallenge(InvalidChallenge {
                    description: format!(
                        "`{}` is not in the active challenge pool.",
                        &user.challenge
                    ),
                }));
        } else {
            challenges.invalidate(&user.challenge).await;
        }

        let cert = parse_cert(&user.certificate, &mut result.errors);
        let sig = parse_signature(&user.signature, &mut result.errors);

        if let (Some(cert), Some(mut sig)) = (cert, sig) {
            validate_challenge(&user.challenge, &mut sig, &cert, &mut result.errors);

            // If anything went wrong, we won't continue here
            if result.errors.is_empty() {
                let db = ctx.data::<PgPool>().unwrap();
                let key = ctx.data::<EncodingKey>().unwrap();
                // this might fail, if so, errors are added to the result
                insert_user(user, &mut result, cert, db, key).await;
            }
        }

        // return the Result. It may include errors, may include a User.
        // The result is constructed by the helper method
        result
    }

    /// The clients sends a AuthenticationCredentialsUserInput
    async fn authenticate(
        &self,
        _ctx: &Context<'_>,
        _credentials: AuthenticationCredentialsUserInput,
    ) -> AuthenticationResult {
        AuthenticationResult {
            user: None,
            errors: vec![],
        }
    }
}
