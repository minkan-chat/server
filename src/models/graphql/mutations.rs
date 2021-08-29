use crate::models::graphql::{
    mutations::helpers::{
        create_session, delete_session, generate_token, get_token_expiry, insert_user,
        is_refresh_token_denied, parse_cert, parse_signature, set_token_expiry, validate_challenge,
        validate_username, Claims,
    },
    types::{
        AuthenticatedUser, AuthenticationError, ExpiredRefreshToken, InvalidCertificate,
        InvalidChallenge, InvalidMasterPasswordHash, InvalidRefreshToken, InvalidSignature,
        PrivateCertificate, RefreshTokenError, SignupError, TokenPair, UnknownUser, UserSuspended,
    },
};
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Validation};
use lazy_static::lazy_static;
use moka::future::Cache;
use regex::Regex;

use super::{
    scalars::Bytes,
    types::{
        AuthenticationCredentialsUserInput, AuthenticationResult, RefreshTokenResult, SignupResult,
        SignupUserInput,
    },
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
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
    use sequoia_openpgp::{serialize::SerializeInto, types::SignatureType, Packet};
    use serde::{Deserialize, Serialize};

    use crate::models::graphql::types::{
        CertificateTaken, InvalidUsername, SignalCompliantPolcy, TokenPair, UsernameUnavailable,
    };

    use super::*;

    #[cfg(test)]
    mod tests {
        use sequoia_openpgp::{parse::Parse, serialize::MarshalInto, Cert};

        use crate::models::graphql::{
            mutations::helpers::{parse_cert, parse_signature, validate_challenge},
            scalars::Bytes,
        };

        use super::strip_certifications;

        // TODO: get external verified test vectors

        const CLIENT_CERT_ARMOR: &[u8] = include_bytes!("../../../other/test_keys/erik.asc");
        const CLIENT_CERT: &[u8] = include_bytes!("../../../other/test_keys/erik.pgp");
        const CLIENT_CERT_FINGERPRINT: &str = "D3DD6935E854E0413634A712D0BF2A3CF9099BEF";

        const CLIENT_KEYRING_ARMOR: &[u8] =
            include_bytes!("../../../other/test_keys/erik_bob_keyring.asc");
        const CLIENT_KEYRING: &[u8] =
            include_bytes!("../../../other/test_keys/erik_bob_keyring.pgp");

        const CHALLENGE: &str = "cffbfa704053bd3c26df1debe1076957477edee8f597c79ac7e6ca6d7aba12f5";
        const INVALID_CHALLENGE: &str =
            "36729f32befa1d1bdbb6413279cc3aa7b9070fc62900c7cbd674499d920b5bab";

        // TODO: get better source for the test vector
        const SIGNATURE: &[u8] = include_bytes!("../../../other/test_keys/challenge_signature.pgp");
        const SIGNATURE_FOR_OTHER_CHALLENGE: &[u8] =
            include_bytes!("../../../other/test_keys/signature_for_other_challenge.pgp");
        // the signature itself is valid but made by another user's key
        const SIGNATURE_BY_OTHER_USER: &[u8] =
            include_bytes!("../../../other/test_keys/challenge_signature_by_other_user.pgp");

        const CLIENT_INVALID_KEY_ALGO: &[u8] =
            include_bytes!("../../../other/test_keys/carl_invalid_key_algo.pgp");

        const CLIENT_CERT_EXPIRATION_DATE: &[u8] =
            include_bytes!("../../../other/test_keys/david_cert_with_expiration_date.pgp");

        const CLIENT_CERT_WITH_CERTIFICATION: &[u8] =
            include_bytes!("../../../other/test_keys/issue_6/bob_certify_erik.asc");

        #[test]
        fn test_reject_cert_with_certification() {
            let cert = Cert::from_bytes(CLIENT_CERT_WITH_CERTIFICATION).unwrap();
            let count = cert.userids().next().unwrap().signatures().count();
            assert_eq!(count, 2);
            let cert = strip_certifications(cert).unwrap();
            let valid_userid = cert.userids().next().unwrap();
            assert_eq!(1, valid_userid.signatures().count());
            assert_eq!(
                1,
                valid_userid.self_signatures().count(),
                "removed a signature but it was the self signature"
            );
        }
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

            e.clear();

            assert!(parse_cert(
                &Bytes(bytes::Bytes::from_static(CLIENT_INVALID_KEY_ALGO)),
                &mut e
            )
            .is_none());
            assert!(!e.is_empty());

            e.clear();

            assert!(parse_cert(
                &Bytes(bytes::Bytes::from_static(CLIENT_CERT_EXPIRATION_DATE)),
                &mut e
            )
            .is_none());
            assert!(!e.is_empty())
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

            let valid = validate_challenge(INVALID_CHALLENGE, &mut sig, &cert, &mut e);
            assert!(
                !valid,
                "validate_challenge validate a signature for another challenge as valid!"
            );
            assert_eq!(e.len(), 1);

            e.clear();

            // a signature that is for another challenge
            let mut sig = parse_signature(
                &Bytes(bytes::Bytes::from_static(SIGNATURE_FOR_OTHER_CHALLENGE)),
                &mut e,
            )
            .unwrap_or_else(|| {
                panic!("parse_signature failed to parse a cryptographically valid signature")
            });
            assert!(e.is_empty());

            let valid = validate_challenge(CHALLENGE, &mut sig, &cert, &mut e);
            assert!(
                !valid,
                "validate_challenge validated a signature from another challenge as valid"
            );
            assert_eq!(1, e.len());

            e.clear();

            // a challenge which is cryptographically ok but made with another user's key
            let mut sig = parse_signature(
                &Bytes(bytes::Bytes::from_static(SIGNATURE_BY_OTHER_USER)),
                &mut e,
            )
            .unwrap_or_else(|| {
                panic!("parse_signature failed to parse a cryptographically valid signature")
            });

            let valid = validate_challenge(CHALLENGE, &mut sig, &cert, &mut e);
            assert!(
                !valid,
                "validate_challenge accepted a signature from another user as valid."
            );
            assert_eq!(e.len(), 1, "validate_challenge didn't add an error!");
        }
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub(super) struct Claims {
        pub(super) exp: i64,
        pub(super) iat: i64,
        pub(super) nbf: i64,
        pub(super) sub: uuid::Uuid,
        pub(super) jti: uuid::Uuid,
        // the session id
        pub(super) sid: uuid::Uuid,
        // if the token is a refresh token
        pub(super) rft: bool,
    }

    pub(crate) fn strip_certifications(cert: Cert) -> anyhow::Result<Cert> {
        let fingerprint = cert.fingerprint();
        let packets = cert.into_packets();
        // packets of a certificate without any Certifications
        let valid_packets = packets.filter(|packet| match packet {
            Packet::Signature(sig) => match sig.typ() {
                SignatureType::GenericCertification
                | SignatureType::PersonaCertification
                | SignatureType::CasualCertification
                | SignatureType::PositiveCertification
                | SignatureType::AttestationKey => {
                    sig.issuer_fingerprints().all(|f| f == &fingerprint)
                }
                _ => true,
            },

            Packet::Unknown(_) => false,
            _ => true,
        });
        Cert::from_packets(valid_packets)
    }
    pub(super) async fn is_refresh_token_denied(claims: &Claims, db: &PgPool) -> bool {
        // TODO: consider caching denied refresh tokens
        sqlx::query!(
            r#"
        SELECT exists(SELECT 1 FROM denied_tokens WHERE "token_id" = $1)
        "#,
            claims.jti
        )
        .fetch_one(db)
        .await
        .unwrap()
        .exists
        .unwrap()
    }

    pub(super) async fn delete_session(session_id: uuid::Uuid, db: &PgPool) {
        if let Err(e) = sqlx::query!(
            r#"
                DELETE FROM session_info WHERE session_id = $1"#,
            session_id
        )
        .execute(db)
        .await
        {
            warn!(
                "Failed to delete session {} from database: {}",
                session_id, e
            )
        }
    }
    /// returns (access token, first refresh token)
    pub(super) async fn create_session(
        key: &EncodingKey,
        user_id: uuid::Uuid,
        session_name: Option<&str>,
        db: &PgPool,
    ) -> (String, String) {
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

        generate_token(key, session_id, user_id)
    }

    pub(super) fn generate_token(
        key: &EncodingKey,
        session_id: uuid::Uuid,
        user_id: uuid::Uuid,
    ) -> (String, String) {
        let now = Utc::now();
        let claims = Claims {
            exp: (now + Duration::hours(12)).timestamp(),
            iat: now.timestamp(),
            jti: uuid::Uuid::new_v4(),
            sid: session_id,
            nbf: now.timestamp(),
            rft: false,
            sub: user_id,
        };

        let access_token =
            encode(&Header::default(), &claims, key).expect("Failed to create access token");

        let claims = Claims {
            exp: (now + Duration::hours(7)).timestamp(),
            iat: now.timestamp(),
            jti: uuid::Uuid::new_v4(),
            sid: session_id,
            nbf: now.timestamp(),
            rft: true,
            sub: user_id,
        };

        let refresh_token =
            encode(&Header::default(), &claims, key).expect("Failed to create refresh token");

        (access_token, refresh_token)
    }

    /// updates the token expiry to now and invalidates the current session
    pub(super) async fn set_token_expiry(
        user_id: uuid::Uuid,
        ctx: &Context<'_>,
        timestamp: Option<DateTime<Utc>>,
    ) -> i64 {
        let cache = ctx.data::<Cache<uuid::Uuid, i64>>().unwrap();
        let db = ctx.data::<PgPool>().unwrap();
        let t = timestamp.unwrap_or_else(Utc::now);
        cache.insert(user_id, t.timestamp()).await;
        sqlx::query!(
            r#"
        UPDATE users SET token_expiry = $1 WHERE user_id = $2
        "#,
            t,
            user_id
        )
        .execute(db)
        .await
        .expect("Failed to update token_expiry in database");
        t.timestamp()
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
        let error_count = errors.len();
        let mut result = None;
        // TODO: make sure to remove certifications from other users.
        match Cert::from_bytes(&cert.0) {
            Ok(cert) => {
                match cert.with_policy(&SignalCompliantPolcy::default(), None) {
                    Ok(cert) => {
                        // Checks if more than one key for each operation is present
                        // Signing, Authentication, Encryption, Certification
                        let mut keys = (false, false, false, false);
                        let mut has_unencrypted_secrets = false;
                        cert.keys().for_each(|key| {
                            has_unencrypted_secrets = key.has_unencrypted_secret();

                            if key.for_signing() {
                                match keys.0 {
                                    true => errors.push(SignupError::InvalidCertificate(
                                        InvalidCertificate {
                                            description: "Found more than one signing key in certificate.".to_string()
                                        }
                                    )),
                                    false => keys.0 = true
                                }
                            }

                            if key.for_authentication() {
                                match keys.1 {
                                    true => errors.push(SignupError::InvalidCertificate(InvalidCertificate {
                                        description:
                                            "Found more than one authentication key in certificate."
                                                .to_string(),
                                    })),
                                    false => keys.1 = true,
                                }
                            }

                            if key.for_storage_encryption() && key.for_transport_encryption() {
                                match keys.2 {
                                    true => errors.push(SignupError::InvalidCertificate(
                                        InvalidCertificate {
                                            // We might accept multiple encryption keys some time in the future
                                            // IF we add smart card support
                                            description: concat!(
                                                "Found more than one key for encryption. ",
                                                "Note: This key is for both transport and ",
                                                "storage encryption which is valid."
                                            ).to_string()
                                        }
                                    )),
                                    false => keys.2 = true,
                                }
                            }
                            if (key.for_storage_encryption() && !key.for_transport_encryption()) || (key.for_transport_encryption() && !key.for_storage_encryption()) {
                                errors.push(SignupError::InvalidCertificate(
                                    InvalidCertificate {
                                        description: concat!(
                                            "Found a key which is only for storage encryption or only for transport encryption. ",
                                            "This is considered invalid. A key must be for both storage and transport encryption. ",
                                            "Note: Most PGP implementation don't distinguish between these operation and will just ",
                                            "say ``encyption``. E.g. GnuPG does it this way."
                                        ).to_string()
                                    }
                                ))
                            }

                            if key.for_certification() {
                                match keys.3 {
                                    true => errors.push(
                                        SignupError::InvalidCertificate(
                                            InvalidCertificate {
                                                description: concat!(
                                                    "Found more than one key for certification. ",
                                                    "Note: Since the certification is the primary ",
                                                    "key, this means this certificate has more than",
                                                    "one primary key, which is really wrong."
                                                ).to_string()
                                            }
                                        )
                                    ),
                                    false => keys.3 = true,
                                }
                            }
                        });

                        match keys {
                            (true, true, true, true) => {
                                if errors.len() == error_count {
                                    result =
                                        Some(strip_certifications(cert.cert().clone()).unwrap())
                                }
                            }
                            _ => errors.push(SignupError::InvalidCertificate(InvalidCertificate {
                                description: concat!(
                                    "The certificate is missing one or more key parts ",
                                    "Note: Look for other errors which tell you which keys ",
                                    "are missing."
                                )
                                .to_string(),
                            })),
                        }
                    }
                    Err(_) => errors.push(SignupError::InvalidCertificate(InvalidCertificate {
                        description: concat!(
                            "The primary key does not match the key policy. ",
                            "Note: Only Curve 25519 keys WITHOUT a expiration ",
                            "date are supported."
                        )
                        .to_string(),
                    })),
                }
            }
            Err(_) => {
                errors.push(SignupError::InvalidCertificate(InvalidCertificate {
                    description: "Failed to parse certificate. Note: Signature not checked."
                        .to_string(),
                }));
            }
        }
        result
    }

    /// Adds the user or an error to the Result
    pub(super) async fn insert_user(
        user: SignupUserInput,
        result: &mut SignupResult,
        cert: Cert,
        db: &PgPool,
        key: &EncodingKey,
    ) {
        assert!(
            cert.is_tsk(),
            "Certificate has no secret parts. Parse_cert should've checked that."
        );

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
                    certificate: PrivateCertificate { cert },
                    name: user.name,
                    token: TokenPair {
                        access_token,
                        refresh_token,
                    },
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
        ctx: &Context<'_>,
        credentials: AuthenticationCredentialsUserInput,
    ) -> AuthenticationResult {
        let db = ctx.data::<PgPool>().unwrap();
        let encoding_key = ctx.data::<EncodingKey>().unwrap();

        let mut result = AuthenticationResult {
            user: None,
            errors: vec![],
        };
        let username = credentials.name.to_lowercase();

        match sqlx::query!(
                    r#"
                SELECT user_id, hash, enc_cert, suspended, suspended_reason FROM users WHERE username = $1
                "#,
                    username
                )
                .fetch_one(db)
                .await {
            Ok(r) => {
                lazy_static! {
                    static ref ARGON2: Argon2<'static> = Argon2::default();
                }

                let hash = PasswordHash::new(&r.hash).expect("Invalid password hash in the database");
                if ARGON2.verify_password(&credentials.hash.0, &hash).is_ok() {
                    match r.suspended {
                        true => result.errors.push(
                                AuthenticationError::UserSuspended(
                                    UserSuspended {
                                        description: format!(concat!(
                                            "The user with the name `{}` authenticated successfully ",
                                            "but is suspended. ",
                                            "Note: You may want to look at the `reason` field ",
                                            "for additional information which can be used in an ",
                                            "aplication. ",
                                        ), username),
                                        reason: r.suspended_reason,
                                        since: None // we don't even store this yet
                                    }
                                )
                            ),
                        false => {
                            let (access_token, refresh_token) = create_session(encoding_key, r.user_id, None, db).await;
                            result.user = Some(
                                AuthenticatedUser {
                                    name: username,
                                    id: ID(r.user_id.to_string()),
                                    certificate: PrivateCertificate { cert: Cert::from_bytes(&r.enc_cert).expect("Certificate from database not valid")},
                                    token: TokenPair { access_token, refresh_token }
                                }
                            )
                        }
                    }
                } else {
                    result.errors.push(AuthenticationError::InvalidMasterPasswordHash(InvalidMasterPasswordHash {
                        description: concat!(
                            "The master password hash didn't match the hash of the master password hash ",
                            "stored in the database. ",
                            "Note: be sure to correctly derive the master password hash from the user's ",
                            "password and username and that you didn't send the (stretched) master key. ",
                            "For help, see https://bitwarden.com/help/article/bitwarden-security-white-paper/",
                            "#overview-of-the-master-password-hashing-key-derivation-and-encryption-process",
                        ).to_string()
                    }))
                }
            },
            Err(_) => {
                result.errors.push(AuthenticationError::UnknownUser(UnknownUser { description: format!("Found no user with name `{}`", credentials.name)}))
            }
        };
        result
    }

    /// A client might obtain a new ``TokenPair`` from this endpoint.
    /// The client sends its refresh token (a String with a JWT) and the server returns a new ``TokenPair``.
    async fn refresh_token(&self, ctx: &Context<'_>, refresh_token: String) -> RefreshTokenResult {
        let decoding_key = ctx.data::<DecodingKey>().unwrap();
        let encoding_key = ctx.data::<EncodingKey>().unwrap();

        let mut result = RefreshTokenResult {
            token: None,
            errors: vec![],
        };

        lazy_static! {
            static ref VALIDATION: Validation = Validation::new(jsonwebtoken::Algorithm::HS256);
        }

        let token = decode::<Claims>(refresh_token.as_str(), decoding_key, &VALIDATION);

        match token {
            Ok(token) => {
                let claims = token.claims;
                let db = ctx.data::<PgPool>().unwrap();
                if claims.rft {
                    if get_token_expiry(claims.sub, ctx).await > claims.iat {
                        result.errors.push(RefreshTokenError::ExpiredRefreshToken(
                            ExpiredRefreshToken {
                                description:
                                    "Refresh token is expired. Note: You have to log in again."
                                        .to_string(),
                            },
                        ))
                    } else if is_refresh_token_denied(&claims, db).await {
                        // a bad actor has stolen a refresh token. We don't know if this
                        // request comes from the actual user or the bad actor. Because
                        // of this, we revoke the session.
                        set_token_expiry(claims.sub, ctx, None).await;
                        delete_session(claims.sid, db).await;
                        result.errors.push(RefreshTokenError::ExpiredRefreshToken(
                            ExpiredRefreshToken {
                                description:
                                    "Refresh token is expired. Note: You have to log in again."
                                        .to_string(),
                            },
                        ))
                    } else {
                        let (access_token, refresh_token) =
                            generate_token(encoding_key, claims.sid, claims.sub);
                        result.token = Some(TokenPair {
                            access_token,
                            refresh_token,
                        })
                    }
                } else {
                    result.errors.push(RefreshTokenError::InvalidRefreshToken(
                        InvalidRefreshToken {
                            description: "Not a refresh token.".to_string(),
                        },
                    ))
                }
            }
            Err(e) => match e.into_kind() {
                jsonwebtoken::errors::ErrorKind::ExpiredSignature => result.errors.push(
                    RefreshTokenError::ExpiredRefreshToken(ExpiredRefreshToken {
                        description: "Refresh token is expired. Note: You have to log in again."
                            .to_string(),
                    }),
                ),
                _ => result.errors.push(RefreshTokenError::InvalidRefreshToken(
                    InvalidRefreshToken {
                        description: "The refresh token is invalid.".to_string(),
                    },
                )),
            },
        }
        result
    }
}
