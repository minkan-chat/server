//! User
//!
//! This represents a normal user without any specialization

use crate::{
    certificate::Certificate,
    fallible::{
        CertificateTaken, Error, InvalidMasterPasswordHash, InvalidUsername, NoSuchUser,
        UsernameUnavailable,
    },
    graphql::Bytes,
    loader::{PublicCertificateLoader, UsernameLoader},
};
use argon2::{password_hash::SaltString, Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use async_graphql::{dataloader::DataLoader, Context, Object};
use chrono::{DateTime, Utc};
use lazy_static::lazy_static;
use sequoia_openpgp::{serialize::SerializeInto, Cert};
use sqlx::{Pool, Postgres};
use uuid::Uuid;

use super::AuthenticatedUser;

#[derive(Debug)]
pub struct User {
    pub(super) id: uuid::Uuid,
}

impl User {
    /// Create a new [`User`]
    /// This function inserts a new user into the database
    pub async fn new(
        name: String,
        cert: &Cert,
        mpw: Bytes,
        db: &Pool<Postgres>,
    ) -> Result<Self, Error> {
        // generate salt
        let salt = SaltString::generate(&mut rand::rngs::OsRng);

        lazy_static! {
            static ref ARGON2: Argon2<'static> = Argon2::default();
        }

        // generate hash of the master password hash
        // the result is a PHC string ($argon2id$19$...). it contains the salt
        let hash = ARGON2
            .hash_password_simple(&mpw.into_inner(), &salt)
            .map_err(|_| {
                Error::InvalidMasterPasswordHash(InvalidMasterPasswordHash {
                    description: "failed to generate hash".to_string(),
                    hint: None,
                })
            })?
            .to_string();

        let fingerprint = cert.fingerprint().to_hex();
        let pub_cert = cert
            .clone()
            .strip_secret_key_material()
            .export_to_vec()
            .unwrap();
        let cert_raw = cert.as_tsk().export_to_vec().unwrap();

        let result = sqlx::query!(
            r#"
            WITH "user" AS (
                INSERT INTO users (username, hash, enc_cert)
                VALUES ($1, $2, $3)
                RETURNING user_id AS id
            )
            INSERT INTO pub_certs (user_id, cert_fingerprint, pub_cert)
            VALUES (
                (SELECT id FROM "user"), $4, $5
            ) RETURNING (SELECT id FROM "user") AS "user_id!: uuid::Uuid"
            "#,
            name,
            hash,
            cert_raw,
            fingerprint,
            pub_cert,
        )
        .fetch_one(db)
        .await;

        match result {
            Ok(record) => Ok(Self { id: record.user_id }),
            Err(e) => Err(match e {
                sqlx::Error::Database(e) => {
                    // won't panic because we use postgres
                    let e = e.downcast::<sqlx::postgres::PgDatabaseError>();
                    // postgresql error codes: https://www.postgresql.org/docs/current/errcodes-appendix.html
                    // 23505 = unique violation -> already exists
                    match (e.code(), e.constraint()) {
                        ("23505", Some("users_username_key")) => {
                            Error::UsernameUnavailable(UsernameUnavailable {
                                description: "another user has the same name".to_string(),
                                hint: Some("choose a different name".to_string()),
                                name,
                            })
                        }
                        ("23505", Some("pub_certs_cert_fingerprint_key")) => {
                            Error::CertificateTaken(CertificateTaken {
                                certificate: Box::new(cert.into()),
                                description: "another user's certificate has the same fingerprint"
                                    .to_string(),
                                hint: Some(
                                    concat!(
                                        "it is VERY unlikely that this is an accident. ",
                                        "it is way more likely that your client reuses ",
                                        "certificates."
                                    )
                                    .to_string(),
                                ),
                            })
                        }
                        ("23514", _) => Error::InvalidUsername(InvalidUsername {
                            description: "username violates policy".to_string(),
                            hint: Some("only a-z, 0-9, _ are allowed".to_string()),
                            name: name.to_lowercase(),
                        }),
                        _ => Error::Unexpected(e.into()),
                    }
                }
                e => Error::Unexpected(e.into()),
            }),
        }
    }

    pub async fn authenticate(
        self,
        mpw: &Bytes,
        db: &Pool<Postgres>,
    ) -> Result<AuthenticatedUser, Error> {
        lazy_static! {
            static ref ARGON2: Argon2<'static> = Argon2::default();
        }
        let hash = sqlx::query!(
            r#"
        SELECT hash FROM users WHERE user_id = $1
        "#,
            self.id
        )
        .fetch_one(db)
        .await
        .expect("user not in database") // safe cuz only Users which are known to be in the database are created
        .hash;

        let hash = PasswordHash::new(&hash).expect("invalid password hash");
        ARGON2.verify_password(mpw, &hash).map_err(|e| {
            Error::InvalidMasterPasswordHash(InvalidMasterPasswordHash {
                description: "invalid master password hash".to_string(),
                hint: Some(e.to_string()),
            })
        })?;

        Ok(self.into())
    }

    pub async fn set_token_expiry(
        &self,
        time: Option<DateTime<Utc>>,
        db: &Pool<Postgres>,
    ) -> DateTime<Utc> {
        let time = time.unwrap_or_else(Utc::now);
        sqlx::query!(
            r#"
        UPDATE users SET token_expiry = $1 WHERE user_id = $2
        "#,
            time,
            self.id
        )
        .execute(db)
        .await
        .expect("cannot update token_expiry in database");
        time
    }
}

impl From<Uuid> for User {
    fn from(id: Uuid) -> Self {
        Self { id }
    }
}

impl User {
    // does database io so it really must be async, but TryFrom can't async, so no trait impl
    /// Like the [``std::convert::TryFrom``] but with an async fn.
    /// This function looks up if there's a user with the ``name`` in the database and gets the uuid.
    /// Errors if there's no such user
    pub async fn try_from(name: &str, db: &Pool<Postgres>) -> Result<Self, Error> {
        Ok(sqlx::query!(
            r#"
                SELECT user_id FROM users WHERE username = $1"#,
            name
        )
        .fetch_one(db)
        .await
        .map_err(|_| {
            Error::NoSuchUser(NoSuchUser {
                description: "cannot find a user with that name".to_string(),
                hint: None,
                name: name.to_string(),
            })
        })?
        .user_id
        .into())
    }
}

#[Object]
impl User {
    pub async fn id(&self) -> async_graphql::ID {
        self.id.into()
    }

    pub async fn name(&self, ctx: &Context<'_>) -> String {
        ctx.data_unchecked::<DataLoader<UsernameLoader>>()
            .load_one(self.id)
            .await
            .unwrap()
            .unwrap()
    }

    pub async fn certificate(&self, ctx: &Context<'_>) -> Certificate {
        ctx.data_unchecked::<DataLoader<PublicCertificateLoader>>()
            .load_one(self.id)
            .await
            .unwrap()
            .unwrap()
    }
}
