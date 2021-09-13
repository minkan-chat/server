//! User
//!
//! This represents a normal user without any specialization

use crate::{
    certificate::{PrivateCertificate, PublicCertificate},
    fallible::{
        CertificateTaken, Error, InvalidMasterPasswordHash, InvalidUsername, Unexpected,
        UsernameUnavailable,
    },
    graphql::Bytes,
    loader::{PublicCertificateLoader, UsernameLoader},
};
use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
use async_graphql::{dataloader::DataLoader, Context, Object};
use lazy_static::lazy_static;
use sequoia_openpgp::serialize::SerializeInto;
use sqlx::{Pool, Postgres};
use uuid::Uuid;

#[derive(Debug)]
pub struct User {
    pub(super) id: uuid::Uuid,
}

impl User {
    /// Create a new [`User`]
    /// This function inserts a new user into the database
    pub async fn new(
        name: String,
        cert: PrivateCertificate,
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

        // can't use graphql implementations from ``PrivateCertificate`` :(
        let fingerprint = cert.cert.fingerprint().to_hex();
        let pub_cert = cert
            .cert
            .clone()
            .strip_secret_key_material()
            .export_to_vec()
            .unwrap();
        let cert_raw = cert.cert.as_tsk().export_to_vec().unwrap();

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
        
        let unexpected = Error::Unexpected(Unexpected {
            description: "unknown database error".to_string(),
            hint: None,
        });

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
                        _ => unexpected,
                    }
                }
                _ => unexpected,
            }),
        }
    }
}

impl From<Uuid> for User {
    fn from(id: Uuid) -> Self {
        Self { id }
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

    pub async fn certificate(&self, ctx: &Context<'_>) -> PublicCertificate {
        ctx.data_unchecked::<DataLoader<PublicCertificateLoader>>()
            .load_one(self.id)
            .await
            .unwrap()
            .unwrap()
    }
}
