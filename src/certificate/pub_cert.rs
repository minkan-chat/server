use crate::{graphql::Bytes, trust::certification::Certification};
use async_graphql::{
    connection::{query, Connection, Edge},
    Context, Object,
};
use futures::stream::TryStreamExt;
use sequoia_openpgp::{parse::Parse, serialize::SerializeInto, Cert, Fingerprint};
use sqlx::{Pool, Postgres};
use std::{hash::Hash, ops::Deref, str::FromStr};
use uuid::Uuid;

use super::PrivateCertificate;

#[derive(Clone, Debug)]
/// a ``Certificate`` that has no secret key material in it
#[non_exhaustive]
pub struct PublicCertificate {
    pub fingerprint: Fingerprint,
    pub cert: Cert,
}

// problems i'm talking about in #20
impl Eq for PublicCertificate {}
impl PartialEq for PublicCertificate {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint == other.fingerprint
    }
}
impl Hash for PublicCertificate {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.fingerprint.hash(state)
    }
}

crate::strip_cert!(PublicCertificate);
crate::try_cert!(PublicCertificate);

#[Object]
/// A ``Certificate`` that contains no secret key material
impl PublicCertificate {
    pub async fn fingerprint(&self) -> String {
        self.fingerprint.to_hex()
    }

    pub async fn body(&self) -> Bytes {
        bytes::Bytes::from(self.cert.export_to_vec().expect("failed to serialize cert")).into()
    }

    // TODO: add doc, explain this
    // first/last max is 1000
    pub async fn certifications(
        &self,
        ctx: &Context<'_>,
        after: Option<String>,
        before: Option<String>,
        first: Option<i32>,
        last: Option<i32>,
    ) -> async_graphql::Result<Connection<String, Certification>> {
        query::<String, _, _, _, _, _>(
            after,
            before,
            first,
            last,
            |after, before, first, last| async move {
                let db = ctx.data_unchecked::<Pool<Postgres>>();

                // what the actual fuck
                // do this shit because we need to parse the cursor as an uuid::Uuid and from_str returns Result
                // which we can't unwrap, because it's untrusted input. And somehow, with and_then etc. everything
                // is totally broken
                // Know a better way? PLEASE open an issue or PR
                let after = if let Some(a) = after {
                    match Uuid::from_str(&a) {
                        Ok(o) => Some(o),
                        Err(_) => return Err(async_graphql::Error::new("invalid cursor")),
                    }
                } else {
                    None
                };
                let before = if let Some(b) = before {
                    match Uuid::from_str(&b) {
                        Ok(o) => Some(o),
                        Err(_) => return Err(async_graphql::Error::new("invalid cursor")),
                    }
                } else {
                    None
                };

                // default to a limit of 100
                let limit = first.unwrap_or_else(|| last.unwrap_or(100));

                let limit = if limit > 1_000 {
                    1_000
                } else {
                    limit as i64
                };

                let page_info = sqlx::query!(r#"
                SELECT (
                    -- if ``after`` is NULL, there won't be any previous page
                    -- because it starts from the beginning
                    -- after cursor is $2
                    -- before cursor is $3
                    CASE WHEN $2::UUID IS NOT NULL AND $3::UUID IS NULL THEN (
                        SELECT exists(
                            SELECT FROM certifications
                                INNER JOIN pub_certs certifier ON (
                                    certifications.certifier_cert = certifier.cert_fingerprint
                                )
                                WHERE target_cert = $1
                                AND certifier.user_id < $2 -- $2 is known to be not null here
                                ORDER BY certifier.user_id
                                LIMIT 1
                        )
                    )
                    ELSE
                        (
                      SELECT exists(
                      	SELECT FROM certifications
                         INNER JOIN pub_certs certifier ON (
                           	certifications.certifier_cert = certifier.cert_fingerprint
                            )
                        WHERE target_cert = $1
                        AND certifier.user_id > $3
                        ORDER BY certifier.user_id
                        LIMIT 1
                      )
                    )
                  END
                ) AS "has_previous!",
                (
                    SELECT exists(
                        SELECT FROM certifications
                            INNER JOIN pub_certs certifier ON (certifications.certifier_cert = certifier.cert_fingerprint)
                            WHERE target_cert = $1
                                AND ((certifier.user_id > $2) OR TRUE)
                                AND ((certifier.user_id < $3) OR TRUE)
                            ORDER BY certifier.user_id
                            LIMIT 1
                            OFFSET $4
                    )
                ) AS "has_next!"
                "#,
                &self.fingerprint.to_string(),
                after,
                before,
                limit
                ).fetch_one(db).await.unwrap();

                let mut connection = Connection::<String, Certification>::new(page_info.has_previous, page_info.has_next);

                // FIXME: see #20 this is the same problem
                let certifications = sqlx::query!(r#"
                    SELECT certifier.pub_cert AS certifier, -- #20
                    target.pub_cert AS target, -- #20
                    certifier.user_id AS certifier_id
                    FROM certifications
                    INNER JOIN pub_certs certifier ON (certifications.certifier_cert = certifier.cert_fingerprint)
                    INNER JOIN pub_certs target ON (certifications.target_cert = target.cert_fingerprint)
                    WHERE target_cert = $1
                    AND ((certifier.user_id > $2) OR TRUE)
                    AND ((certifier.user_id < $3) OR TRUE)
                    ORDER BY certifier.user_id
                    LIMIT $4
                    "#,
                    &self.fingerprint.to_string(),
                    after,
                    before,
                    limit
                )
                .fetch(db)
                .map_err(async_graphql::Error::from)
                .map_ok(|record| {
                    // we use the uuid as the cursor
                    Edge::new(record.certifier_id.to_string(),
                    Certification {
                        certifier: Cert::from_bytes(&record.certifier).expect("invalid certificate in database").into(),
                        target: Cert::from_bytes(&record.target).expect("invalid certificate in database").into(),
                    })
                });
                    connection.try_append_stream(certifications).await?;
                Ok(connection)
            },
        )
        .await
    }
}

impl From<Cert> for PublicCertificate {
    fn from(cert: Cert) -> Self {
        Self {
            fingerprint: cert.fingerprint(),
            cert,
        }
    }
}

impl From<PrivateCertificate> for PublicCertificate {
    fn from(cert: PrivateCertificate) -> Self {
        Self {
            fingerprint: cert.cert.fingerprint(),
            cert: cert.cert.strip_secret_key_material(),
        }
    }
}

impl Deref for PublicCertificate {
    type Target = Cert;
    fn deref(&self) -> &Self::Target {
        &self.cert
    }
}
