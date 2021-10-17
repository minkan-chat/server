use std::{collections::HashMap, sync::Arc};

use crate::{basic_loader, certificate::Certificate, graphql::Bytes, loader_struct};
use async_graphql::dataloader::Loader;
use async_trait::async_trait;
use futures::TryStreamExt;
use sequoia_openpgp::Fingerprint;
use uuid::Uuid;

/*loader_struct!(PrivateCertificateLoader);

use futures::stream::TryStreamExt;

#[async_trait]
impl Loader<uuid::Uuid> for PrivateCertificateLoader {
    type Value = PrivateCertificate;
    type Error = Arc<sqlx::Error>;
    async fn load(
        &self,
        keys: &[uuid::Uuid],
    ) -> Result<HashMap<uuid::Uuid, Self::Value>, Self::Error> {
        Ok(sqlx::query!(
            r#"
                SELECT user_id, enc_cert FROM users WHERE user_id = ANY($1)
                "#,
            keys,
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            let p =
                PrivateCertificate::try_from(record.enc_cert).expect("invalid cert in database");
            (record.user_id, p)
        })
        .try_collect()
        .await?)
    }
}

loader_struct!(PublicCertificateLoader);

#[async_trait]
impl Loader<uuid::Uuid> for PublicCertificateLoader {
    type Value = PublicCertificate;
    type Error = Arc<sqlx::Error>;
    async fn load(
        &self,
        keys: &[uuid::Uuid],
    ) -> Result<HashMap<uuid::Uuid, Self::Value>, Self::Error> {
        Ok(sqlx::query!(
            r#"
                SELECT user_id, pub_cert FROM pub_certs WHERE user_id = ANY($1)
                "#,
            keys,
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            let p = PublicCertificate::try_from(record.pub_cert).expect("invalid cert in database");
            (record.user_id, p)
        })
        .try_collect()
        .await?)
    }
}*/

loader_struct!(PublicCertificateLoader);

#[async_trait]
impl Loader<Uuid> for PublicCertificateLoader {
    type Value = Certificate;
    type Error = Arc<sqlx::Error>;
    async fn load(&self, keys: &[Uuid]) -> Result<HashMap<Uuid, Self::Value>, Self::Error> {
        Ok(sqlx::query!(
            r#"
            SELECT user_id, cert_fingerprint FROM pub_certs WHERE user_id = ANY($1)
            "#,
            keys,
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            (
                record.user_id,
                Certificate::from_public(
                    Fingerprint::from_hex(&record.cert_fingerprint)
                        .expect("invalid certificate fingerprint in database"),
                ),
            )
        })
        .try_collect()
        .await?)
    }
}

loader_struct!(PrivateCertificateLoader);

#[async_trait]
impl Loader<Uuid> for PrivateCertificateLoader {
    type Value = Certificate;
    type Error = Arc<sqlx::Error>;
    async fn load(&self, keys: &[Uuid]) -> Result<HashMap<Uuid, Self::Value>, Self::Error> {
        Ok(sqlx::query!(
            r#"
            SELECT user_id, cert_fingerprint FROM pub_certs WHERE user_id = ANY($1)
            "#,
            keys,
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            (
                record.user_id,
                Certificate::from_private(
                    Fingerprint::from_hex(&record.cert_fingerprint)
                        .expect("invalid certificate fingerprint in database"),
                ),
            )
        })
        .try_collect()
        .await?)
    }
}

basic_loader!(
    UserIDLoaderByFingerprint,
    String,
    uuid::Uuid,
    "SELECT cert_fingerprint AS ka, user_id AS val FROM pub_certs WHERE cert_fingerprint = ANY($1)"
);

loader_struct!(PrivateCertificateBodyLoader);

#[async_trait]
impl Loader<Certificate> for PrivateCertificateBodyLoader {
    type Value = Bytes;
    type Error = Arc<sqlx::Error>;
    async fn load(
        &self,
        keys: &[Certificate],
    ) -> Result<HashMap<Certificate, Self::Value>, Self::Error> {
        let fingerprints: Vec<_> = keys.iter().map(|c| c.fingerprint.to_hex()).collect();
        Ok(sqlx::query!(
            r#"
        SELECT enc_cert, cert_fingerprint FROM users
        INNER JOIN pub_certs u ON (users.user_id = u.user_id)
        WHERE u.cert_fingerprint = ANY($1)
        "#,
            &fingerprints
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            (
                Certificate {
                    fingerprint: Fingerprint::from_hex(&record.cert_fingerprint)
                        .expect("invalid certificate fingerprint in database"),
                    secret: true,
                },
                Bytes::from(bytes::Bytes::from(record.enc_cert)),
            )
        })
        .try_collect()
        .await?)
    }
}

loader_struct!(PublicCertificateBodyLoader);

#[async_trait]
impl Loader<Certificate> for PublicCertificateBodyLoader {
    type Value = Bytes;
    type Error = Arc<sqlx::Error>;
    async fn load(
        &self,
        keys: &[Certificate],
    ) -> Result<HashMap<Certificate, Self::Value>, Self::Error> {
        let fingerprints: Vec<_> = keys.iter().map(|c| c.fingerprint.to_hex()).collect();
        Ok(sqlx::query!(
            r#"
        SELECT pub_cert, cert_fingerprint FROM pub_certs
        WHERE cert_fingerprint = ANY($1)
        "#,
            &fingerprints
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            (
                Certificate {
                    fingerprint: Fingerprint::from_hex(&record.cert_fingerprint)
                        .expect("invalid certificate fingerprint in database"),
                    secret: false,
                },
                Bytes::from(bytes::Bytes::from(record.pub_cert)),
            )
        })
        .try_collect()
        .await?)
    }
}
