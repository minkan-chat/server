use std::{collections::HashMap, sync::Arc};

use crate::{basic_loader, certificate::Certificate, graphql::Bytes, loader_struct};
use async_graphql::dataloader::Loader;
use async_trait::async_trait;
use futures::TryStreamExt;
use sequoia_openpgp::Fingerprint;
use uuid::Uuid;

loader_struct!(PublicCertificateLoader);

#[async_trait]
impl Loader<Uuid> for PublicCertificateLoader {
    type Value = Certificate;
    type Error = Arc<sqlx::Error>;
    async fn load(&self, keys: &[Uuid]) -> Result<HashMap<Uuid, Self::Value>, Self::Error> {
        Ok(sqlx::query!(
            r#"
            SELECT user_id, fingerprint FROM certificates WHERE user_id = ANY($1)
            "#,
            keys,
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            (
                record.user_id,
                Certificate::from_public(
                    Fingerprint::from_hex(&record.fingerprint)
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
            SELECT user_id, fingerprint FROM certificates WHERE user_id = ANY($1)
            "#,
            keys,
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            (
                record.user_id,
                Certificate::from_private(
                    Fingerprint::from_hex(&record.fingerprint)
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
    "SELECT fingerprint AS ka, user_id AS val FROM certificates WHERE fingerprint = ANY($1)"
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
        SELECT body, fingerprint FROM certificates
        WHERE fingerprint = ANY($1)
        "#,
            &fingerprints
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            (
                Certificate {
                    fingerprint: Fingerprint::from_hex(&record.fingerprint)
                        .expect("invalid certificate fingerprint in database"),
                    secret: true,
                },
                Bytes::from(bytes::Bytes::from(record.body)),
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
        SELECT body, fingerprint FROM certificates
        WHERE fingerprint = ANY($1)
        "#,
            &fingerprints
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            (
                Certificate {
                    fingerprint: Fingerprint::from_hex(&record.fingerprint)
                        .expect("invalid certificate fingerprint in database"),
                    secret: false,
                },
                Bytes::from(bytes::Bytes::from(record.body)),
            )
        })
        .try_collect()
        .await?)
    }
}
