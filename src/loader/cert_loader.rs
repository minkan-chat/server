use std::{collections::HashMap, convert::TryFrom, sync::Arc};

use crate::{
    basic_loader,
    certificate::{PrivateCertificate, PublicCertificate},
    loader_struct,
};
use async_graphql::dataloader::Loader;
use async_trait::async_trait;

loader_struct!(PrivateCertificateLoader);

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
}

basic_loader!(
    UserIDLoaderByFingerprint,
    String,
    uuid::Uuid,
    "SELECT cert_fingerprint AS ka, user_id AS val FROM pub_certs WHERE cert_fingerprint = ANY($1)"
);
