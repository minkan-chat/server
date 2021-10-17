use futures::stream::TryStreamExt;
use sequoia_openpgp::Fingerprint;
use std::{collections::HashMap, sync::Arc};

use async_graphql::dataloader::Loader;
use async_trait::async_trait;

use crate::{
    certificate::Certificate, graphql::Bytes, loader_struct, trust::certification::Certification,
};

loader_struct!(CertificationBodyLoader);

#[async_trait]
impl Loader<Certification> for CertificationBodyLoader {
    type Value = Bytes;
    type Error = Arc<sqlx::Error>;

    /// Loads the openpgp signature packet from the database for a [``Certification``].
    async fn load(
        &self,
        keys: &[Certification],
    ) -> Result<HashMap<Certification, Self::Value>, Self::Error> {
        // transform the fields of certification to a Vec<Certifier>, Vec<Target> so we can use it
        // with sqlx
        let (c, t): (Vec<_>, Vec<_>) = keys
            .iter()
            .map(|c| {
                (
                    c.certifier.fingerprint.to_hex(),
                    c.target.fingerprint.to_hex(),
                )
            })
            .unzip();
        Ok(sqlx::query!(
            r#"
            SELECT certifier.cert_fingerprint AS certifier, target.cert_fingerprint AS target, certification
            FROM certifications
            INNER JOIN pub_certs certifier ON (certifications.certifier_cert = certifier.cert_fingerprint)
            INNER JOIN pub_certs target ON (certifications.target_cert = target.cert_fingerprint)
            WHERE target_cert = ANY($1)
            AND certifier_cert = ANY($2)
            "#,
            &c,
            &t,
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            (
                Certification {
                    certifier: Certificate::from_public(Fingerprint::from_hex(&record.certifier).expect("invalid cert fingerprint in database")),
                    target: Certificate::from_public(Fingerprint::from_hex(&record.target).expect("invalid cert fingerprint in database")),
                },
                bytes::Bytes::from(record.certification).into(),
            )
        })
        .try_collect()
        .await?)
    }
}
