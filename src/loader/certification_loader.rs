use futures::stream::TryStreamExt;
use sequoia_openpgp::{parse::Parse, Cert};
use std::{collections::HashMap, sync::Arc};

use async_graphql::dataloader::Loader;
use async_trait::async_trait;

use crate::{graphql::Bytes, loader_struct, trust::certification::Certification};

loader_struct!(CertificationLoader);

#[async_trait]
impl Loader<Certification> for CertificationLoader {
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
                    (*c.certifier).fingerprint().to_hex(),
                    (*c.target).fingerprint().to_hex(),
                )
            })
            .unzip();
        Ok(sqlx::query!(
            r#"
            SELECT certifier.pub_cert AS certifier, target.pub_cert AS target, certification FROM certifications -- TODO: only select certificate fingerprints
            INNER JOIN pub_certs certifier ON (certifications.certifier_cert = certifier.cert_fingerprint)      -- when PublicCertificate can be build from 
            INNER JOIN pub_certs target ON (certifications.target_cert = target.cert_fingerprint)               -- a certificate fingerprint only (next PR)
            WHERE target_cert = ANY($1)
            AND certifier_cert = ANY($2)
            "#,
            &c,
            &t,
        )
        .fetch(&self.pool)
        .map_ok(|record| {
            (
                // TODO: see sql statement for TODO
                Certification {
                    certifier: Cert::from_bytes(&record.certifier).expect("invalid certificate in database").into(),
                    target: Cert::from_bytes(&record.target).expect("invalid certificate in database").into(),
                },
                bytes::Bytes::from(record.certification).into(),
            )
        })
        .try_collect()
        .await?)
    }
}
