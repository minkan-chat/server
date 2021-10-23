use async_graphql::{dataloader::DataLoader, guard::Guard, Context, Object};
use sequoia_openpgp::{
    packet::Signature, parse::Parse, serialize::MarshalInto, types::SignatureType, Cert,
    Fingerprint,
};
use sqlx::{PgPool, Pool, Postgres};

use crate::{
    auth::token::Claims,
    certificate::Certificate,
    fallible::{Error, InvalidCertificateFingerprint, InvalidSignature, UnknownCertificate},
    graphql::Bytes,
    loader::{CertificationBodyLoader, PublicCertificateBodyLoader, PublicCertificateLoader},
    result_type, tri,
};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Certification {
    pub certifier: Certificate,
    pub target: Certificate,
}

// TODO: add result type here
impl Certification {
    // cant use TryFrom cuz async :(
    /// Tries to verify a [``Certification``] and inserts it into the database if valid
    async fn try_from(
        signer: &Cert,
        target: &Cert,
        certification: Bytes,
        db: &Pool<Postgres>,
    ) -> Result<Self, Error> {
        let mut signature = Signature::from_bytes(&*certification)
            .map_err(|_| InvalidSignature::new("cannot parse signature".to_string()))?;

        // there are 4 types for certifications in openpgp
        // implementations don't differ and so don't we
        // NOTE: this check is actually not needed because ``verify_user_id_binding`` does exactly that too.
        if !matches!(
            signature.typ(),
            SignatureType::GenericCertification
                | SignatureType::PersonaCertification
                | SignatureType::CasualCertification
                | SignatureType::PositiveCertification
        ) {
            return Err(InvalidSignature {
                description: "not a valid signature type".to_string(),
                hint: Some(
                    concat!(
                        "expected 0x10-0x13 as defined in ",
                        "<https://datatracker.ietf.org/doc/html/rfc4880#section-5.2.1>"
                    )
                    .to_string(),
                ),
            }
            .into());
        }

        // since a signature should only be ussed by one user, there is only one issuer
        if signature.issuers().count() != 1 {
            return Err(InvalidSignature::new("expected one issuer".to_string()).into());
        }

        // checks signature and signature type
        match signature.verify_userid_binding(
            signer.primary_key().key(),
            target.primary_key().key(),
            &target
                .userids()
                .next()
                .expect("certs in database should have exactly one userid"),
        ) {
            Ok(_) => {
                sqlx::query!(
                    r#"
                    INSERT INTO certifications (
                        certifier_cert,
                        target_cert,
                        certification
                    ) VALUES ($1, $2, $3)
                    "#,
                    signer.fingerprint().to_hex(),
                    target.fingerprint().to_hex(),
                    signature.export_to_vec().unwrap(),
                )
                .execute(db)
                .await
                .expect("failed to insert certification in database");
                Ok(Certification {
                    certifier: signer.into(),
                    target: target.into(),
                })
            }
            Err(e) => Err(InvalidSignature {
                description: "invalid signature".to_string(),
                hint: Some(e.to_string()),
            }
            .into()),
        }
    }
}

#[Object]
impl Certification {
    /// The creator of the certification
    async fn certifier(&self) -> &Certificate {
        &self.certifier
    }

    /// The certified ``PublicCertificate``
    async fn target(&self) -> &Certificate {
        &self.target
    }

    /// The actual openpgp signature packet
    async fn body(&self, ctx: &Context<'_>) -> Bytes {
        ctx.data_unchecked::<DataLoader<CertificationBodyLoader>>()
            .load_one(self.clone())
            .await
            .unwrap()
            .unwrap()
    }
}

#[derive(Default)]
pub struct CertificationMutations;

#[derive(Default)]
pub struct CertificationQueries;

result_type!(PublishCertificationResult, Certification);

#[Object]
impl CertificationMutations {
    #[graphql(guard(crate::guards::AuthenticationGuard()))]
    /// Publish a certification
    ///
    /// A user may upload certifications for other certificates.
    /// Other users can then query for certifications and don't
    /// have to trust the server that it's actually the correct
    /// openpgp identity for a user.\
    /// ``target`` is the ``fingerprint`` of the user's certificate
    /// the certification is for.\
    /// ``certification`` is a single openpgp signature packet
    /// of one of the certification types (0x10-0x13).
    /// Note that attestations are not supported. Also, you can
    /// only upload signatures made by the current authenticated
    /// user.
    async fn publish_certification(
        &self,
        ctx: &Context<'_>,
        target: String,
        certification: Bytes,
    ) -> PublishCertificationResult {
        // won't panic, because it is guarded by the AuthenticationGuard
        let claims = ctx.data_unchecked::<Claims>();
        let target = target.to_uppercase();

        let t_figerprint = tri!(Fingerprint::from_hex(&target).map_err(|_| Error::from(
            InvalidCertificateFingerprint::new("cannot parse fingerprint".to_string())
        )));

        let t_cert = Certificate::from_public(t_figerprint);
        let cert_loader = ctx.data_unchecked::<DataLoader<PublicCertificateBodyLoader>>();

        // the cert body of the target
        let t_cert = tri!(cert_loader
            .load_one(t_cert)
            .await
            .unwrap()
            .ok_or_else(|| Error::from(UnknownCertificate::new(
                "cannot find a certificate with that fingerprint".to_string(),
                target,
            ))));

        let c_cert = ctx
            .data_unchecked::<DataLoader<PublicCertificateLoader>>()
            .load_one(claims.sub)
            .await
            .unwrap()
            .unwrap();

        // the cert body of the certifier
        let c_cert = cert_loader.load_one(c_cert).await.unwrap().unwrap();

        let target =
            Cert::from_bytes(&t_cert.into_inner()).expect("invalid certificate in database");
        let signer =
            Cert::from_bytes(&c_cert.into_inner()).expect("invalid certificate in database");

        tri!(
            Certification::try_from(
                &signer,
                &target,
                certification,
                ctx.data_unchecked::<PgPool>(),
            )
            .await
        )
        .into()
    }
}
