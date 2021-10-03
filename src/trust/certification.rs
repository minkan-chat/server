use async_graphql::{dataloader::DataLoader, guard::Guard, Context, Object};
use sequoia_openpgp::{
    packet::Signature, parse::Parse, serialize::MarshalInto, types::SignatureType,
};
use sqlx::{Pool, Postgres};

use crate::{
    auth::token::Claims,
    certificate::PublicCertificate,
    fallible::{Error, InvalidSignature, NoSuchUser},
    graphql::Bytes,
    loader::{CertificationLoader, PublicCertificateLoader, UserIDLoaderByFingerprint},
    result_type,
};

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Certification {
    pub certifier: PublicCertificate,
    pub target: PublicCertificate,
}

// TODO: add result type here
impl Certification {
    // cant use TryFrom cuz async :(
    /// Tries to verify a [``Certification``] and inserts it into the database if valid
    async fn try_from(
        signer: &PublicCertificate,
        target: &PublicCertificate,
        certification: Bytes,
        db: &Pool<Postgres>,
    ) -> Result<Self, Error> {
        let mut signature = Signature::from_bytes(&*certification)
            .map_err(|_| InvalidSignature::new("cannot parse signature".to_string()))?;

        // there are 4 types for certifications in openpgp
        // implementations don't differ and so don't we
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
                    signer.fingerprint.to_string(),
                    target.fingerprint.to_string(),
                    signature.export_to_vec().unwrap(),
                )
                .execute(db)
                .await
                .expect("failed to insert certification in database");
                todo!("#20")
                /*Ok(Certification {
                    certifier_fingerprint: signer.fingerprint.clone(),
                    target_fingerprint: target.fingerprint.clone(),
                })*/
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
    async fn certifier(&self) -> &PublicCertificate {
        &self.certifier
    }

    /// The certified ``PublicCertificate``
    async fn target(&self) -> &PublicCertificate {
        &self.target
    }

    /// The actual openpgp signature packet
    async fn content(&self, ctx: &Context<'_>) -> Bytes {
        ctx.data_unchecked::<DataLoader<CertificationLoader>>()
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

        // try to load the user from the database
        if let Some(target_id) = ctx
            .data_unchecked::<DataLoader<UserIDLoaderByFingerprint>>()
            .load_one(target.clone())
            .await
            .unwrap()
        {
            let cert_loader = ctx.data_unchecked::<DataLoader<PublicCertificateLoader>>();

            // load both certificates of the target and the signer from the database
            let certs = cert_loader
                .load_many([claims.sub, target_id])
                .await
                .unwrap();

            let target = certs.get(&target_id).unwrap();
            let signer = certs.get(&claims.sub).unwrap();

            Certification::try_from(
                signer,
                target,
                certification,
                ctx.data_unchecked::<Pool<Postgres>>(),
            )
            .await
            .into()
        } else {
            Error::NoSuchUser(NoSuchUser::new(
                "found no user with a cert that matched the fingerprint".to_string(),
                target,
            ))
            .into()
        }
    }
}
