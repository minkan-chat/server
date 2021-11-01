//! OpenPGP certificates & friends

use async_graphql::{dataloader::DataLoader, Context, Object};
use sequoia_openpgp::{parse::Parse, types::KeyFlags, Cert, Fingerprint};

mod policy;
pub use policy::*;

use crate::{
    fallible::{Error, InvalidCertificate},
    graphql::Bytes,
    loader::PrivateCertificateBodyLoader,
};
/// An OpenPGP certificate which MAY include secret key material
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Certificate {
    /// the fingerprint of the certificate so it can be found in the database
    pub fingerprint: Fingerprint,
    /// used to determine if the object should allow the access to secret key
    /// material
    pub secret: bool,
}

#[Object]
impl Certificate {
    /// Returns the fingerprint of the certificate
    async fn fingerprint(&self) -> String {
        self.fingerprint.to_hex()
    }

    /// Loads the body from the database and returns the OpenPGP certificate
    async fn body(&self, ctx: &Context<'_>) -> Bytes {
        ctx.data_unchecked::<DataLoader<PrivateCertificateBodyLoader>>()
            .load_one(self.clone())
            .await
            .unwrap()
            .unwrap()
    }

    /// Returns true if the ``body`` will include encrypted secret key material
    async fn has_secret(&self) -> &bool {
        &self.secret
    }
}

/// Loads the fingerprint from the given [`Cert`]
impl From<&Cert> for Certificate {
    fn from(cert: &Cert) -> Self {
        Self {
            fingerprint: cert.fingerprint(),
            secret: cert.is_tsk(),
        }
    }
}

impl Certificate {
    /// Checks if the provided [`bytes::Bytes`] are a valid openpgp certificate
    /// and if it passes our custom [`CompliantPolicy`]
    pub fn check(value: &bytes::Bytes) -> Result<Cert, Error> {
        static POLICY: CompliantPolicy = CompliantPolicy::new();
        let cert = Cert::from_bytes(value).map_err(|_| {
            Error::from(InvalidCertificate::new(
                "cannot parse certificate".to_string(),
            ))
        })?;
        let v_cert = cert.with_policy(&POLICY, None).map_err(|e| {
            Error::from(InvalidCertificate {
                description: "certificate violates policy".to_string(),
                hint: Some(e.to_string()),
            })
        })?;

        let signing = KeyFlags::empty().set_signing();
        let authentication = KeyFlags::empty().set_authentication();
        let encryption = KeyFlags::empty()
            .set_transport_encryption()
            .set_storage_encryption();
        let certification = KeyFlags::empty().set_certification();

        // check that there's exactly one key for each operation

        if v_cert.keys().key_flags(signing).count() != 1 {
            return Err(
                InvalidCertificate::new("no or more than one key for signing".to_string()).into(),
            );
        }

        if v_cert.keys().key_flags(authentication).count() != 1 {
            return Err(InvalidCertificate::new(
                "no or more than one key for authentication".to_string(),
            )
            .into());
        }

        if v_cert.keys().key_flags(encryption).count() != 1 {
            return Err(InvalidCertificate {
                description: "no or more than one key for encryption".to_string(),
                hint: Some(
                    "be sure to set both transport and storage encryption as keyflags".to_string(),
                ),
            }
            .into());
        }

        if v_cert.keys().key_flags(certification).count() != 1 {
            return Err(InvalidCertificate::new(
                "no or more than one key for certification".to_string(),
            )
            .into());
        }

        Ok(cert)
    }

    pub fn from_public(fingerprint: Fingerprint) -> Self {
        Self {
            fingerprint,
            secret: false,
        }
    }

    pub fn from_private(fingerprint: Fingerprint) -> Self {
        Self {
            fingerprint,
            secret: true,
        }
    }
}
