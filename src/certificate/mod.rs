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

        // keys with `transport` or `storage` encryption key flag
        let mut enc_keys = v_cert.keys().key_flags(encryption);

        if let Some(key) = enc_keys.next() {
            if enc_keys.next().is_some() {
                return Err(InvalidCertificate {
                    description: "found more than one encryption key".to_string(),
                    hint: None,
                }
                .into());
            }

            // we only accept keys that are both for transport and storage encryption
            if !(key.for_transport_encryption() && key.for_storage_encryption()) {
                return Err(InvalidCertificate {
                    description: "key not for both transport and storage encryption".to_string(),
                    hint: None,
                }
                .into());
            }
        } else {
            return Err(InvalidCertificate {
                description: "found no key for encryption".to_string(),
                hint: None,
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

#[cfg(test)]
mod tests {
    use crate::certificate::Certificate;
    #[test]
    fn missing_key_check() {
        // is missing an encryption key
        let s_c_a = include_bytes!("../../other/tests/missing_key/s_c_a.pgp")[..].into();
        Certificate::check(&s_c_a).expect_err("cert is missing encryption keys");

        // is missing authentication key
        let s_c_e = include_bytes!("../../other/tests/missing_key/s_c_e.pgp")[..].into();
        Certificate::check(&s_c_e).expect_err("cert is missing authentication key");

        // is missing signing key
        let c_a_e = include_bytes!("../../other/tests/missing_key/c_a_e.pgp")[..].into();
        Certificate::check(&c_a_e).expect_err("cert is missing signing key");

        // has only a key for storage encryption but not one for transport encryption
        let s_c_a_es = include_bytes!("../../other/tests/missing_key/s_c_a_es.pgp")[..].into();
        Certificate::check(&s_c_a_es).expect_err("cert is missing transport encryption key");

        // has two keys one with storage encryption, one with transport encryption
        let s_c_a_et_es =
            include_bytes!("../../other/tests/missing_key/s_c_a_et_es.pgp")[..].into();
        Certificate::check(&s_c_a_et_es)
            .expect_err("cert has two encryption keys for transport and storage encryption");

        // this cert is valid but has two encryption keys
        let s_c_a_e_e = include_bytes!("../../other/tests/missing_key/s_c_a_e_e.pgp")[..].into();
        Certificate::check(&s_c_a_e_e).expect_err("cert has two encryption keys");

        // this is a valid cert
        let valid = include_bytes!("../../other/tests/missing_key/valid.pgp")[..].into();
        Certificate::check(&valid).expect("cert is valid");
    }
}
