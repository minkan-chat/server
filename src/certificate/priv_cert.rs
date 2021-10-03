use std::convert::TryFrom;

use sequoia_openpgp::{serialize::SerializeInto, Cert, Fingerprint};

use crate::{
    fallible::{Error, InvalidCertificate},
    graphql::Bytes,
};

use async_graphql::{Object, Result};

#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct PrivateCertificate {
    fingerprint: Fingerprint,
    pub cert: Cert,
}

crate::strip_cert!(PrivateCertificate);
crate::try_cert!(PrivateCertificate);

impl TryFrom<Cert> for PrivateCertificate {
    type Error = Error;

    fn try_from(cert: Cert) -> Result<Self, Self::Error> {
        super::full_cert_check(&cert)?;
        for key in cert.keys() {
            // if a key has no secret, it's not a private key
            if !key.has_secret() {
                return Err(Error::InvalidCertificate(InvalidCertificate {
                    description: "certificate is missing a secret key".to_string(),
                    hint: Some(format!(
                        "key is missing for {}",
                        key.fingerprint().to_spaced_hex()
                    )),
                }));
            }
        }

        Ok(Self {
            fingerprint: cert.fingerprint(),
            cert,
        })
    }
}
#[Object]
impl PrivateCertificate {
    pub async fn fingerprint(&self) -> String {
        self.fingerprint.to_hex()
    }

    pub async fn body(&self) -> Bytes {
        bytes::Bytes::from(
            self.cert
                .as_tsk() // only TSK exports secret key material
                .export_to_vec()
                .expect("failed to serialize cert"),
        )
        .into()
    }
}
