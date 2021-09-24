use crate::graphql::Bytes;
use async_graphql::Object;
use sequoia_openpgp::{serialize::SerializeInto, Cert, Fingerprint};
use std::ops::Deref;

use super::PrivateCertificate;

#[derive(Clone, Debug)]
/// a ``Certificate`` that has no secret key material in it
#[non_exhaustive]
pub struct PublicCertificate {
    pub fingerprint: Fingerprint,
    pub cert: Cert,
}

crate::strip_cert!(PublicCertificate);
crate::try_cert!(PublicCertificate);

#[Object]
/// A ``Certificate`` that contains no secret key material
impl PublicCertificate {
    pub async fn fingerprint(&self) -> String {
        self.fingerprint.to_hex()
    }

    pub async fn content(&self) -> Bytes {
        bytes::Bytes::from(self.cert.export_to_vec().expect("failed to serialize cert")).into()
    }
}

impl From<Cert> for PublicCertificate {
    fn from(cert: Cert) -> Self {
        Self {
            fingerprint: cert.fingerprint(),
            cert,
        }
    }
}

impl From<PrivateCertificate> for PublicCertificate {
    fn from(cert: PrivateCertificate) -> Self {
        Self {
            fingerprint: cert.cert.fingerprint(),
            cert: cert.cert.strip_secret_key_material(),
        }
    }
}

impl Deref for PublicCertificate {
    type Target = Cert;
    fn deref(&self) -> &Self::Target {
        &self.cert
    }
}
