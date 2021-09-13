mod priv_cert;
mod pub_cert;

use crate::{
    fallible::{Error, InvalidCertificate},
    graphql::Bytes,
};
use async_graphql::Interface;
pub use priv_cert::*;
pub use pub_cert::*;
use sequoia_openpgp::{
    cert::ValidCert,
    crypto::mpi::PublicKey,
    policy::{Policy, StandardPolicy},
    types::{Curve, KeyFlags, SignatureType},
    Cert, Packet,
};

#[derive(Interface)]
#[graphql(
    field(
        name = "fingerprint",
        type = "String",
        desc = "\
The fingerprint of the certificate as defined in [RFC4880 section 12.2][1]

[1]: https://datatracker.ietf.org/doc/html/rfc4880#section-12.2\
"
    ),
    field(name = "content", type = "Bytes")
)]
/// Certificate
///
/// A OpenPGP certificate
pub enum Certificate {
    PrivateCertificate(PrivateCertificate),
    PublicCertificate(PublicCertificate),
}

#[derive(Debug)]
pub struct SignalCompliantPolcy<'a>(StandardPolicy<'a>);

impl SignalCompliantPolcy<'static> {
    const fn new() -> Self {
        Self(StandardPolicy::new())
    }
}

macro_rules! disallow_unknown_and_private_variants {
    ($e:path, $a:ident $(,)?) => {
        use $e as base;
        match $a {
            base::Private(_) => anyhow::bail!("private variants are not allowed."),
            base::Unknown(_) => anyhow::bail!("unknown variants are not allowed."),
            _ => (),
        };
    };
}

impl<'a> Policy for SignalCompliantPolcy<'a> {
    fn key(
        &self,
        ka: &sequoia_openpgp::cert::prelude::ValidErasedKeyAmalgamation<
            sequoia_openpgp::packet::key::PublicParts,
        >,
    ) -> sequoia_openpgp::Result<()> {
        if ka.key_expiration_time().is_some() {
            anyhow::bail!("only keys without an expiration time are supported.");
        }
        match ka.has_unencrypted_secret() {
            true => anyhow::bail!("found unencypted secret."),
            false => (),
        }

        match ka.mpis() {
            PublicKey::EdDSA { curve: _, q: _ } => {
                // EdDSA is only used with curve 25519
                self.0.key(ka)
            }
            PublicKey::ECDH {
                curve,
                hash: _,
                q: _,
                sym: _,
            } => match curve {
                Curve::Cv25519 => self.0.key(ka), // fallback to the standard policy to check other parts of the key
                _ => anyhow::bail!("only ECDH with curve 25519 is supported."),
            },
            _ => anyhow::bail!("only curve 25519 ciphersuites are supported."),
        }
    }
    fn signature(
        &self,
        sig: &sequoia_openpgp::packet::Signature,
        sec: sequoia_openpgp::policy::HashAlgoSecurity,
    ) -> sequoia_openpgp::Result<()> {
        if let sequoia_openpgp::types::SignatureType::Unknown(_) = sig.typ() {
            anyhow::bail!("unknown variants are not allowed.");
        }
        self.0.signature(sig, sec)
    }

    fn symmetric_algorithm(
        &self,
        algo: sequoia_openpgp::types::SymmetricAlgorithm,
    ) -> sequoia_openpgp::Result<()> {
        disallow_unknown_and_private_variants!(sequoia_openpgp::types::SymmetricAlgorithm, algo);
        self.0.symmetric_algorithm(algo)
    }

    fn aead_algorithm(
        &self,
        algo: sequoia_openpgp::types::AEADAlgorithm,
    ) -> sequoia_openpgp::Result<()> {
        disallow_unknown_and_private_variants!(sequoia_openpgp::types::AEADAlgorithm, algo);
        self.0.aead_algorithm(algo)
    }

    fn packet(&self, packet: &sequoia_openpgp::Packet) -> sequoia_openpgp::Result<()> {
        match packet {
            Packet::Trust(_) => {
                anyhow::bail!("trust packets are implementation-defined and are not allowed")
            }
            Packet::Unknown(_) => anyhow::bail!("unknown packets are not allowed"),
            _ => (),
        }
        self.0.packet(packet)
    }
}

/// strips certifications from others and all user attributes
/// also strips all userids that are not ``username``
pub(self) fn strip_cert(cert: Cert, username: String) -> Result<Cert, Error> {
    // the fingerprint of the certificate
    let fingerprint = cert.fingerprint();
    // certificate as raw packets
    let packets = cert.into_packets();
    // packets of a certificate without any Certifications
    let valid_packets = packets.filter(|packet| match packet {
        // certifications are a signature packet
        Packet::Signature(sig) => match sig.typ() {
            // and there are 4 forms of certifications and 1 extra form for third party attestation
            SignatureType::GenericCertification
            | SignatureType::PersonaCertification
            | SignatureType::CasualCertification
            | SignatureType::PositiveCertification // we accept signatures
            | SignatureType::AttestationKey => sig.issuer_fingerprints().all(|f| f == &fingerprint),
            _ => true,
        },
        Packet::UserID(user_id) => user_id.value() == username.as_bytes(),
        Packet::UserAttribute(_) => false,
        _ => true,
    });

    // build a new certificate from only the filtered packets
    Cert::from_packets(valid_packets).map_err(|e| {
        Error::InvalidCertificate(InvalidCertificate {
            description: e.to_string(),
            hint: None,
        })
    })
}

#[macro_export]
/// macro to call [``crate::certificate::strip_cert``]
macro_rules! strip_cert {
    ($t:ty) => {
        impl $t {
            /// Removes certifications, user attributes and all userid except ``username``
            #[allow(unused)]
            pub fn strip_cert(self, username: String) -> Result<Self, $crate::fallible::Error> {
                let cert = super::strip_cert(self.cert, username)?;
                Ok(Self {
                    fingerprint: cert.fingerprint(),
                    cert,
                })
            }
        }
    };
}

#[macro_export]
/// used by try_cert macro
macro_rules! try_cert_parse_policy {
    ($t:ty, $from:ty) => {
        impl std::convert::TryFrom<$from> for $t {
            type Error = $crate::fallible::Error;
            fn try_from(value: $from) -> Result<Self, Self::Error> {
                use sequoia_openpgp::parse::Parse;
                let cert = sequoia_openpgp::Cert::from_bytes(&value).map_err(|_| {
                    Self::Error::InvalidCertificate($crate::fallible::InvalidCertificate {
                        description: "cannot parse certificate".to_string(),
                        hint: None,
                    })
                })?;
                $crate::certificate::policy_check(&cert)?;
                Ok(Self {
                    fingerprint: cert.fingerprint(),
                    cert,
                })
            }
        }
    };
}
#[macro_export]
/// macro to generate TryFrom for certificate types
macro_rules! try_cert {
    ($t:ty) => {
        $crate::try_cert_parse_policy!($t, Vec<u8>);
        $crate::try_cert_parse_policy!($t, &[u8]);
        $crate::try_cert_parse_policy!($t, bytes::Bytes);
    };
}

pub fn policy_check(cert: &Cert) -> Result<ValidCert<'_>, Error> {
    static POLICY: SignalCompliantPolcy = SignalCompliantPolcy::new();
    cert.with_policy(&POLICY, None).map_err(|e| {
        Error::InvalidCertificate(InvalidCertificate {
            description: "certificate violates policy".to_string(),
            hint: Some(e.to_string()), // anyhow error description
        })
    })
}

macro_rules! match_key {
    ($expr:expr) => {
        match $expr {
            true => {
                return Err(Error::InvalidCertificate(InvalidCertificate {
                    description: "found multiple keys for the same operation".to_string(),
                    hint: None,
                }))
            }
            false => $expr = true,
        }
    };
}
/// checks a [``Cert``] for the required keys
///
/// * one key for signing
/// * one key for authentication
/// * one key for transport and storage encryption
/// * primary only for certification
pub fn full_cert_check(cert: &Cert) -> Result<(), Error> {
    // signing, authentication, encryption, certification
    let mut keys = (false, false, false, false);
    let cert = policy_check(cert)?;
    let signing: KeyFlags = KeyFlags::empty().set_signing();
    let authentication: KeyFlags = KeyFlags::empty().set_authentication();
    let encryption: KeyFlags = KeyFlags::empty()
        .set_transport_encryption()
        .set_storage_encryption();
    let certification: KeyFlags = KeyFlags::empty().set_certification();
    for key in cert.keys() {
        match key.key_flags().unwrap() {
            k if k == signing => match_key!(keys.0),
            k if k == authentication => match_key!(keys.1),
            k if k == encryption => match_key!(keys.2),
            k if k == certification => match_key!(keys.3),
            _ => {
                return Err(Error::InvalidCertificate(InvalidCertificate {
                    description: "found disallowed keyflags".to_string(),
                    hint: Some(format!(
                        "keyflags for key {}: {:?}",
                        key.fingerprint().to_spaced_hex(),
                        key.key_flags().unwrap()
                    )),
                }))
            }
        }
    }

    // check if there is one key for each operation
    if keys != (true, true, true, true) {
        return Err(Error::InvalidCertificate(InvalidCertificate {
            description: "certificate is missing one or more keys".to_string(),
            hint: Some(format!(
                "(signing, authentication, encryption, certificate): {:?}",
                &keys
            )),
        }));
    }
    Ok(())
}
