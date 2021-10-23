use sequoia_openpgp::{
    crypto::mpi::PublicKey,
    policy::{Policy, StandardPolicy},
    types::{Curve}, Packet,
};

#[derive(Debug)]
pub struct SignalCompliantPolcy<'a>(StandardPolicy<'a>);

impl SignalCompliantPolcy<'static> {
    pub const fn new() -> Self {
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
