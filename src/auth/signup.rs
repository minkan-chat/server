//! Signup
//!
//! This module keeps models related to the ``signup`` mutation.

use crate::certificate::PublicCertificate;
use crate::fallible::{Error, InvalidChallenge, InvalidSignature};
use crate::graphql::Bytes;
use crate::result_type;
use async_graphql::InputObject;
use sequoia_openpgp::packet::Signature;
use sequoia_openpgp::parse::Parse;

result_type!(SignupResult, crate::actors::AuthenticatedUser);

#[derive(InputObject)]
pub struct SignupUserInput {
    /// The name, the user would like to use.
    /// The user needs this name to login and for
    /// other users so they can find them.
    pub name: String,
    /// The ``master password hash``
    pub hash: Bytes,
    /// The PGP certificate the user'd like to use with encrypted
    /// secret parts.\
    /// Note: the certificate has to be unique to this user.
    pub certificate: Bytes,
}

#[derive(InputObject)]
pub struct ChallengeProof {
    /// The challenge, the client obtained from the ``challenge`` query.
    /// This will be 32 byte.
    pub challenge: String,
    /// a signature of the ``challenge`` made with the primary key of the user
    pub signature: Bytes,
}

impl ChallengeProof {
    /// verifies that the challenge's signature is made by the ``signer``
    // TODO: prio: add test for this
    // TODO: mid-prio: benchmark to see if it's blocking too long
    pub async fn verify(&self, signer: PublicCertificate) -> Result<(), Error> {
        let mut signature = Signature::from_bytes(&self.signature.as_ref()).map_err(|_| {
            Error::InvalidSignature(InvalidSignature {
                description: "failed to parse signature".to_string(),
                hint: None,
            })
        })?;

        let challenge = hex::decode(&self.challenge).map_err(|_| {
            Error::InvalidChallenge(InvalidChallenge {
                challenge: self.challenge.clone(),
                description: "challenge is not a hex string".to_string(),
                hint: None,
            })
        })?;

        signature
            .verify_message(signer.cert.primary_key().key(), &challenge)
            .map_err(|e| {
                Error::InvalidChallenge(InvalidChallenge {
                    challenge: self.challenge.clone(),
                    description: "cannot verify signature".to_string(),
                    hint: Some(e.to_string()),
                })
            })
    }
}
