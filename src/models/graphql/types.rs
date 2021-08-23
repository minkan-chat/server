use async_graphql::{InputObject, Object, SimpleObject, Union, ID};
use sequoia_openpgp::{
    crypto::mpi::PublicKey,
    policy::{Policy, StandardPolicy},
    serialize::SerializeInto,
    types::Curve,
    Cert,
};

use super::scalars::{Bytes, DateTime};

////// Types //////
///// Output Types /////
#[derive(Clone)]
pub(crate) struct PublicCertificate {
    pub(super) cert: Cert,
}

#[Object]
/// Represents a Certificate without secret parts
impl PublicCertificate {
    pub(crate) async fn fingerprint(&self) -> String {
        self.cert.fingerprint().to_hex()
    }

    pub(crate) async fn content(&self) -> Bytes {
        Bytes(bytes::Bytes::from(
            self.cert
                .to_vec()
                .expect("Certificate from the database is valid"),
        ))
    }
}

pub(crate) struct PrivateCertificate {
    pub(super) cert: Cert,
}

#[Object]
/// Represents a Certificate with encrypted secret parts
impl PrivateCertificate {
    pub(crate) async fn fingerprint(&self) -> String {
        self.cert.fingerprint().to_hex()
    }

    /// The encrypted Certificate. In order for the secret parts to be used, the stretched master key is needed.
    pub(crate) async fn content(&self) -> Bytes {
        Bytes(bytes::Bytes::from(
            self.cert
                .as_tsk()
                .to_vec()
                .expect("Certificate from the database is valid"),
        ))
    }
}

pub(crate) struct User {
    pub id: ID,
    pub certificate: PublicCertificate,
    pub name: String,
}

#[Object]
/// A normal user
impl User {
    pub(crate) async fn id(&self) -> ID {
        self.id.clone()
    }

    pub(crate) async fn certificate(&self) -> PublicCertificate {
        self.certificate.clone()
    }

    pub(crate) async fn name(&self) -> String {
        self.name.clone()
    }
}

#[derive(SimpleObject)]
/// Used for the response after a successful authentication
pub(crate) struct AuthenticatedUser {
    pub(crate) id: ID,
    pub(crate) name: String,
    /// Since the client needs the secret parts of the PGP Certificate, the server sends them to the client for decryption
    pub(crate) certificate: PrivateCertificate,
    pub(crate) token: TokenPair,
}
///// Input Types /////
#[derive(InputObject)]
/// The information the server needs for the signup process
pub(crate) struct SignupUserInput {
    /// The name the user wants to use for login etc. If not set, the first identity of the PGP Certificate is used.
    pub(crate) name: String,
    /// The master password hash derived from the master password
    pub(crate) hash: Bytes,
    /// The PGP Certificate WITH encrypted secret parts generated by the client
    pub(crate) certificate: Bytes, // PrivateCertificate is not an input type, so Bytes have to do
    /// A random challenge obtained by calling the getChallenge query signed by the primary key of the Certificate.
    /// Used to proof that the client has the control over the Certificate's primary key and therefore the whole Certificate.
    pub(crate) challenge: String,
    pub(crate) signature: Bytes,
}

#[derive(InputObject)]
/// Used for the login credentials
pub(crate) struct AuthenticationCredentialsUserInput {
    /// The name of the user used to login
    pub(crate) name: String,
    /// the master password hash derived from the master password
    pub(crate) hash: Bytes,
}

////// Result types (unions) //////
///// Signup Result /////
#[derive(SimpleObject)]
/// Used to have typed error types
pub(crate) struct SignupResult {
    /// The generated User for the client to get its id. If there is an error, it should be null
    pub(crate) user: Option<AuthenticatedUser>,
    /// The errors that may have occured. If there were no errors, it is empty ([]) NOT null
    pub(crate) errors: Vec<SignupError>,
}

///// Authentication Result /////
#[derive(SimpleObject)]
pub(crate) struct AuthenticationResult {
    // Returns the AuthenticatedUser with the Certificate WITH encrypted secret parts
    pub(crate) user: Option<AuthenticatedUser>,
    /// The errors that may have occured. If there were no errors, it is empty ([]) NOT null
    pub(crate) errors: Vec<AuthenticationError>,
}
////// Error types //////
///// Signup Errors /////
#[derive(Union, Debug)]
/// All error that can occur during signup
pub(crate) enum SignupError {
    UsernameUnavailable(UsernameUnavailable),
    InvalidUsername(InvalidUsername),
    CertificateTaken(CertificateTaken),
    InvalidCertificate(InvalidCertificate),
    InvalidSignature(InvalidSignature),
    InvalidChallenge(InvalidChallenge),
}

#[derive(SimpleObject, Debug)]
/// The username is already taken or unavailable for other reasons
pub(crate) struct UsernameUnavailable {
    pub(crate) description: String,
}

#[derive(SimpleObject, Debug)]
/// If a username containts invalid characters (only letters and numbers are allowed) or is too long.
pub(crate) struct InvalidUsername {
    pub(crate) description: String,
}

#[derive(SimpleObject, Debug)]
/// Another user's certificate has the same fingerprint.
/// This error is normally almost impossible but can happen if the client tries to use the same certificate twice.
pub(crate) struct CertificateTaken {
    pub(crate) description: String,
}

#[derive(SimpleObject, Debug)]
/// The certificate malformed or something similar
pub(crate) struct InvalidCertificate {
    pub(crate) description: String,
}

#[derive(SimpleObject, Debug)]
/// The certification of the server's PGP Certificate is invalid
pub(crate) struct InvalidSignature {
    pub(crate) description: String,
}

#[derive(SimpleObject, Debug)]
pub(crate) struct InvalidChallenge {
    pub(crate) description: String,
}

///// Authentication Errors /////
#[derive(Union)]
/// All errors that can occur during authentication/login
pub(crate) enum AuthenticationError {
    UnknownUser(UnknownUser),
    InvalidMasterPasswordHash(InvalidMasterPasswordHash),
    UserSuspended(UserSuspended),
}

#[derive(SimpleObject)]
/// The username is unknown
pub(crate) struct UnknownUser {
    pub(crate) description: String,
}

#[derive(SimpleObject)]
/// The master password hash derived from the master password is invalid
pub(crate) struct InvalidMasterPasswordHash {
    pub(crate) description: String,
}

#[derive(SimpleObject)]
/// The user is suspended
pub(crate) struct UserSuspended {
    pub(crate) description: String,
    /// the date the user got suspended
    pub(crate) since: Option<DateTime>,
    /// the reason for the suspension
    pub(crate) reason: Option<String>,
}

#[derive(SimpleObject)]
pub(crate) struct RefreshTokenResult {
    pub(crate) token: Option<TokenPair>,
    pub(crate) errors: Vec<RefreshTokenError>,
}

#[derive(Union)]
pub(crate) enum RefreshTokenError {
    InvalidRefreshToken(InvalidRefreshToken),
    ExpiredRefreshToken(ExpiredRefreshToken),
}
#[derive(SimpleObject)]
/// The token is malformed or invalid
pub(crate) struct InvalidRefreshToken {
    pub(crate) description: String,
}

#[derive(SimpleObject)]
/// The token is expired. The client can check this before making the request
/// by looking at the ``exp`` field in the claims
pub(crate) struct ExpiredRefreshToken {
    pub(crate) description: String,
}

#[derive(SimpleObject)]
/// Containts the current access token and the refresh token for the next token pair.
/// Both are Json Web Tokens
pub(crate) struct TokenPair {
    pub(crate) access_token: String,
    pub(crate) refresh_token: String,
}

#[derive(Debug)]
pub struct SignalCompliantPolcy<'a>(StandardPolicy<'a>);

impl<'a> Default for SignalCompliantPolcy<'a> {
    fn default() -> Self {
        Self(StandardPolicy::default())
    }
}

impl<'a> Policy for SignalCompliantPolcy<'a> {
    fn key(
        &self,
        ka: &sequoia_openpgp::cert::prelude::ValidErasedKeyAmalgamation<
            sequoia_openpgp::packet::key::PublicParts,
        >,
    ) -> sequoia_openpgp::Result<()> {
        if ka.key_expiration_time().is_some() {
            anyhow::bail!("Only keys without an expiration time are supported.");
        }
        match ka.has_unencrypted_secret() {
            true => anyhow::bail!("Found unencypted secret."),
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
                _ => anyhow::bail!("Only ECDH with curve 25519 is supported."),
            },
            _ => anyhow::bail!("Only curve 25519 ciphersuites are supported."),
        }
    }
    fn signature(
        &self,
        sig: &sequoia_openpgp::packet::Signature,
        sec: sequoia_openpgp::policy::HashAlgoSecurity,
    ) -> sequoia_openpgp::Result<()> {
        self.0.signature(sig, sec)
    }

    fn symmetric_algorithm(
        &self,
        algo: sequoia_openpgp::types::SymmetricAlgorithm,
    ) -> sequoia_openpgp::Result<()> {
        self.0.symmetric_algorithm(algo)
    }

    fn aead_algorithm(
        &self,
        algo: sequoia_openpgp::types::AEADAlgorithm,
    ) -> sequoia_openpgp::Result<()> {
        self.0.aead_algorithm(algo)
    }

    fn packet(&self, packet: &sequoia_openpgp::Packet) -> sequoia_openpgp::Result<()> {
        self.0.packet(packet)
    }
}
