use async_graphql::{Interface, ID};

use super::{
    scalars::Bytes,
    types::{
        CertificateTaken, ExpiredRefreshToken, InvalidCertificate, InvalidChallenge,
        InvalidMasterPasswordHash, InvalidRefreshToken, InvalidSignature, InvalidUsername,
        PrivateCertificate, PublicCertificate, UnexpectedSigner, UnknownUser, User, UserSuspended,
        UsernameUnavailable,
    },
};

#[derive(Interface)]
#[graphql(
    field(
        name = "id",
        type = "ID",
        desc = "The unique identify (UUID) of the Actor as defined in RFC 4122"
    ),
    field(
        name = "certificate",
        type = "PublicCertificate",
        desc = "The certificate of the Actor without secret parts."
    ),
    field(
        name = "name",
        type = "String",
        desc = "The name of the Actor as an utf-8 string"
    )
)]
/// Represents an Actor.
pub(crate) enum Actor {
    User(User),
}

#[derive(Interface)]
#[graphql(
    field(
        name = "fingerprint",
        type = "String",
        desc = "The long-form fingerprint of the Certificate as a hex string"
    ),
    field(
        name = "content",
        type = "Bytes",
        desc = "The whole certificate as bytes"
    )
)]
/// Represents a PGP Certificate
pub(crate) enum Certificate {
    PublicCertificate(PublicCertificate),
    PrivateCertificate(PrivateCertificate),
}

#[derive(Interface)]
#[graphql(field(name = "description", type = "String"))]
/// Generic error type used for typed errors
pub(crate) enum Error {
    UsernameUnavailable(UsernameUnavailable),
    InvalidUsername(InvalidUsername),
    CertificateTaken(CertificateTaken),
    InvalidCetificate(InvalidCertificate),
    InvalidSignature(InvalidSignature),
    UnknownUser(UnknownUser),
    InvalidMasterPasswordHash(InvalidMasterPasswordHash),
    UserSuspended(UserSuspended),
    InvalidChallenge(InvalidChallenge),
    ExpiredRefreshToken(ExpiredRefreshToken),
    InvalidRefreshToken(InvalidRefreshToken),
    UnexpectedSigner(UnexpectedSigner),
}
