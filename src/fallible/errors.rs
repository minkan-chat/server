use crate::actors::Actor;
use crate::certificate::PublicCertificate;
use crate::error_type;
use chrono::{DateTime, Utc};

use async_graphql::Interface;

#[derive(Interface, Debug)]
#[graphql(
    field(name = "description", type = "String", desc="\
A short description what went wrong\\
Note: This description is only for the developer.
An application should match ``__typename`` and display
a message based on that."
),
    field(name = "hint", type = "&Option<String>", desc="\
A hint for the developer what they could do to prevent this error"
) // only &Option slice works?
)]
pub enum Error {
    UsernameUnavailable(UsernameUnavailable),
    InvalidUsername(InvalidUsername),
    CertificateTaken(CertificateTaken),
    InvalidCertificate(InvalidCertificate),
    InvalidSignature(InvalidSignature),
    InvalidMasterPasswordHash(InvalidMasterPasswordHash),
    InvalidChallenge(InvalidChallenge),
    ExpiredRefreshToken(ExpiredRefreshToken),
    InvalidRefreshToken(InvalidRefreshToken),
    UnexpectedSigner(UnexpectedSigner),
    Unexpected(Unexpected),
}

error_type! {
    /// UsernameUnavailable
    ///
    /// The supplied username is unavailable.
    /// This error usually occurs when another user has the same
    /// name. However, it could also occur because the name violates
    /// the name policy.
    struct UsernameUnavailable {
        /// The name that was given in the input object
        name: String,
    }
}

error_type! {
    /// InvalidUsername
    ///
    /// The supplied username is invalid.
    /// This error occurs mostly if the username contains
    /// invalid characters or otherwise does not meet the
    /// criteria.
    ///
    /// # Criteria
    ///
    /// To be valid, a username must be between 3-16 chars long,
    /// and only consist of letters, numbers and underscores.
    /// Regex: ``^[a-z0-9_]{3,16}$``
    struct InvalidUsername {
        /// The name that was given in the input object
        name: String,
    }
}

error_type! {
    /// CertificateTaken
    ///
    /// This error means that another user's PGP certificate has the same fingerprint.
    /// The chance that this will happen by accident is incredible low. It is way more
    /// likely that the client has a bug and sent the same certificate twice.
    struct CertificateTaken {
        /// The certificate that was sent in the input.\
        /// Note: If the input certificate contained secret key material,
        /// this will be stripped. A ``PrivateCertificate`` becomes a ``PublicCertificate``.
        certificate: Box<PublicCertificate>,
    }
}

error_type!(
    /// InvalidCertificate
    ///
    /// The server failed to parse the certificate.
    /// The client should check how it encodes the certificate.
    InvalidCertificate
);

error_type!(
    /// InvalidSignature
    ///
    /// The server either failed to parse the signature or parsed the signature
    /// successful but failed to verify the signature. In the latter case, the
    /// server would probably respond with ``UnexpectedSigner`` instead.
    InvalidSignature
);

error_type! {
    /// UnknownUser
    ///
    /// The server can't find a ``User`` with supplied name
    struct UnknownUser {
        /// The ``name`` field contains the name given in the input object
        name: String,
    }
}

error_type!(
    /// InvalidMasterPasswordHash
    ///
    /// The hash sent is not valid.
    ///
    /// # Details
    ///
    /// The client uses the username and the cleartext password to generate a hash called
    /// the ``master  key``. It generates that hash by taking the username as a salt and
    /// the password as the payload and running it through a PBKDF2-SHA256  function
    /// with ``100,000`` iterations. The output is called ``master key``.\
    /// The master key is then sent through another PBKDF2-SHA256 function with ``1``
    /// interation. This time, the salt is the cleartext password and the payload
    /// is the ``master key``. The output is called ``master password hash``.\
    /// The ``master password hash`` is sent to the server. The server stored a argon2id
    /// hash of that ``master password hash`` and so hashes the ``master password hash``
    /// again and compares these two hashes.\
    /// If you want to read further, please refer to the [bitwarden site][1] which you can
    /// use as a guide.
    ///
    /// [1]: https://bitwarden.com/help/article/bitwarden-security-white-paper/#overview-of-the-master-password-hashing-key-derivation-and-encryption-process
    InvalidMasterPasswordHash
);
error_type! {
    /// UserSuspended
    ///
    /// The user is not able to perform any actions because they are suspended.\
    /// A user might get suspended because they violated the rules.
    struct UserSuspended {
        /// The optional date and time since the user is suspended in utc
        since: Option<DateTime<Utc>>,
        /// The optional reason for the suspension
        reason: Option<String>,

    }
}
error_type! {
    /// InvalidChallenge
    ///
    /// The challenge provided by the client is invalid.\
    /// Note: if the challenge's signature is also invalid,
    /// another ``InvalidSignature`` error could be attached.
    struct InvalidChallenge {
        /// The challenge provided in the input object
        challenge: String,
    }
}
error_type!(
    /// ExpiredRefreshToken
    ///
    /// The [``exp``][1] field in the [``JWT``][2] indicates that the token is expired.
    /// The server won't allow this token to request a new ``TokenPair``.\
    /// The client could check the [``exp``][1] field by itself and see
    /// that the token is expired. This would prevent an unneccessary request.\
    /// Note: The client has to authenticate again with the ``master password hash``.
    /// This requires the password from the end user.
    ///
    /// [1]: https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.4
    /// [2]: https://jwt.io/
    ExpiredRefreshToken
);
error_type!(
    /// InvalidRefreshToken
    ///
    /// The token is invalid. The server might provide additional information
    /// in the ``description`` field.
    ///
    /// # Details
    ///
    /// If the server detects that a refresh token is being reused, the user's
    /// token kill timestamp[1] will be set to the current time. This invalids
    /// all access and refresh tokens.\
    /// This approach is based on ``automatic reuse detection``. You can read more
    /// about why it is deployed under
    /// [``Refresh Token Automatic Reuse Detection`` at Auth0][1].
    ///
    /// [1]: https://auth0.com/blog/refresh-tokens-what-are-they-and-when-to-use-them/#Refresh-Token-Automatic-Reuse-Detection
    InvalidRefreshToken
);
error_type! {
    /// UnexpectedSigner
    ///
    /// The server could verify signature but detected that the signature
    /// is not made by the expected signer.
    struct UnexpectedSigner {
        /// If the server can figure out the expected signer,
        /// this field will be set
        expected: Option<Actor>,
        /// If the server can figure out the actually signer,
        /// this field will contain the signer
        got: Option<Actor>,
    }
}

error_type! {
    /// Unexpected
    ///
    /// An unexpected error. Probably something internal like a offline database
    Unexpected
}
