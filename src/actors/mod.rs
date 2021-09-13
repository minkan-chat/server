use async_graphql::Interface;

mod authenticated_user;
mod user;
use crate::certificate::PublicCertificate;
pub use authenticated_user::AuthenticatedUser;
pub use user::User;

#[derive(Interface, Debug)]
#[graphql(
    field(name = "name", type = "String", desc = "The name of the actor"),
    field(
        name = "certificate",
        type = "PublicCertificate",
        desc = "The OpenPGP certificate of the ``Actor``"
    )
)]
/// Shared behavior
///
/// An ``Actor`` is everything that can *act*.
/// An action can be to send a message in a channel or to kick someone.
/// Currently, we only have the ``User`` as an Actor so
/// this interface is primary to allow future non-breaking extensions.
///
/// # Example
///
/// Alice can perform *actions* like sending a message, so she's an
/// Actor.
///
/// In the future, we could introduce a Bot which, like Alice, is able
/// to send messages, kick someone or take any other action. So the bot would
/// be an Actor too.
pub enum Actor {
    User(User),
    AuthenticatedUser(AuthenticatedUser),
}
