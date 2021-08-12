

// Note: If you're adding a constant here, you have to add it to the test at `crate::tests::permissions::test_bitflag_overlapping` too.
pub(crate) const MESSAGE_READ: u64 = 0b0000000000000000000000000000000000000000000000000000000000000001;
pub(crate) const MESSAGE_SEND: u64 = 0b0000000000000000000000000000000000000000000000000000000000000010;
pub(crate) const MESSAGE_EDIT: u64 = 0b0000000000000000000000000000000000000000000000000000000000000100;
pub(crate) const MESSAGE_DELETE: u64 = 0b0000000000000000000000000000000000000000000000000000000000001000;
pub(crate) const MESSAGE_DELETE_OWNED: u64 = 0b0000000000000000000000000000000000000000000000000000000000010000;
pub(crate) const CHANNEL_CREATE: u64 = 0b0000000000000000000000000000000000000000000000000000000000100000;
pub(crate) const CHANNEL_EDIT: u64 = 0b0000000000000000000000000000000000000000000000000000000001000000;
pub(crate) const CHANNEL_DELETE: u64 = 0b0000000000000000000000000000000000000000000000000000000010000000;
pub(crate) const USER_INVITE: u64 = 0b0000000000000000000000000000000000000000000000000000000100000000;
pub(crate) const USER_EDIT: u64 = 0b0000000000000000000000000000000000000000000000000000001000000000;
pub(crate) const USER_DELETE: u64 = 0b0000000000000000000000000000000000000000000000000000010000000000; 
pub(crate) const USER_SUSPEND: u64 = 0b0000000000000000000000000000000000000000000000000000100000000000;




pub enum Permission {
    /// Read the messages from a given textchannel
    MessageRead,
    /// Send a message in a given textchannel
    MessageSend,
    /// Edit own message after the user has sent it
    MessageEdit,
    /// Delete another users message
    MessageDelete,
    /// Delete a message previously sent by the user
    MessageDeleteOwned,
    /// Create a new channel
    ChannelCreate,
    /// Edit a channels description, name, etc
    ChannelEdit,
    /// Delete a channel
    ChannelDelete,
    /// Create a new useraccount
    UserInvite,
    /// Edit another user's account
    UserEdit,
    /// Delete another user's account
    UserDelete,
    /// Suspend another user's account
    UserSuspend
}

pub fn get_bitflag(permission: Permission) -> u64 {
    match permission {
        Permission::MessageRead => MESSAGE_READ,
        Permission::MessageSend => MESSAGE_SEND,
        Permission::MessageEdit => MESSAGE_EDIT,
        Permission::MessageDelete => MESSAGE_DELETE,
        Permission::MessageDeleteOwned => MESSAGE_DELETE_OWNED,
        Permission::ChannelCreate => CHANNEL_CREATE,
        Permission::ChannelEdit => CHANNEL_EDIT,
        Permission::ChannelDelete => CHANNEL_DELETE,
        Permission::UserInvite => USER_INVITE,
        Permission::UserEdit => USER_EDIT,
        Permission::UserDelete => USER_DELETE,
        Permission::UserSuspend => USER_SUSPEND,
    }

}

