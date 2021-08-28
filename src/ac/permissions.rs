use bitflags::bitflags;

bitflags! {
        struct Flags: u64 {
            const MESSAGE_READ = 1 << 0;
            const MESSAGE_SEND = 1 << 1;
            const MESSAGE_EDIT = 1 << 2;
            const MESSAGE_DELETE = 1 << 3;
            const MESSAGE_DELETE_OWNED = 1 << 4;
            const CHANNEL_CREATE = 1 << 5;
            const CHANNEL_EDIT = 1 << 6;
            const CHANNEL_DELETE = 1 << 7;
            const USER_INVITE = 1 << 8;
            const USER_EDIT = 1 << 9;
            const USER_DELETE = 1 << 10;
            const USER_SUSPEND = 1 << 11;
        }
}

#[allow(dead_code)]
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
    UserSuspend,
}

/// This checks whether a given sum includes a permission
pub fn check_permission(sum: u64, permission: u64) -> bool {
    if permission < 64 {
        sum & permission != 0
    } else {
        false
    }
}
