use uuid::Uuid;

pub struct User {
    /// The users chosen username<br>
    /// **Note:** This is modifiable by the user
    pub username: String,
    /// Unique identifier to identify the user
    pub id: Uuid,

    pub cert: Vec<u8>,
    /// Hash of the users password
    pub password: [u8; 32],
}