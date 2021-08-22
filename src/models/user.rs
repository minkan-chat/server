use sqlx::types::Uuid;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    pub master_pw_hash: Vec<u8>,
    pub enc_cert: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub suspended: bool,
    pub suspended_reason: Option<String>
}