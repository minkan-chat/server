use async_graphql::scalar;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
/// An ISO-8601 encoded UTC date string
pub struct DateTime(pub(super) chrono::DateTime<chrono::Utc>);

scalar!(DateTime, "DateTime", "An ISO-601 encoded UTC date string");

#[derive(Deserialize, Serialize)]
/// A custom scalar that encodes Bytes
pub struct Bytes(pub(super) bytes::Bytes);

scalar!(Bytes, "Bytes", "A custom scalar that encodes Bytes");
