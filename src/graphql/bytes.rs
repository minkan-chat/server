use async_graphql::scalar;
use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

#[derive(Serialize, Deserialize, Clone, Debug)]
#[repr(transparent)]
/// Bytes
///
/// A wrapper struct around [``bytes::Bytes``]
pub struct Bytes(bytes::Bytes);

impl Deref for Bytes {
    type Target = bytes::Bytes;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Bytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Bytes {
    pub fn into_inner(self) -> bytes::Bytes {
        self.0
    }
}

impl From<bytes::Bytes> for Bytes {
    fn from(value: bytes::Bytes) -> Self {
        Self(value)
    }
}
scalar!(Bytes, "Bytes", "A custom scalar that encodes bytes");
