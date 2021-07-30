use async_graphql::{Schema, EmptySubscription, ID, Object, Result, Error, Scalar, ScalarType, Value, InputValueResult, InputValueError};
use uuid::Uuid;
use bytes::{self, Bytes};
pub type AzumaSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub struct QueryRoot;
pub struct MutationRoot;


#[Object]
impl QueryRoot {
    async fn user(&self, username: String) -> User {
        User {
            id: ID(Uuid::new_v4().to_string()),
            username: username.to_string(),
            cert: Binary(Bytes::from("Hello"))
        }
    }
}

#[Object]
impl MutationRoot {
    async fn signup(&self, _username: String) -> Result<User> {
        Err(Error { message: "Failed".to_string(), extensions: None})
    }
}

#[derive(Clone)]
struct Binary(Bytes);

#[Scalar]
impl ScalarType for Binary {
    fn parse(value: Value) -> InputValueResult<Self> {
        if let Value::Binary(value) = value {
            Ok(Binary(value))
        } else {
            Err(InputValueError::expected_type(value))
        }
    }

    fn to_value(&self) -> Value {
        Value::Binary(self.0.clone())
    }
}

#[derive(Clone)]
struct User {
    id: ID,
    username: String,
    cert: Binary
}

#[Object]
impl User {
    async fn id(&self) -> ID {
        self.id.clone()
    }

    async fn name(&self) -> String {
        self.username.clone()
    }

    async fn cert(&self) -> Binary {
        self.cert.clone()
    }
}