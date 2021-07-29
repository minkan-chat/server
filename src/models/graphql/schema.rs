use async_graphql::{Schema, EmptySubscription, ID, Object, Result, Error};
use uuid::Uuid;

pub type AzumaSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub struct QueryRoot;
pub struct MutationRoot;


#[Object]
impl QueryRoot {
    async fn user(&self, username: String) -> User {
        User {
            id: ID(Uuid::new_v4().to_string()),
            username: username.to_string(),
            cert: vec![0x42u8]
        }
    }
}

#[Object]
impl MutationRoot {
    async fn signup(&self, _username: String) -> Result<User> {
        Err(Error { message: "Failed".to_string(), extensions: None})
    }
}
struct User {
    id: ID,
    username: String,
    cert: Vec<u8>
}

#[Object]
impl User {
    async fn id(&self) -> ID {
        self.id.clone()
    }

    async fn name(&self) -> String {
        self.username.clone()
    }

    async fn cert(&self) -> Vec<u8> {
        self.cert.clone()
    }
}