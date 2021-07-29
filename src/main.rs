use actix_web::{guard, web, App, HttpResponse, HttpServer, Result};
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql::{EmptySubscription, Schema};
use async_graphql_actix_web::{Request};
use sqlx::{PgPool, migrate};
use std::fs::read_to_string;
use crate::models::graphql::schema::{AzumaSchema, QueryRoot, MutationRoot};
use serde::Deserialize;
use actix_web::body::Body;
use actix_web::web::Bytes;
use actix_web::{post};

const GRAPHQL_ENDPOINT: &str = "/graphql";
const GRAPHQL_PLAYGROUND_ENDPOINT: &str = "/playground";

mod models;

#[post("/graphql")]
async fn graphql(schema: web::Data<AzumaSchema>, req: Request) -> HttpResponse {
    HttpResponse::Ok().body(Body::Bytes(Bytes::from(serde_cbor::to_vec(&schema.execute(req.into_inner()).await).unwrap())))
}

async fn getsdl(schema: web::Data<AzumaSchema>) -> HttpResponse {
    HttpResponse::Ok().body(Body::from(schema.sdl()))
}

async fn playground() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(playground_source(
            GraphQLPlaygroundConfig::new(GRAPHQL_ENDPOINT)),
        ))
}

#[derive(Deserialize, Clone)]
pub struct AzumaConfig {
    pub db_uri: String,
    pub host_uri: String,
}

impl AzumaConfig {
    fn load(path: &str) -> Self {
        toml::from_str(&read_to_string(path).expect("Couldn't read file")).expect("couldn't deserialize config")
    }
}
#[actix_web::main]
async fn main() -> std::io::Result<()> {

    // Load config
    let config  = AzumaConfig::load("config.toml");

    // Connect to db
    let db = PgPool::connect(&config.db_uri).await.unwrap();
    migrate!("./migrations/")
        .run(&db)
        .await
        .expect("couldn't run database migrations");

    let schema = Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .finish();

    HttpServer::new(move || {
        let mut app = App::new()
            .data(schema.clone())
            .service(graphql)
            .route("/graphql/sdl", web::get().to(getsdl));
        //println!("Playground: http://{}", config.host_uri);
        if cfg!(debug_assertions) {
            app = app.service(web::resource(GRAPHQL_PLAYGROUND_ENDPOINT).guard(guard::Get()).to(playground));
        }
        app
    })
    .bind(config.host_uri)?
    .run()
    .await
}
