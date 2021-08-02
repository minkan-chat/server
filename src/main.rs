use crate::models::graphql::{schema::GraphQLSchema, queries::Query, mutations::Mutation};
use actix_web::body::Body;

use actix_web::post;
use actix_web::web::Bytes;
use actix_web::{guard, web, App, HttpRequest, HttpResponse, HttpServer, Result};
use async_graphql::EmptySubscription;
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql_actix_web::Request;
use serde::Deserialize;
use sqlx::{migrate, PgPool};
use std::fs::read_to_string;

const GRAPHQL_ENDPOINT: &str = "/graphql";
const GRAPHQL_PLAYGROUND_ENDPOINT: &str = "/playground";

mod models;

#[post("/graphql")]
async fn graphql(
    schema: web::Data<GraphQLSchema>,
    req: Request,
    http_request: HttpRequest,
) -> HttpResponse {
    let response = &schema.execute(req.into_inner()).await;
    let content_type = http_request
        .headers()
        .get("Content-Type")
        .unwrap() // could crash the worker
        .to_str()
        .unwrap();

    match content_type {
        "application/json" => HttpResponse::Ok()
            .content_type("application/json")
            .body(serde_json::to_string(&response).unwrap()),
        _ => HttpResponse::Ok().body(Body::Bytes(Bytes::from(
            serde_cbor::to_vec(&response).unwrap(),
        ))),
    }
}

async fn getsdl(schema: web::Data<GraphQLSchema>) -> HttpResponse {
    HttpResponse::Ok().body(Body::from(schema.sdl()))
}

async fn playground() -> Result<HttpResponse> {
    Ok(HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(playground_source(GraphQLPlaygroundConfig::new(
            GRAPHQL_ENDPOINT,
        ))))
}

#[derive(Deserialize, Clone)]
pub struct AzumaConfig {
    pub db_uri: String,
    pub host_uri: String,
}

impl AzumaConfig {
    fn load(path: &str) -> Self {
        toml::from_str(&read_to_string(path).expect("Couldn't read file"))
            .expect("couldn't deserialize config")
    }
}
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load config
    let config = AzumaConfig::load("config.toml");

    // Connect to db
    let db = PgPool::connect(&config.db_uri).await.unwrap();
    migrate!("./migrations/")
        .run(&db)
        .await
        .expect("couldn't run database migrations");

    let schema = GraphQLSchema::build(Query, Mutation, EmptySubscription)
        .finish();

    HttpServer::new(move || {
        let mut app = App::new()
            .data(schema.clone())
            .service(graphql)
            .route("/graphql/sdl", web::get().to(getsdl));
        if cfg!(debug_assertions) {
            app = app.service(
                web::resource(GRAPHQL_PLAYGROUND_ENDPOINT)
                    .guard(guard::Get())
                    .to(playground),
            );
        }
        app
    })
    .bind(config.host_uri)?
    .run()
    .await
}
