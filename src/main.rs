use actix_web::body::Body;

use actix_web::web::Bytes;
use actix_web::{guard, web, App, HttpRequest, HttpResponse, HttpServer, Result};
use actix_web::{post, HttpMessage};

use async_graphql::dataloader::DataLoader;
use async_graphql::extensions::ApolloTracing;
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql::EmptySubscription;
use async_graphql_actix_web::Request;

use graphql::GraphQLSchema;

use log::info;
use moka::future::{Cache, CacheBuilder};
use redis::Client;
use sqlx::{migrate, PgPool};

use std::time::Duration;

use crate::config::Config;
use crate::graphql::{Mutations, Queries};

const GRAPHQL_ENDPOINT: &str = "/graphql";
const GRAPHQL_PLAYGROUND_ENDPOINT: &str = "/playground";

mod ac;
mod actors;
mod auth;
mod certificate;
mod config;
mod fallible;
mod graphql;
mod loader;

#[post("/graphql")]
async fn execute_graphql(
    schema: web::Data<GraphQLSchema>,
    req: Request,
    http_request: HttpRequest,
) -> HttpResponse {
    let req = req.into_inner();
    let response = &schema.execute(req).await;
    let content_type = http_request.content_type();

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

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();
    // Load config

    let config = Config::new();

    // Connect to db
    info!("Connecting to the database");
    let db: PgPool = PgPool::connect(&config.db_uri)
        .await
        .unwrap_or_else(|e| panic!("Can't connect to database: {}", e));
    info!("Running database migrations...");
    migrate!("./migrations/")
        .run(&db)
        .await
        .expect("couldn't run database migrations");

    let client =
        redis::Client::open(config.redis_uri.clone()).expect("can't connect to redis server");

    let pool: r2d2::Pool<Client> = r2d2::Pool::builder().build(client).unwrap();

    // cache items for one minute (60 seconds)
    let challenge_cache: Cache<String, ()> = CacheBuilder::new(10_000)
        .time_to_live(Duration::from_secs(60))
        .build();

    let token_expiry_cache: Cache<uuid::Uuid, i64> = CacheBuilder::new(100_000)
        .time_to_live(Duration::from_secs(120))
        .build();

    // build the graphql schema
    let schema = GraphQLSchema::build(Queries::default(), Mutations::default(), EmptySubscription)
        //.register_type::<Error>() // https://github.com/async-graphql/async-graphql/issues/595#issuecomment-892321221
        //.register_type::<Certificate>()
        .register_type::<actors::Actor>()
        .register_type::<certificate::Certificate>()
        .register_type::<graphql::Node>()
        .extension(ApolloTracing)
        .data(config.clone())
        .data(DataLoader::new(crate::loader::UsernameLoader::new(
            db.clone(),
        )))
        .data(pool)
        .data(config.jwt_secret.0.clone())
        .data(config.jwt_secret.1.clone())
        .data(config.server_cert.clone())
        .data(challenge_cache)
        .data(token_expiry_cache)
        .finish();

    info!("Starting http server on {}", config.listen);

    HttpServer::new(move || {
        App::new()
            .data(schema.clone())
            .service(execute_graphql)
            .route("/graphql/sdl", web::get().to(getsdl))
            .service(
                web::resource(GRAPHQL_PLAYGROUND_ENDPOINT)
                    .guard(guard::Get())
                    .to(playground),
            )
    })
    .bind(config.listen)?
    .run()
    .await
}
