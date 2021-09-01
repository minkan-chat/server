use crate::models::graphql::interfaces::{Certificate, Error};
use crate::models::graphql::mutations::helpers::Claims;
use crate::models::graphql::{mutations::Mutation, queries::Query, schema::GraphQLSchema};
use actix_web::body::Body;

use actix_web::http::header::Header;
use actix_web::web::Bytes;
use actix_web::{guard, web, App, HttpRequest, HttpResponse, HttpServer, Result};
use actix_web::{post, HttpMessage};
use actix_web_httpauth::headers::authorization::{Authorization, Bearer};
use async_graphql::extensions::ApolloTracing;
use async_graphql::http::{playground_source, GraphQLPlaygroundConfig};
use async_graphql::EmptySubscription;
use async_graphql_actix_web::Request;
use jsonwebtoken::{decode, DecodingKey, EncodingKey, Validation};
use lazy_static::lazy_static;
use log::{debug, info};
use moka::future::{Cache, CacheBuilder};
use sequoia_openpgp::Cert;
use serde::Deserialize;
use sqlx::{migrate, PgPool};
use std::fs::read_to_string;
use std::str::FromStr;
use std::time::Duration;

const GRAPHQL_ENDPOINT: &str = "/graphql";
const GRAPHQL_PLAYGROUND_ENDPOINT: &str = "/playground";

mod ac;
mod models;

#[post("/graphql")]
async fn graphql(
    schema: web::Data<GraphQLSchema>,
    key: web::Data<DecodingKey>,
    req: Request,
    http_request: HttpRequest,
) -> HttpResponse {
    let req = req.into_inner();
    let req = if let Ok(auth) = Authorization::<Bearer>::parse(&http_request) {
        lazy_static! {
            static ref VALIDATION: Validation = Validation::default();
        }
        let token = decode::<Claims>(auth.as_ref().token(), &key, &VALIDATION);
        if let Ok(token) = token {
            req.data(token)
        } else {
            req
        }
    } else {
        req
    };

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

#[derive(Clone, Deserialize, Debug)]
pub struct Config {
    pub(crate) db_uri: String,
    pub(crate) host_uri: String,
    // The unencrypted private certificate of the server armor encoded.
    pub(crate) server_cert: ServerCert,
    pub(crate) jwt_secret: String,
}

impl Config {
    fn load(path: &str) -> Self {
        toml::from_str(&read_to_string(path).expect("Couldn't read file"))
            .expect("couldn't deserialize config")
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ServerCert(Cert);

impl<'de> Deserialize<'de> for ServerCert {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let cert = String::deserialize(deserializer)?;
        Ok(ServerCert(Cert::from_str(&cert).unwrap_or_else(|e| {
            panic!("Invalid server certificate: {}", e)
        })))
    }
}
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pretty_env_logger::init();
    // Load config
    info!("Loading config ...");
    let config = Config::load("config.toml");
    debug!("Config: {:#?}", config);

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

    // cache items for one minute (60 seconds)
    let challenge_cache: Cache<String, ()> = CacheBuilder::new(10_000)
        .time_to_live(Duration::from_secs(60))
        .build();

    let token_expiry_cache: Cache<uuid::Uuid, i64> = CacheBuilder::new(100_000)
        .time_to_live(Duration::from_secs(120))
        .build();

    let jwt_encoding_key =
        EncodingKey::from_secret(&hex::decode(&config.jwt_secret).expect("Invalid jwt hex secret"));

    let jwt_decoding_key =
        DecodingKey::from_secret(&hex::decode(&config.jwt_secret).expect("Invalid jwt hex secret"));

    // build the graphql schema
    let schema = GraphQLSchema::build(Query, Mutation, EmptySubscription)
        .register_type::<Error>() // https://github.com/async-graphql/async-graphql/issues/595#issuecomment-892321221
        .register_type::<Certificate>()
        .extension(ApolloTracing)
        .data(config.clone())
        .data(challenge_cache)
        .data(token_expiry_cache)
        .data(db)
        .data(jwt_encoding_key)
        .data(jwt_decoding_key.clone())
        .finish();

    info!("Starting http server on {}", config.host_uri);

    HttpServer::new(move || {
        App::new()
            .data(schema.clone())
            .data(jwt_decoding_key.clone())
            .service(graphql)
            .route("/graphql/sdl", web::get().to(getsdl))
            .service(
                web::resource(GRAPHQL_PLAYGROUND_ENDPOINT)
                    .guard(guard::Get())
                    .to(playground),
            )
    })
    .bind(config.host_uri.clone())?
    .run()
    .await
}
