#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
use actix_web::{middleware::Logger, web, App, HttpServer};
use config::Config;
use redis::aio::ConnectionManager;
use sqlx::{migrate, PgPool};
use tokio::sync::Mutex;

#[macro_use]
extern crate log;

mod authn;
mod config;
#[cfg(feature = "oidc_login")]
mod oidc;

#[actix_web::main]
/// The entry point into the application
async fn main() -> anyhow::Result<()> {
    // enable logging
    env_logger::init();

    let config = Config::load()?;

    // connect to the database
    info!("Connecting to the postgres database");
    let db: PgPool = PgPool::connect(&config.postgres_uri).await?;
    info!("Running database migrations");
    migrate!("./migrations/").run(&db).await?;

    // create the redis client
    let redis = redis::Client::open(&*config.redis_uri)?;
    let redis = ConnectionManager::new(redis).await?;

    // start the http server
    info!("Starting server at {}", &config.listen);
    let listen = config.listen.clone();
    Ok(HttpServer::new(move || {
        // allow this because else there's no nice way to register endpoints
        // based on a feature flag
        #[allow(clippy::let_and_return)]
        let app = App::new()
            .wrap(Logger::default())
            // register endpoints
            .app_data(web::Data::new(config.clone()))
            .app_data(web::Data::new(Mutex::new(redis.clone())))
            .app_data(web::Data::new(db.clone()));

        // make built-in authentication with an openid connect identity
        // provider optional
        #[cfg(feature = "oidc_login")]
        let app = app.service(
            web::scope("/oidc")
                .service(oidc::login_redirect)
                .service(oidc::login_callback),
        );

        app
    })
    .bind(listen)?
    .run()
    .await?)
}
