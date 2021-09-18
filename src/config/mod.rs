use std::{fs::File, io::Write, net::SocketAddr, str::FromStr};

use directories::ProjectDirs;
use figment::{
    providers::{Env, Format, Toml},
    Figment,
};

use jsonwebtoken::{DecodingKey, EncodingKey};
use log::info;
use sequoia_openpgp::Cert;
use serde::{Deserialize, Deserializer};

#[derive(Deserialize, Clone)]
pub struct Config {
    pub db_uri: String,
    pub redis_uri: String,
    pub listen: SocketAddr,
    #[serde(deserialize_with = "deserialize_jwt_secret")]
    pub jwt_secret: (EncodingKey, DecodingKey),
    #[serde(deserialize_with = "deserialize_cert")]
    pub server_cert: Cert,
}

impl Config {
    pub fn new() -> Self {
        let project_dir = ProjectDirs::from("rs", "minkan", env!("CARGO_CRATE_NAME"))
            .expect("cannot build project dir path");

        let config_path = project_dir.config_dir();

        // create config dir if not exist
        if !config_path.exists() {
            info!("creating config file at {}", config_path.display());
            let mut file = File::create(config_path).expect("cannot create file"); // blocking but we cant use tokio::fs because actix-web 4 is not released
            file.write_all(include_bytes!("../../other/config.sample")) // include sample config
                .expect("cannot write to config file")
        }

        info!("parsing config file at {}", config_path.display());
        let config: Self = Figment::new()
            .merge(Toml::file(config_path))
            .merge(Env::prefixed(concat!(env!("CARGO_CRATE_NAME"), "_")))
            .extract()
            .unwrap();
        config
    }
}

// i really wanna use the ec secret from the server's certificate tho. but imo does not make no sense unless the key is signed
fn deserialize_jwt_secret<'de, D>(secret: D) -> Result<(EncodingKey, DecodingKey), D::Error>
where
    D: Deserializer<'de>,
{
    let secret = String::deserialize(secret)?;
    let encoding_key = EncodingKey::from_secret(secret.as_bytes());
    let decoding_key: DecodingKey = DecodingKey::from_secret(secret.as_bytes());
    Ok((encoding_key, decoding_key))
}

fn deserialize_cert<'de, D>(cert: D) -> Result<Cert, D::Error>
where
    D: Deserializer<'de>,
{
    let armor = String::deserialize(cert)?; // deserialize the armor string
    let cert = Cert::from_str(&armor).map_err(<D::Error as serde::de::Error>::custom)?;
    Ok(cert)
}
