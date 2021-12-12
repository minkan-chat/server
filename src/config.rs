use std::{fs::write, path::PathBuf};

use figment::{
    providers::{Env, Format, Toml},
    Figment,
};
use openidconnect::{
    core::{CoreClient, CoreProviderMetadata},
    reqwest::async_http_client,
    ClientId, ClientSecret, IssuerUrl, RedirectUrl,
};
use serde::Deserialize;
use url::Url;

#[derive(Deserialize, Clone)]
pub struct Config {
    /// Configuration for openid connect
    pub openid_connect: OidcConfig,
    /// the address the server should bind to
    pub listen: String,
    /// The uri to the postgres database
    pub postgres_uri: String,
    /// The uri to the redis cache
    pub redis_uri: String,
}

#[derive(Deserialize, Clone)]
pub struct OidcConfig {
    /// The id of the client used for operations like a [Authorization Request][1]
    ///
    /// [1]: https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
    pub client_id: String,
    /// The secret for signing operations as per [section 10.1][1]
    ///
    /// [1]: https://openid.net/specs/openid-connect-core-1_0.html#Signing
    pub client_secret: String,
    /// Used for [open id connect discovery][1]
    ///
    /// [1]: https://openid.net/specs/openid-connect-discovery-1_0.html
    pub discovery_url: Url,
    /// The url the User-Agent should be redirected to after an authentication
    pub redirect_url: Url,
}

impl OidcConfig {
    /// Performs a request to the openid connect discovery endpoint and returns
    /// a [`CoreClient`]
    pub async fn load_client(self) -> anyhow::Result<CoreClient> {
        let issuer_url = IssuerUrl::from_url(self.discovery_url);

        let redirect_url = RedirectUrl::from_url(self.redirect_url);

        // perform request to the openid connect endpoint
        let meta = CoreProviderMetadata::discover_async(issuer_url, async_http_client).await?;

        let client_id = ClientId::new(self.client_id);
        let client_secret = ClientSecret::new(self.client_secret);
        let client = CoreClient::from_provider_metadata(meta, client_id, Some(client_secret))
            .set_redirect_uri(redirect_url);
        Ok(client)
    }
}
impl Config {
    /// Load the configuration
    ///
    /// The default path is a file called `config.toml` in $PWD/config.toml
    pub fn load() -> anyhow::Result<Self> {
        // either read the path for the config from the env <CRATE_NAME>_CONFIG
        // or use the default path relativ to the executable
        let path: PathBuf = match std::env::var(concat!(env!("CARGO_CRATE_NAME"), "_CONFIG")) {
            Ok(path) => path.into(),
            Err(e) => {
                debug!("Cannot read env var for config path: {}", e);
                std::env::current_dir()?.join("config.toml")
            }
        };

        // write the sample config to the file only if it does not exist
        if !path.exists() {
            info!("Creating config with default options at {}", path.display());
            write(&path, include_str!("../other/config.sample"))?;
        }

        info!("Reading config from {}", path.display());
        Ok(Figment::new()
            // first read the config file
            .merge(Toml::file(path))
            // and then let the env overwrite options
            .merge(Env::prefixed(env!("CARGO_CRATE_NAME")))
            .extract()?)
    }
}

#[test]
fn test_parse_default_config() {
    use figment::providers::{Data, Toml};
    // ensure that the default config is valid and can be parsed
    let _: Config = Figment::new()
        .merge(Data::<Toml>::string(include_str!("../other/config.sample")))
        .extract()
        .expect("default config is malformed");
}
