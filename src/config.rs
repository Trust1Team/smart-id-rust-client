

use crate::utils::b64u_decode_to_string;
use crate::{Result, ServerError};
use std::env;
use std::sync::OnceLock;

pub fn config() -> &'static Config {
    static INSTANCE: OnceLock<Config> = OnceLock::new();

    INSTANCE.get_or_init(|| {
        Config::load_from_env().unwrap_or_else(|e| {
            panic!("FATAL - WHILE LOADING CONF - Cause: {e:?}");
        })
    })
}

#[derive(Debug, Clone)]
pub struct Config {
    pub host_url: String,
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub document_number: Option<String>,
    pub data_to_sign: Option<String>,
    pub certificate_level_qualified: Option<String>,
    pub certificate_level_advanced: Option<String>,
}

//TODO retrieve the keys through JWKS (IDP)
//TODO for issuance -> credential store GCP?
// Set defaults as this is an emergency track
impl Config {
    fn load_from_env() -> Result<Config> {
        Ok(Config {
            host_url: get_env("HOST_URL").unwrap(),
            relying_party_uuid: get_env("RELYING_PARTY_UUID").unwrap(),
            relying_party_name: get_env("RELYING_PARTY_NAME").unwrap(),
            document_number: env::var("DOCUMENT_NUMBER").ok(),
            data_to_sign: env::var("DATA_TO_SIGN").ok(),
            certificate_level_qualified: env::var("CERTIFICATE_LEVEL_QUALIFIED").ok(),
            certificate_level_advanced: env::var("CERTIFICATE_LEVEL_ADVANCED").ok(),
        })
    }
}

fn get_env(name: &'static str) -> Result<String> {
    env::var(name).map_err(|_| ServerError::ConfigMissingEnv(name))
}

fn get_env_b64_pem_as_string(name: &'static str) -> Result<String> {
    get_env(name).and_then(|v| b64u_decode_to_string(&v).map_err(|_| ServerError::ConfigWrongFormat(name)))
}

/// Server config
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub gtw_key_pub: String,
    pub gtw_key_priv: String,
    pub gtw_jwt_header_x5u: String,
}

impl From<&Config> for ServerConfig {
    fn from(cfg: &Config) -> Self {
        ServerConfig {
            gtw_key_pub: cfg.gtw_key_pub.clone(),
            gtw_key_priv: cfg.gtw_key_priv.clone(),
            gtw_jwt_header_x5u: cfg.gtw_jwt_header_x5u.clone(),
        }
    }
}   
