use std::env;
use crate::config::SmartIDConfig;
use crate::error::SmartIdClientError;
use crate::models::APIVersion;

/// Smart ID Client Configuration
#[derive(Debug, Clone)]
pub struct SmartIDConfigV3 {
    pub root_url: String,
    pub api_path: String,
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub client_request_timeout: Option<u64>,
    pub client_retry_attempts: Option<u8>,
    pub client_retry_delay: Option<u64>,
    pub client_enable_polling: Option<bool>,
}

impl SmartIDConfigV3 {
    pub fn load_from_env(api_version: APIVersion) -> anyhow::Result<SmartIDConfigV3> {
        Ok(SmartIDConfigV3 {
            root_url: get_env("ROOT_URL_V3")?,
            api_path: get_env("API_PATH_V3")?,
            relying_party_uuid: get_env("RELYING_PARTY_UUID")?,
            relying_party_name: get_env("RELYING_PARTY_NAME")?,
            client_request_timeout: get_env_u64("CLIENT_REQ_NETWORK_TIMEOUT_MILLIS").ok(),
            client_retry_attempts: get_env_u8("CLIENT_REQ_MAX_ATTEMPTS").ok(),
            client_retry_delay: get_env_u64("CLIENT_REQ_DELAY_SEONDS_BETWEEN_ATTEMPTS").ok(),
            client_enable_polling: get_env_bool("ENABLE_POLLING_BY_LIB").ok(),
        })
    }
}

fn get_env(name: &'static str) -> anyhow::Result<String> {
    env::var(name).map_err(|_| SmartIdClientError::ConfigMissingException(name).into())
}

fn get_env_u64(name: &'static str) -> anyhow::Result<u64> {
    env::var(name)?.parse().map_err(|_| SmartIdClientError::ConfigMissingException(name).into())
}

fn get_env_u8(name: &'static str) -> anyhow::Result<u8> {
    env::var(name)?.parse().map_err(|_| SmartIdClientError::ConfigMissingException(name).into())
}

fn get_env_bool(name: &'static str) -> anyhow::Result<bool> {
    env::var(name)?.parse().map_err(|_| SmartIdClientError::ConfigMissingException(name).into())
}