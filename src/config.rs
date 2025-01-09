use crate::{Result};
use std::env;
use std::sync::OnceLock;
use crate::error::SmartIdClientError;

/// Loads the Smart ID configuration from the environment variables
pub fn config() -> &'static SmartIDConfig {
    static INSTANCE: OnceLock<SmartIDConfig> = OnceLock::new();

    INSTANCE.get_or_init(|| {
        SmartIDConfig::load_from_env().unwrap_or_else(|e| {
            panic!("FATAL - WHILE LOADING CONF - Cause: {e:?}");
        })
    })
}

/// Smart ID Client Configuration
#[derive(Debug, Clone)]
pub struct SmartIDConfig {
    pub url: String,
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub client_request_timeout: Option<u64>,
    pub client_retry_attempts: Option<u8>,
    pub client_retry_delay: Option<u64>,
    pub client_enable_polling: Option<bool>,
}

impl From<SmartIDConfig> for SmartIDConfigBuilder {
    fn from(config: SmartIDConfig) -> Self {
        SmartIDConfigBuilder {
            url: Some(config.url),
            relying_party_uuid: Some(config.relying_party_uuid),
            relying_party_name: Some(config.relying_party_name),
            client_request_timeout: config.client_request_timeout,
            client_retry_attempts: config.client_retry_attempts,
            client_retry_delay: config.client_retry_delay,
            client_enable_polling: config.client_enable_polling,
        }
    }
}

// region: Config Builder
/// Smart ID Configuration Builder
///
/// Use this builder to create a Smart ID Configuration using a building pattern
/// # Example
/// ```
/// # use anyhow::Result;
/// # use smart_id_rust_client::config::{SmartIDConfig, SmartIDConfigBuilder};
/// let cfg: Result<SmartIDConfig> = SmartIDConfigBuilder::new()
///     .url("https://sid.demo.sk.ee/smart-id-rp/v3") // DEMO environment
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct SmartIDConfigBuilder {
    url: Option<String>,
    relying_party_uuid: Option<String>,
    relying_party_name: Option<String>,
    client_request_timeout: Option<u64>,
    client_retry_attempts: Option<u8>,
    client_retry_delay: Option<u64>,
    pub client_enable_polling: Option<bool>,
}

impl SmartIDConfigBuilder {
    pub fn new() -> Self {
        SmartIDConfig::default().into() //from env
    }

    pub fn url(&mut self, url: impl Into<String>) -> &mut Self {
        let _ = self.url.insert(url.into());
        self
    }

    pub fn relying_party_uuid(&mut self, rp_uuid: impl Into<String>) -> &mut Self {
        let _ = self.relying_party_uuid.insert(rp_uuid.into());
        self
    }

    pub fn relying_party_name(&mut self, rp_name: impl Into<String>) -> &mut Self {
        let _ = self.relying_party_name.insert(rp_name.into());
        self
    }

    pub fn client_request_timeout(&mut self, req_timeout: u64) -> &mut Self {
        let _ = self.client_request_timeout.insert(req_timeout);
        self
    }

    pub fn client_retry_attempts(&mut self, req_attempts: u8) -> &mut Self {
        let _ = self.client_retry_attempts.insert(req_attempts);
        self
    }

    pub fn client_retry_delay(&mut self, req_delay: u64) -> &mut Self {
        let _ = self.client_retry_delay.insert(req_delay);
        self
    }

    pub fn build(&self) -> Result<SmartIDConfig> {
        Ok(SmartIDConfig {
            url: self.url.clone().ok_or(SmartIdClientError::ConfigMissingException("url"))?,
            relying_party_uuid: self.relying_party_uuid.clone().ok_or(SmartIdClientError::ConfigMissingException("relying_party_uuid"))?,
            relying_party_name: self.relying_party_name.clone().ok_or(SmartIdClientError::ConfigMissingException("relying_party_name"))?,
            client_request_timeout: self.client_request_timeout.clone(),
            client_retry_attempts: self.client_retry_attempts.clone(),
            client_retry_delay: self.client_retry_delay.clone(),
            client_enable_polling: self.client_enable_polling.clone(),
        })
    }

}
// endregion: Config Builder

impl Default for SmartIDConfig {
    fn default() -> Self {
        Self::load_from_env().expect("Failed to initialize Smart ID Client or load SmartIDConfig from env")
    }
}

impl SmartIDConfig {
    pub fn load_from_env() -> Result<SmartIDConfig> {
        Ok(SmartIDConfig {
            url: get_env("HOST_URL").unwrap(),
            relying_party_uuid: get_env("RELYING_PARTY_UUID").unwrap(),
            relying_party_name: get_env("RELYING_PARTY_NAME").unwrap(),
            client_request_timeout: get_env_u64("CLIENT_REQ_NETWORK_TIMEOUT_MILLIS").ok(),
            client_retry_attempts: get_env_u8("CLIENT_REQ_MAX_ATTEMPTS").ok(),
            client_retry_delay: get_env_u64("CLIENT_REQ_DELAY_SEONDS_BETWEEN_ATTEMPTS").ok(),
            client_enable_polling: get_env_bool("ENABLE_POLLING_BY_LIB").ok(),
        })
    }
}

fn get_env(name: &'static str) -> Result<String> {
    env::var(name).map_err(|_| SmartIdClientError::ConfigMissingException(name).into())
}

fn get_env_u64(name: &'static str) -> Result<u64> {
    env::var(name).unwrap().parse().map_err(|_| SmartIdClientError::ConfigMissingException(name).into())
}

fn get_env_u8(name: &'static str) -> Result<u8> {
    env::var(name).unwrap().parse().map_err(|_| SmartIdClientError::ConfigMissingException(name).into())
}

fn get_env_bool(name: &'static str) -> Result<bool> {
    env::var(name).unwrap().parse().map_err(|_| SmartIdClientError::ConfigMissingException(name).into())
}