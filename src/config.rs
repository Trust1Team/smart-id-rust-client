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
    pub document_number: Option<String>,
    pub data_to_sign: Option<String>,
    pub certificate_level_qualified: Option<String>,
    pub certificate_level_advanced: Option<String>,
}

impl From<SmartIDConfig> for SmartIDConfigBuilder {
    fn from(config: SmartIDConfig) -> Self {
        SmartIDConfigBuilder {
            url: Some(config.url),
            relying_party_uuid: Some(config.relying_party_uuid),
            relying_party_name: Some(config.relying_party_name),
            document_number: config.document_number,
            data_to_sign: config.data_to_sign,
            certificate_level_qualified: config.certificate_level_qualified,
            certificate_level_advanced: config.certificate_level_advanced,
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
///     .url("https://sid.demo.sk.ee/smart-id-rp/v2") // DEMO environment
///     .build();
/// ```
#[derive(Debug, Clone)]
pub struct SmartIDConfigBuilder {
    url: Option<String>,
    relying_party_uuid: Option<String>,
    relying_party_name: Option<String>,
    document_number: Option<String>,
    data_to_sign: Option<String>,
    certificate_level_qualified: Option<String>,
    certificate_level_advanced: Option<String>,
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

    pub fn document_number(&mut self, doc_nr: impl Into<String>) -> &mut Self {
        let _ = self.document_number.insert(doc_nr.into());
        self
    }

    pub fn data_to_sign(&mut self, dts: impl Into<String>) -> &mut Self {
        let _ = self.data_to_sign.insert(dts.into());
        self
    }

    pub fn build(&self) -> Result<SmartIDConfig> {
        Ok(SmartIDConfig {
            url: self.url.clone().ok_or(SmartIdClientError::ConfigMissingException("url"))?,
            relying_party_uuid: self.relying_party_uuid.clone().ok_or(SmartIdClientError::ConfigMissingException("relying_party_uuid"))?,
            relying_party_name: self.relying_party_name.clone().ok_or(SmartIdClientError::ConfigMissingException("relying_party_name"))?,
            document_number: self.document_number.clone(),
            data_to_sign: self.data_to_sign.clone(),
            certificate_level_qualified: self.certificate_level_qualified.clone(),
            certificate_level_advanced: self.certificate_level_advanced.clone(),
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
            document_number: env::var("DOCUMENT_NUMBER").ok(),
            data_to_sign: env::var("DATA_TO_SIGN").ok(),
            certificate_level_qualified: env::var("CERTIFICATE_LEVEL_QUALIFIED").ok(),
            certificate_level_advanced: env::var("CERTIFICATE_LEVEL_ADVANCED").ok(),
        })
    }
}

fn get_env(name: &'static str) -> Result<String> {
    env::var(name).map_err(|_| SmartIdClientError::ConfigMissingException(name).into())
}