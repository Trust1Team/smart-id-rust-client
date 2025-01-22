use crate::error::SmartIdClientError;
use std::env;

const DYNAMIC_LINK_PATH: &str = "/dynamic-link";

/// Smart ID Client Configuration
#[derive(Debug, Clone)]
pub struct SmartIDConfig {
    pub root_url: String,
    pub api_path: String,
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub client_request_timeout: Option<u64>,
}

impl SmartIDConfig {
    pub fn load_from_env() -> anyhow::Result<SmartIDConfig> {
        Ok(SmartIDConfig {
            root_url: get_env("ROOT_URL")?,
            api_path: get_env("V3_API_PATH")?,
            relying_party_uuid: get_env("RELYING_PARTY_UUID")?,
            relying_party_name: get_env("RELYING_PARTY_NAME")?,
            client_request_timeout: get_env_u64("CLIENT_REQ_NETWORK_TIMEOUT_MILLIS").ok(),
        })
    }

    pub fn api_url(&self) -> String {
        format!("{}{}", self.root_url, self.api_path)
    }

    pub fn dynamic_link_url(&self) -> String {
        format!("{}{}", self.root_url, DYNAMIC_LINK_PATH)
    }

    pub fn is_demo(&self) -> bool {
        self.root_url == "https://sid.demo.sk.ee"
    }
}

fn get_env(name: &'static str) -> anyhow::Result<String> {
    env::var(name).map_err(|_| SmartIdClientError::ConfigMissingException(name).into())
}

fn get_env_u64(name: &'static str) -> anyhow::Result<u64> {
    env::var(name)?
        .parse()
        .map_err(|_| SmartIdClientError::ConfigMissingException(name).into())
}
