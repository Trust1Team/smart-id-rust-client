use crate::error::Result;
use crate::error::SmartIdClientError;
use crate::models::common::SchemeName;
use std::env;
use std::str::FromStr;

/// Smart ID Client Configuration
///
/// This struct holds the configuration details required to interact with the Smart ID service.
/// It includes the root URL, API path, relying party UUID, relying party name, and an optional client request timeout.
///
/// This can be loaded from environment variables using the `load_from_env` method.
///
/// # Properties
///
/// * `root_url` - The base URL of the Smart ID service, e.g., `https://sid.sk.ee`.
/// * `api_path` - The API path to be appended to the root URL, e.g., `/v3`.
/// * `scheme_version` - The scheme/environment to use, e.g smart-id (production) or smart-id-demo (demo).
/// * `relying_party_uuid` - The UUID of the relying party, obtained from Smart ID.
/// * `relying_party_name` - The name of the relying party, obtained from Smart ID.
/// * `client_request_timeout` - An optional timeout for client requests, in milliseconds. This is not used for the long-polling status request.
#[derive(Debug, Clone)]
pub struct SmartIDConfig {
    pub root_url: String,
    pub api_path: String,
    pub scheme_name: SchemeName,
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub client_request_timeout: Option<u64>,
    pub long_polling_timeout: u64,
}

impl SmartIDConfig {
    /// Loads the Smart ID configuration from environment variables.
    ///
    /// # Returns
    ///
    /// * `Ok(SmartIDConfig)` - If all required environment variables are present and valid.
    /// * `Err(anyhow::Error)` - If any required environment variable is missing or invalid.
    pub fn load_from_env() -> Result<SmartIDConfig> {
        Ok(SmartIDConfig {
            root_url: get_env("SMART_ID_ROOT_URL")?,
            api_path: get_env("SMART_ID_V3_API_PATH")?,
            scheme_name: SchemeName::from_str(&get_env("SMART_ID_SCHEME_NAME")?)
                .map_err(|_| SmartIdClientError::ConfigMissingException("SMART_ID_SCHEME_NAME"))?,
            relying_party_uuid: get_env("RELYING_PARTY_UUID")?,
            relying_party_name: get_env("RELYING_PARTY_NAME")?,
            client_request_timeout: get_env_u64("CLIENT_REQ_NETWORK_TIMEOUT_MILLIS").ok(),
            long_polling_timeout: get_env_u64("CLIENT_LONG_POLLING_TIMEOUT_MILLIS")
                .unwrap_or(120000),
        })
    }

    /// Constructs the full API URL using the root URL and API path.
    ///
    /// # Returns
    ///
    /// * `String` - The full API URL.
    pub fn api_url(&self) -> String {
        format!("{}{}", self.root_url, self.api_path)
    }

    pub(crate) fn is_demo(&self) -> bool {
        self.root_url == "https://sid.demo.sk.ee"
    }
}

fn get_env(name: &'static str) -> Result<String> {
    env::var(name).map_err(|_| SmartIdClientError::ConfigMissingException(name))
}

fn get_env_u64(name: &'static str) -> Result<u64> {
    env::var(name)
        .map_err(|_| SmartIdClientError::ConfigMissingException(name))
        .and_then(|val| {
            val.parse()
                .map_err(|_| SmartIdClientError::ConfigMissingException(name))
        })
}
