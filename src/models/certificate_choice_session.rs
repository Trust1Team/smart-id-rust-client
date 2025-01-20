use crate::config::SmartIDConfig;
use crate::models::common::{CertificateLevel, RequestProperties};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

// region CertificateChoiceSessionRequest

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[skip_serializing_none]
pub struct CertificateChoiceRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub certificate_level: CertificateLevel,
    pub nonce: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub request_properties: Option<RequestProperties>,
}

impl CertificateChoiceRequest {
    pub async fn new(cfg: &SmartIDConfig) -> Self {
        CertificateChoiceRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            certificate_level: CertificateLevel::QUALIFIED,
            ..Self::default()
        }
    }
}

// endregion

// region CertificateChoiceSessionResponse

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateChoiceResponse {
    #[serde(rename = "sessionID")]
    pub session_id: String,
}

// endregion
