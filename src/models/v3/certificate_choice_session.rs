use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use crate::common::CertificateLevel;
use crate::config::SmartIDConfig;
use crate::models::v3::common::{RequestProperties, SessionConfig};

// region CertificateChoiceSessionRequest

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[skip_serializing_none]
pub struct CertificateRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub certificate_level: Option<CertificateChoiceCertificateLevel>,
    pub nonce: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub request_properties: Option<RequestProperties>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum CertificateChoiceCertificateLevel {
    QUALIFIED,
    ADVANCED,
    QSCD,
}


impl CertificateRequest {
    pub async fn new(cfg: &SmartIDConfig) -> Self {
        CertificateRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            certificate_level: Some(CertificateChoiceCertificateLevel::QUALIFIED),
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

impl Into<SessionConfig> for CertificateChoiceResponse {
    fn into(self) -> SessionConfig {
        SessionConfig {
            session_id: self.session_id,
            session_secret: None,
            session_token: None,
            session_start_time: chrono::Utc::now(),
        }
    }
}

// endregion