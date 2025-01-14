use serde::{Deserialize, Serialize};
use crate::config::SmartIDConfig;
use crate::error::SmartIdClientError;
use crate::models::v2::requests::RequestProperties;
use crate::models::v3::common::CertificateLevel;
use crate::models::v3::interaction::Interaction;
use crate::models::v3::session_status::SignatureProtocol;
use crate::models::v3::signature::{SignatureAlgorithm, SignatureRequestParameters};

// region SignatureSessionRequest

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde_with::skip_serializing_none]
#[serde(rename_all = "camelCase")]
pub struct SignatureRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub certificate_level: CertificateLevel,
    pub signature_protocol: SignatureProtocol,
    pub signature_protocol_parameters: SignatureRequestParameters,
    pub allowed_interaction_order: Vec<Interaction>,
    pub nonce: Option<String>,
    pub request_properties: Option<RequestProperties>,
    pub capabilities: Option<Vec<String>>,
}

impl SignatureRequest {
    pub async fn new(cfg: &SmartIDConfig, interactions: Vec<Interaction>, digest: String, signature_algorithm: SignatureAlgorithm) -> anyhow::Result<Self> {
        /// At least one interaction is needed for every authentication request
        if interactions.len() == 0 {
            return Err(SmartIdClientError::ConfigMissingException("Define at least 1 interaction for an authentication request").into());
        };

        Ok(SignatureRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            certificate_level: CertificateLevel::QUALIFIED,
            signature_protocol: SignatureProtocol::RAW_DIGEST_SIGNATURE,
            signature_protocol_parameters: SignatureRequestParameters::RAW_DIGEST_SIGNATURE {
                digest,
                signature_algorithm,
            },
            nonce: None,
            allowed_interaction_order: interactions,
            request_properties: None,
            capabilities: None,
        })
    }
}

// endregion

// region SignatureSessionResponse

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureRequestResponse {
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub session_secret: String,
    pub session_token: String,
}

// endregion