use crate::config::SmartIDConfig;
use crate::error::SmartIdClientError;
use crate::models::common::{CertificateLevel, RequestProperties};
use crate::models::interaction::Interaction;
use crate::models::signature::{SignatureAlgorithm, SignatureProtocol, SignatureRequestParameters};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
// region SignatureSessionRequest

#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub certificate_level: CertificateLevel,
    pub signature_protocol: SignatureProtocol,
    pub signature_protocol_parameters: SignatureRequestParameters,
    pub allowed_interactions_order: Vec<Interaction>,
    pub nonce: Option<String>,
    pub request_properties: Option<RequestProperties>,
    pub capabilities: Option<Vec<String>>,
}

impl SignatureRequest {
    pub fn new(
        cfg: &SmartIDConfig,
        interactions: Vec<Interaction>,
        digest: String,
        signature_algorithm: SignatureAlgorithm,
    ) -> anyhow::Result<Self> {
        // At least one interaction is needed for every authentication request
        if interactions.is_empty() {
            return Err(SmartIdClientError::ConfigMissingException(
                "Define at least 1 interaction for an authentication request",
            )
            .into());
        };

        for interaction in &interactions {
            interaction.validate_text_length()?;
        }

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
            allowed_interactions_order: interactions,
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