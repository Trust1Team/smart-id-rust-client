use std::clone;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use crate::config::SmartIDConfig;
use crate::error::SmartIdClientError;
use crate::models::v3::common::{CertificateLevel, RequestProperties, SessionConfig};
use crate::models::v3::signature::{SignatureAlgorithm, SignatureRequestParameters};
use crate::models::v3::interaction::Interaction;
use anyhow::Result;
// region AuthenticationSessionRequest

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[skip_serializing_none]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub certificate_level: AuthenticationCertificateLevel,
    pub signature_protocol: AuthenticationSignatureProtocol,
    pub signature_protocol_parameters: SignatureRequestParameters,
    pub nonce: Option<String>,
    pub allowed_interactions_order: Vec<Interaction>,
    pub request_properties: Option<RequestProperties>,
    pub capabilities: Option<Vec<String>>,
}

impl AuthenticationRequest {
    pub async fn new(cfg: &SmartIDConfig, interactions: Vec<Interaction>, signature_algorithm: SignatureAlgorithm) -> Result<Self> {
        /// At least one interaction is needed for every authentication request
        if interactions.len() == 0 {
            return Err(SmartIdClientError::ConfigMissingException("Define at least 1 interaction for an authentication request").into());
        };

        for interaction in &interactions {
            interaction.validate_text_length()?;
        }

        Ok(AuthenticationRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            certificate_level: AuthenticationCertificateLevel::QUALIFIED,
            signature_protocol: AuthenticationSignatureProtocol::ACSP_V1,
            signature_protocol_parameters: SignatureRequestParameters::new_acsp_v1(signature_algorithm),
            nonce: None,
            allowed_interactions_order: interactions,
            request_properties: None,
            capabilities: None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum AuthenticationCertificateLevel {
    QUALIFIED,
    ADVANCED,
}

impl Into<CertificateLevel> for AuthenticationCertificateLevel {
    fn into(self) -> CertificateLevel {
        match self {
            AuthenticationCertificateLevel::QUALIFIED => CertificateLevel::QUALIFIED,
            AuthenticationCertificateLevel::ADVANCED => CertificateLevel::ADVANCED,
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuthenticationSignatureProtocol {
    ACSP_V1,
}

// endregion

// region AuthenticationSessionResponse
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationResponse {
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub session_secret: String,
    pub session_token: String,
}

// endregion