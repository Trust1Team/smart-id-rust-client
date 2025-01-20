use crate::config::SmartIDConfig;
use crate::error::SmartIdClientError;
use crate::models::common::{CertificateLevel, RequestProperties};
use crate::models::interaction::Interaction;
use crate::models::signature::{SignatureAlgorithm, SignatureProtocol, SignatureRequestParameters};
use serde::{Deserialize, Serialize};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SmartIDConfig;
    use crate::models::common::CertificateLevel;
    use crate::models::interaction::Interaction;
    use crate::models::signature::{SignatureProtocol, SignatureRequestParameters};
    use crate::models::v3::interaction::Interaction;
    use crate::models::v3::signature::SignatureAlgorithm;
    use std::env;

    fn setup() {
        env::set_var("HOST_URL", "https://sid.demo.sk.ee/smart-id-rp/v3");
    }

    #[test]
    fn test_signature_request_new() {
        setup();
        let cfg = SmartIDConfig {
            relying_party_uuid: "test-uuid".to_string(),
            relying_party_name: "test-name".to_string(),
            ..Default::default()
        };
        let interactions = vec![Interaction::DisplayTextAndPIN {
            display_text_60: "Test interaction".to_string(),
        }];
        let digest = "test-digest".to_string();
        let signature_algorithm = SignatureAlgorithm::sha256WithRSAEncryption;

        let sig_request = SignatureRequest::new(
            &cfg,
            interactions.clone(),
            digest.clone(),
            signature_algorithm.clone(),
        );

        assert!(sig_request.is_ok(), "SignatureRequest::new should succeed");
        let sig_request = sig_request.unwrap();
        assert_eq!(sig_request.relying_party_uuid, "test-uuid");
        assert_eq!(sig_request.relying_party_name, "test-name");
        assert_eq!(sig_request.certificate_level, CertificateLevel::QUALIFIED);
        assert_eq!(
            sig_request.signature_protocol,
            SignatureProtocol::RAW_DIGEST_SIGNATURE
        );
        assert_eq!(
            sig_request.signature_protocol_parameters,
            SignatureRequestParameters::RAW_DIGEST_SIGNATURE {
                digest,
                signature_algorithm,
            }
        );
        assert_eq!(sig_request.allowed_interaction_order, interactions);
    }

    #[test]
    fn test_signature_request_validation_fail_with_no_interactions() {
        let cfg = SmartIDConfig {
            relying_party_uuid: "test-uuid".to_string(),
            relying_party_name: "test-name".to_string(),
            ..Default::default()
        };
        let interactions = vec![];
        let digest = "test-digest".to_string();
        let signature_algorithm = SignatureAlgorithm::sha256WithRSAEncryption;

        let sig_request = SignatureRequest::new(&cfg, interactions, digest, signature_algorithm);

        assert!(
            sig_request.is_err(),
            "SignatureRequest::new should fail with no interactions"
        );
    }
}
