use serde::{Deserialize, Serialize};
use anyhow::Result;
use crate::models::v2::common::{HashType, Interaction};
use crate::config::SmartIDConfig;
use crate::error::SmartIdClientError;
use crate::models::v2::common::CertificateLevel;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationSessionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "relyingPartyName")]
    pub relying_party_name: Option<String>,
    #[serde(rename = "certificateLevel")]
    pub certificate_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "hashType")]
    pub hash_type: Option<HashType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "allowedInteractionsOrder")]
    pub interaction_order: Option<Vec<Interaction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "requestProperties")]
    pub request_properties: Option<RequestProperties>,
}

impl AuthenticationSessionRequest {
    pub async fn new(cfg: &SmartIDConfig, interactions: Vec<Interaction>, hash: impl Into<String>, hash_type: HashType) -> Result<Self> {
        // At least one interaction is needed for every authentication request
        if interactions.is_empty() {
            return Err(SmartIdClientError::ConfigMissingException("Define at least 1 interaction for an authentication request").into());
        };

        Ok(AuthenticationSessionRequest {
            relying_party_uuid: Some(cfg.relying_party_uuid.clone()),
            relying_party_name: Some(cfg.relying_party_name.clone()),
            certificate_level: CertificateLevel::QUALIFIED.into(),
            interaction_order: Some(interactions),
            hash: Some(hash.into()),
            hash_type: Some(hash_type),
            ..Self::default()
        })
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde_with::skip_serializing_none]
pub struct SignatureSessionRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "relyingPartyName")]
    pub relying_party_name: Option<String>,
    #[serde(rename = "certificateLevel")]
    pub certificate_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "hashType")]
    pub hash_type: Option<HashType>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "allowedInteractionsOrder")]
    pub interaction_order: Option<Vec<Interaction>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "requestProperties")]
    pub request_properties: Option<RequestProperties>,
}

impl SignatureSessionRequest {
    pub async fn new(cfg: &SmartIDConfig, interactions: Vec<Interaction>, hash: impl Into<String>, hash_type: HashType) -> Result<Self> {
        // At least one interaction is needed for every authentication request
        if interactions.is_empty() {
            return Err(SmartIdClientError::ConfigMissingException("Define at least 1 interaction for an authentication request").into());
        };

        Ok(SignatureSessionRequest {
            relying_party_uuid: Some(cfg.relying_party_uuid.clone()),
            relying_party_name: Some(cfg.relying_party_name.clone()),
            certificate_level: CertificateLevel::QUALIFIED.into(),
            interaction_order: Some(interactions),
            hash: Some(hash.into()),
            hash_type: Some(hash_type),
            ..Self::default()
        })
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde_with::skip_serializing_none]
pub struct CertificateRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: Option<String>,
    #[serde(rename = "relyingPartyName")]
    pub relying_party_name: Option<String>,
    #[serde(rename = "certificateLevel")]
    pub certificate_level: String,
    pub nonce: Option<String>,
    #[serde(rename = "capabilities")]
    pub capabilities: Option<Vec<String>>, //todo not sure as Set is generic interface
    #[serde(rename = "requestProperties")]
    pub request_properties: Option<RequestProperties>,
}

impl CertificateRequest {
    pub async fn new(cfg: &SmartIDConfig) -> Self {
        CertificateRequest {
            relying_party_uuid: Some(cfg.relying_party_uuid.clone()),
            relying_party_name: Some(cfg.relying_party_name.clone()),
            certificate_level: CertificateLevel::QUALIFIED.into(),
            ..Self::default()
        }
    }

    pub async fn new_with_level(cfg: &SmartIDConfig, level: CertificateLevel) -> Self {
        CertificateRequest {
            relying_party_uuid: Some(cfg.relying_party_uuid.clone()),
            relying_party_name: Some(cfg.relying_party_name.clone()),
            certificate_level: level.into(),
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionStatusRequest {
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "responseSocketOpenTimeUnit")]
    pub request_socket_open_time_value: String,
    #[serde(rename = "responseSocketOpenTimeValue")]
    pub response_socket_open_time_value: i64,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestProperties {
    pub share_md_client_ip_address: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum InteractionFlow {
    DISPLAY_TEXT_AND_PIN,
    CONFIRMATION_MESSAGE,
    VERIFICATION_CODE_CHOICE,
    CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE,
}

impl From<String> for InteractionFlow {
    fn from(s: String) -> Self {
        match s.as_str() {
            "displayTextAndPIN" => InteractionFlow::DISPLAY_TEXT_AND_PIN,
            "confirmationMessage" => InteractionFlow::CONFIRMATION_MESSAGE,
            "verificationCodeChoice" => InteractionFlow::VERIFICATION_CODE_CHOICE,
            "confirmationMessageAndVerificationCodeChoice" => InteractionFlow::CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE,
            _ => InteractionFlow::DISPLAY_TEXT_AND_PIN
        }
    }
}

impl From<InteractionFlow> for String {
    fn from(val: InteractionFlow) -> Self {
        match val {
            InteractionFlow::DISPLAY_TEXT_AND_PIN => "displayTextAndPIN".to_string(),
            InteractionFlow::CONFIRMATION_MESSAGE => "confirmationMessage".to_string(),
            InteractionFlow::VERIFICATION_CODE_CHOICE => "verificationCodeChoice".to_string(),
            InteractionFlow::CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE => "confirmationMessageAndVerificationCodeChoice".to_string(),
        }
    }
}

// region: Model testing
#[cfg(test)]
mod tests {
    use super::*;
    use tracing_test::traced_test;

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_60_none() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::VERIFICATION_CODE_CHOICE),
            None,
            None
        );

        match inter_flow.validate_display_text60() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText60 cannot be null for AllowedInteractionOrder of type VERIFICATION_CODE_CHOICE");
                assert!(true)
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_60_too_long() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::VERIFICATION_CODE_CHOICE),
            Some("0123456789012345678901234567890123456789012345678901234567890".to_string()),
            None
        );

        match inter_flow.validate_display_text60() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText60 must not be longer than 60 characters");
                assert!(true)
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_60_with_200() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::VERIFICATION_CODE_CHOICE),
            Some("012345678901234567890123456789012345678901234567890123456789".to_string()),
            Some("something".to_string())
        );

        match inter_flow.validate_display_text60() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText200 must be null for AllowedInteractionOrder of type VERIFICATION_CODE_CHOICE");
                assert!(true)
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_60_none_diplay_text() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::DISPLAY_TEXT_AND_PIN),
            None,
            None
        );

        match inter_flow.validate_display_text60() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText60 cannot be null for AllowedInteractionOrder of type DISPLAY_TEXT_AND_PIN");
                assert!(true)
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_60_too_long_diplay_text() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::DISPLAY_TEXT_AND_PIN),
            Some("0123456789012345678901234567890123456789012345678901234567890".to_string()),
            None
        );

        match inter_flow.validate_display_text60() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText60 must not be longer than 60 characters");
                assert!(true)
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_60_with_200_diplay_text() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::DISPLAY_TEXT_AND_PIN),
            Some("012345678901234567890123456789012345678901234567890123456789".to_string()),
            Some("something".to_string())
        );

        match inter_flow.validate_display_text60() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText200 must be null for AllowedInteractionOrder of type DISPLAY_TEXT_AND_PIN");
                assert!(true)
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_200_none() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::CONFIRMATION_MESSAGE),
            None,
            None
        );

        match inter_flow.validate_display_text200() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText200 cannot be null for AllowedInteractionOrder of type CONFIRMATION_MESSAGE");
                assert!(true)
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_200_too_long() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::CONFIRMATION_MESSAGE),
            None,
            Some("012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".to_string()),
        );

        match inter_flow.validate_display_text200() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText200 must not be longer than 200 characters");
                assert!(true)
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_200_with_60() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::CONFIRMATION_MESSAGE),
            Some("something".to_string()),
            Some("012345678901234567890123456789012345678901234567890123456789".to_string()),
        );

        match inter_flow.validate_display_text200() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText60 must be null for AllowedInteractionOrder of type CONFIRMATION_MESSAGE");
                assert!(true)
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_200_none_cm_and_vch() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE),
            None,
            None
        );

        match inter_flow.validate_display_text200() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText200 cannot be null for AllowedInteractionOrder of type CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE");
                assert!(true)
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_200_too_long_cm_and_vch() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE),
            None,
            Some("012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890".to_string()),
        );

        match inter_flow.validate_display_text200() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText200 must not be longer than 200 characters");
                assert!(true)
            }
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_interaction_flow_200_with_60_cm_and_vch() {
        let inter_flow = Interaction::new(
            Some(InteractionFlow::CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE),
            Some("something".to_string()),
            Some("012345678901234567890123456789012345678901234567890123456789".to_string()),
        );

        match inter_flow.validate_display_text200() {
            Ok(_) => assert!(false), //must fail
            Err(e) => {
                assert_eq!(e.to_string(), "displayText60 must be null for AllowedInteractionOrder of type CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE");
                assert!(true)
            }
        }
    }
}
// endregion: Model testing