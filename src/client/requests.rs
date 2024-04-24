use serde::{Deserialize, Serialize};
use anyhow::Result;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationSessionRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: Option<String>,
    #[serde(rename = "relyingPartyName")]
    pub relying_party_name: Option<String>,
    #[serde(rename = "certificateLevel")]
    pub certificate_level: String,
    pub hash: Option<String>,
    #[serde(rename = "hashType")]
    pub hash_type: String,
    pub nonce: String,
    pub capabilities: Vec<String>,
    #[serde(rename = "allowedInteractionsOrder")]
    pub interaction_order: Vec<Interaction>,
    #[serde(rename = "requestProperties")]
    pub request_properties: RequestProperties,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Interaction {
    #[serde(rename = "type")]
    pub interaction_flow: Option<InteractionFlow>,
    pub display_text_60: Option<String>,
    pub display_text_200: Option<String>,
}

impl Interaction {
    pub fn new(interaction_flow: Option<InteractionFlow>, display_text_60: Option<String>, display_text_200: Option<String>) -> Self {
        Interaction {
            interaction_flow: interaction_flow,
            display_text_60,
            display_text_200,
        }
    }

    pub fn diplay_text_and_pin(&self, display_text_60: String) -> Self {
        Interaction {
            interaction_flow: Some(InteractionFlow::DISPLAY_TEXT_AND_PIN),
            display_text_60: Some(display_text_60),
            display_text_200: None,
        }
    }

    pub fn verification_code_choice(&self, display_text_60: String) -> Self {
        Interaction {
            interaction_flow: Some(InteractionFlow::VERIFICATION_CODE_CHOICE),
            display_text_60: Some(display_text_60),
            display_text_200: None,
        }
    }

    pub fn confirmation_message(&self, display_text_200: String) -> Self {
        Interaction {
            interaction_flow: Some(InteractionFlow::CONFIRMATION_MESSAGE),
            display_text_60: None,
            display_text_200: Some(display_text_200),
        }
    }

    pub fn confirmation_message_and_verification_code_choice(&self, display_text_200: String) -> Self {
        Interaction {
            interaction_flow: Some(InteractionFlow::CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE),
            display_text_60: None,
            display_text_200: Some(display_text_200),
        }
    }

    pub fn validate_display_text60(&self) -> Result<()> {
        match &self.interaction_flow {
            None => Ok(()),
            Some(inter_f) => {
                if inter_f.eq(&InteractionFlow::VERIFICATION_CODE_CHOICE) || inter_f.eq(&InteractionFlow::DISPLAY_TEXT_AND_PIN) {
                    let display_text_60 = self.display_text_60.clone();
                    let display_text_200 = self.display_text_200.clone();
                    if display_text_60.is_none() {
                        return Err(anyhow::anyhow!(format!("displayText60 cannot be null for AllowedInteractionOrder of type {}", inter_f.get_code())));
                    };
                    if display_text_60.is_some() && display_text_60.unwrap().clone().len() > 60 {
                        return Err(anyhow::anyhow!("displayText60 must not be longer than 60 characters"));
                    };
                    if display_text_200.is_some() {
                        return Err(anyhow::anyhow!(format!("displayText200 must be null for AllowedInteractionOrder of type {}", inter_f.get_code())));
                    };
                }
                Ok(())
            }
        }
    }

    pub fn validate_display_text200(&self) -> Result<()> {
        match &self.interaction_flow {
            None => Ok(()),
            Some(inter_f) => {
                if inter_f.eq(&InteractionFlow::CONFIRMATION_MESSAGE) || inter_f.eq(&InteractionFlow::CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE) {
                    let display_text_60 = self.display_text_60.clone();
                    let display_text_200 = self.display_text_200.clone();
                    if display_text_200.is_none() {
                        return Err(anyhow::anyhow!(format!("displayText200 cannot be null for AllowedInteractionOrder of type {}", inter_f.get_code())));
                    };
                    if display_text_200.is_some() && display_text_200.unwrap().clone().len() > 200 {
                        return Err(anyhow::anyhow!("displayText200 must not be longer than 200 characters"));
                    };
                    if display_text_60.is_some() {
                        return Err(anyhow::anyhow!(format!("displayText60 must be null for AllowedInteractionOrder of type {}", inter_f.get_code())));
                    };
                }
                Ok(())
            }
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RequestProperties {
    #[serde(rename = "shareMdClientIpAddress")]
    pub share_md_client_ip_address: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum InteractionFlow {
    DISPLAY_TEXT_AND_PIN,
    CONFIRMATION_MESSAGE,
    VERIFICATION_CODE_CHOICE,
    CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE,
}

impl InteractionFlow {
    pub fn get_code(&self) -> String {
        match self {
            InteractionFlow::DISPLAY_TEXT_AND_PIN => "displayTextAndPIN".to_string(),
            InteractionFlow::CONFIRMATION_MESSAGE => "confirmationMessage".to_string(),
            InteractionFlow::VERIFICATION_CODE_CHOICE => "verificationCodeChoice".to_string(),
            InteractionFlow::CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE => {
                "confirmationMessageAndVerificationCodeChoice".to_string()
            }
        }
    }
}

impl InteractionFlow {
    // transforms to Smart ID InteractionFlow 'code'
    fn as_str(&self) -> &'static str {
        match self {
            InteractionFlow::DISPLAY_TEXT_AND_PIN => "displayTextAndPIN",
            InteractionFlow::CONFIRMATION_MESSAGE => "confirmationMessage",
            InteractionFlow::VERIFICATION_CODE_CHOICE => "verificationCodeChoice",
            InteractionFlow::CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE => {
                "confirmationMessageAndVerificationCodeChoice"
            }
        }
    }
}

// region: Model testing
#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{error, info};
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
                assert_eq!(e.to_string(), "displayText60 cannot be null for AllowedInteractionOrder of type verificationCodeChoice");
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
                assert_eq!(e.to_string(), "displayText200 must be null for AllowedInteractionOrder of type verificationCodeChoice");
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
                assert_eq!(e.to_string(), "displayText60 cannot be null for AllowedInteractionOrder of type displayTextAndPIN");
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
                assert_eq!(e.to_string(), "displayText200 must be null for AllowedInteractionOrder of type displayTextAndPIN");
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
                assert_eq!(e.to_string(), "displayText200 cannot be null for AllowedInteractionOrder of type confirmationMessage");
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
                assert_eq!(e.to_string(), "displayText60 must be null for AllowedInteractionOrder of type confirmationMessage");
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
                assert_eq!(e.to_string(), "displayText200 cannot be null for AllowedInteractionOrder of type confirmationMessageAndVerificationCodeChoice");
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
                assert_eq!(e.to_string(), "displayText60 must be null for AllowedInteractionOrder of type confirmationMessageAndVerificationCodeChoice");
                assert!(true)
            }
        }
    }
}
// endregion: Model testing