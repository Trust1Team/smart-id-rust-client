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

    pub fn validate_display_text60(&self) -> Result<()> {
        match &self.interaction_flow {
            None => Ok(()),
            Some(inter_f) => {
                if inter_f.eq(&InteractionFlow::VERIFICATION_CODE_CHOICE) {
                    if self.display_text_60.is_none() {
                        return Err(anyhow::anyhow!("displayText60 is required for VerificationCodeChoice"));
                    }
                }
                Ok(())
            }
        }
    }
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
                assert_eq!(e.to_string(), "displayText60 is required for VerificationCodeChoice");
                assert!(true)
            }
        }
    }
}