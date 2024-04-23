use serde::{Deserialize, Serialize};
use serde_json::Value;

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
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Interaction {
    #[serde(rename = "type")]
    pub interaction_flow: String,
}

#[allow(non_camel_case_types)]
pub enum InteractionFlow {
    DISPLAY_TEXT_AND_PIN,
    CONFIRMATION_MESSAGE,
    VERIFICATION_CODE_CHOICE,
    CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE,
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
