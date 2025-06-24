use crate::error::Result;
use crate::error::SmartIdClientError;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use strum_macros::AsRefStr;

/// Interaction Flow
///
/// This enum represents the different types of interaction flows that can be started on the user's device.
/// Each variant corresponds to a specific interaction type.
///
/// # Variants
///
/// * `DisplayTextAndPIN` - Displays a text message and prompts the user to enter a PIN.
/// * `ConfirmationMessage` - Displays a confirmation message with confirm and cancel buttons, then prompts the user to enter a pin.
/// * `VerificationCodeChoice` - Prompts the user to choose a verification code, then enter a pin.
/// * `ConfirmationMessageAndVerificationCodeChoice` - Displays a confirmation message and prompts the user to choose a verification code.
#[skip_serializing_none]
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Default, AsRefStr)]
#[serde(rename_all = "camelCase")]
#[strum(serialize_all = "camelCase")]
#[non_exhaustive]
pub enum InteractionFlow {
    #[default]
    DisplayTextAndPIN,
    ConfirmationMessage,
    VerificationCodeChoice,
    ConfirmationMessageAndVerificationCodeChoice,
}

/// Represents different types of interactions that can be started on the users device
///
/// There are limitations on which interactions can be used with which request types.
/// For device link flows, the following interactions are allowed:
/// - DisplayTextAndPIN with display_text_60
/// - ConfirmationMessage with display_text_200
///
/// For notificaiton flows, the following interactions are allowed:
/// - VerificationCodeChoice with display_text_60
/// - ConfirmationMessageAndVerificationCodeChoice with display_text_200
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
#[non_exhaustive]
pub enum Interaction {
    #[serde(rename_all = "camelCase")]
    DisplayTextAndPIN { display_text_60: String },
    #[serde(rename_all = "camelCase")]
    ConfirmationMessage { display_text_200: String },
    #[serde(rename_all = "camelCase")]
    VerificationCodeChoice { display_text_60: String },
    #[serde(rename_all = "camelCase")]
    ConfirmationMessageAndVerificationCodeChoice { display_text_200: String },
}

impl Interaction {
    pub fn validate_text_length(&self) -> Result<()> {
        match self {
            Interaction::DisplayTextAndPIN { display_text_60 } => {
                if display_text_60.len() > 60 {
                    return Err(SmartIdClientError::InvalidInteractionParametersException(
                        "Display text must be 60 characters or less",
                    ));
                }
            }
            Interaction::ConfirmationMessage { display_text_200 } => {
                if display_text_200.len() > 200 {
                    return Err(SmartIdClientError::InvalidInteractionParametersException(
                        "Display text must be 200 characters or less",
                    ));
                }
            }
            Interaction::VerificationCodeChoice { display_text_60 } => {
                if display_text_60.len() > 60 {
                    return Err(SmartIdClientError::InvalidInteractionParametersException(
                        "Display text must be 60 characters or less",
                    ));
                }
            }
            Interaction::ConfirmationMessageAndVerificationCodeChoice { display_text_200 } => {
                if display_text_200.len() > 200 {
                    return Err(SmartIdClientError::InvalidInteractionParametersException(
                        "Display text must be 200 characters or less",
                    ));
                }
            }
        }
        Ok(())
    }
}

/// Pulled from https://sk-eid.github.io/smart-id-documentation/rp-api/interactions.html
pub fn encode_interactions_base_64(interactions: &Vec<Interaction>) -> Result<String> {
    let interactions_json = serde_json::to_string(&interactions)
        .map_err(|e| SmartIdClientError::SerializationError(e.to_string()))?;
    let base64_encoded =
        base64::engine::general_purpose::STANDARD.encode(interactions_json.as_bytes());
    Ok(base64_encoded)
}

// region: Interaction Tests
#[cfg(test)]
mod interaction_tests {
    use super::*;
    use serde_json;
    use tracing_test::traced_test;

    #[traced_test]
    #[tokio::test]
    async fn test_serializing_display_text_and_pin() {
        let interaction = Interaction::DisplayTextAndPIN {
            display_text_60: "Hello, World!".to_string(),
        };
        let serialized = serde_json::to_string(&interaction).unwrap();
        assert_eq!(
            serialized,
            "{\"type\":\"displayTextAndPIN\",\"displayText60\":\"Hello, World!\"}"
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_text_length_display_text_and_pin() {
        let valid_interaction = Interaction::DisplayTextAndPIN {
            display_text_60: "Valid text".to_string(),
        };
        assert!(valid_interaction.validate_text_length().is_ok());

        let invalid_interaction = Interaction::DisplayTextAndPIN {
            display_text_60: "This text is way too long and should cause an error because it exceeds the 60 character limit.".to_string(),
        };
        assert!(invalid_interaction.validate_text_length().is_err());
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_text_length_confirmation_message() {
        let valid_interaction = Interaction::ConfirmationMessage {
            display_text_200: "Valid text".to_string(),
        };
        assert!(valid_interaction.validate_text_length().is_ok());

        let invalid_interaction = Interaction::ConfirmationMessage {
            display_text_200: "This text is way too long and should cause an error because it exceeds the 200 character limit. This text is way too long and should cause an error because it exceeds the 200 character limit. This text is way too long and should cause an error because it exceeds the 200 character limit.".to_string(),
        };
        assert!(invalid_interaction.validate_text_length().is_err());
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_text_length_verification_code_choice() {
        let valid_interaction = Interaction::VerificationCodeChoice {
            display_text_60: "Valid text".to_string(),
        };
        assert!(valid_interaction.validate_text_length().is_ok());

        let invalid_interaction = Interaction::VerificationCodeChoice {
            display_text_60: "This text is way too long and should cause an error because it exceeds the 60 character limit.".to_string(),
        };
        assert!(invalid_interaction.validate_text_length().is_err());
    }

    #[traced_test]
    #[tokio::test]
    async fn test_validate_text_length_confirmation_message_and_verification_code_choice() {
        let valid_interaction = Interaction::ConfirmationMessageAndVerificationCodeChoice {
            display_text_200: "Valid text".to_string(),
        };
        assert!(valid_interaction.validate_text_length().is_ok());

        let invalid_interaction = Interaction::ConfirmationMessageAndVerificationCodeChoice {
            display_text_200: "This text is way too long and should cause an error because it exceeds the 200 character limit. This text is way too long and should cause an error because it exceeds the 200 character limit. This text is way too long and should cause an error because it exceeds the 200 character limit.".to_string(),
        };
        assert!(invalid_interaction.validate_text_length().is_err());
    }

    // Based on the examples provided in https://sk-eid.github.io/smart-id-documentation/rp-api/interactions.html
    #[traced_test]
    #[tokio::test]
    async fn test_confirmation_interaction_base64_encoding() {
        let interaction = Interaction::ConfirmationMessage {
            display_text_200: "Longer description of the transaction context".to_string(),
        };
        let encoded = encode_interactions_base_64(&vec![interaction]).unwrap();
        assert_eq!(encoded, "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IkxvbmdlciBkZXNjcmlwdGlvbiBvZiB0aGUgdHJhbnNhY3Rpb24gY29udGV4dCJ9XQ==");
    }

    // Based on the examples provided in https://sk-eid.github.io/smart-id-documentation/rp-api/interactions.html
    #[traced_test]
    #[tokio::test]
    async fn test_display_text_and_pin_base64_encoding() {
        let interaction = Interaction::DisplayTextAndPIN {
            display_text_60: "Log in to mobile banking app".to_string(),
        };
        let encoded = encode_interactions_base_64(&vec![interaction]).unwrap();
        assert_eq!(encoded, "W3sidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6IkxvZyBpbiB0byBtb2JpbGUgYmFua2luZyBhcHAifV0=");
    }

    // Based on the examples provided in https://sk-eid.github.io/smart-id-documentation/rp-api/interactions.html
    #[traced_test]
    #[tokio::test]
    async fn test_multi_interaction_base64_encoding() {
        let interactions = vec![
            Interaction::ConfirmationMessage {
                display_text_200: "Longer description of the transaction context".to_string(),
            },
            Interaction::DisplayTextAndPIN {
                display_text_60: "Short description of the transaction context".to_string(),
            },
        ];
        let encoded = encode_interactions_base_64(&interactions).unwrap();
        assert_eq!(encoded, "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IkxvbmdlciBkZXNjcmlwdGlvbiBvZiB0aGUgdHJhbnNhY3Rpb24gY29udGV4dCJ9LHsidHlwZSI6ImRpc3BsYXlUZXh0QW5kUElOIiwiZGlzcGxheVRleHQ2MCI6IlNob3J0IGRlc2NyaXB0aW9uIG9mIHRoZSB0cmFuc2FjdGlvbiBjb250ZXh0In1d");
    }
}

// endregion: Device Link Tests
