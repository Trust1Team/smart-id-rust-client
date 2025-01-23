use crate::error::SmartIdClientError;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

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
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Default)]
#[serde(rename_all = "camelCase")]
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
/// For dynamic link flows, the following interactions are allowed:
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
    pub fn validate_text_length(&self) -> anyhow::Result<()> {
        match self {
            Interaction::DisplayTextAndPIN { display_text_60 } => {
                if display_text_60.len() > 60 {
                    return Err(SmartIdClientError::InvalidInteractionParametersException(
                        "Display text must be 60 characters or less",
                    )
                    .into());
                }
            }
            Interaction::ConfirmationMessage { display_text_200 } => {
                if display_text_200.len() > 200 {
                    return Err(SmartIdClientError::InvalidInteractionParametersException(
                        "Display text must be 200 characters or less",
                    )
                    .into());
                }
            }
            Interaction::VerificationCodeChoice { display_text_60 } => {
                if display_text_60.len() > 60 {
                    return Err(SmartIdClientError::InvalidInteractionParametersException(
                        "Display text must be 60 characters or less",
                    )
                    .into());
                }
            }
            Interaction::ConfirmationMessageAndVerificationCodeChoice { display_text_200 } => {
                if display_text_200.len() > 200 {
                    return Err(SmartIdClientError::InvalidInteractionParametersException(
                        "Display text must be 200 characters or less",
                    )
                    .into());
                }
            }
        }
        Ok(())
    }
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
}

// endregion: Dynamic Link Tests
