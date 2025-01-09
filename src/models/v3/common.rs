use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CertificateLevel {
    #[default]
    QUALIFIED,
    ADVANCED
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Default)]
#[skip_serializing_none]
#[serde(rename_all = "camelCase")]
pub enum InteractionFlow {
    #[default]
    DisplayTextAndPIN,
    ConfirmationMessage,
    VerificationCodeChoice,
    ConfirmationMessageAndVerificationCodeChoice,
}
