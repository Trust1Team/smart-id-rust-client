use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use crate::error::SmartIdClientError;
use crate::models::v3::interaction::InteractionFlow;
use crate::models::v3::signature::{SignatureProtocol, SignatureResponse};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[skip_serializing_none]
#[serde(rename_all = "camelCase")]
pub struct SessionStatus {
    pub state: SessionState,
    pub result: Option<SessionResult>,
    pub signature_protocol: Option<SignatureProtocol>,
    pub signature: Option<SignatureResponse>,
    pub cert: Option<SessionCertificate>,
    pub ignored_properties: Option<Vec<String>>,
    pub interaction_flow_used: Option<InteractionFlow>,
    // IP address of the mobile device. Is present only when it has been previously requested by the RelyingParty within the session creation parameters.
    pub device_ip_address: Option<String>,
}


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[skip_serializing_none]
#[serde(rename_all = "camelCase")]
pub struct SessionCertificate {
    // Certificate value, DER+Base64 encoded. The certificate itself contains info on whether the certificate is QSCD-enabled, data which is not represented by certificate level.
    pub value: String,
    pub certificate_level: SessionCertificateLevel,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone, Default)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum SessionCertificateLevel {
    #[default]
    QUALIFIED,
    ADVANCED
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[skip_serializing_none]
#[serde(rename_all = "camelCase")]
pub struct SessionResult {
    pub end_result: EndResult,
    pub document_number: Option<String>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub enum SessionState {
    #[default]
    RUNNING,
    COMPLETE,
}

#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum EndResult {
    // Session was completed successfully, there is a certificate, document number and possibly signature in return structure.
    OK,
    // User refused the session.
    USER_REFUSED,
    // There was a timeout, i.e. end user did not confirm or refuse the operation within given time frame.
    TIMEOUT,
    // For some reason, this RP request cannot be completed. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.
    DOCUMENT_UNUSABLE,
    // In case the multiple-choice verification code was requested, the user did not choose the correct verification code.
    WRONG_VC,
    // User app version does not support any of the allowedInteractionsOrder interactions.
    REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP,
    // User has multiple accounts and pressed Cancel on device choice screen on any device.
    USER_REFUSED_CERT_CHOICE,
    // User pressed Cancel on PIN screen. Can be from the most common displayTextAndPIN flow or from verificationCodeChoice flow when user chosen the right code and then pressed cancel on PIN screen.
    USER_REFUSED_DISPLAYTEXTANDPIN,
    // User cancelled verificationCodeChoice screen.
    USER_REFUSED_VC_CHOICE,
    // User cancelled on confirmationMessage screen.
    USER_REFUSED_CONFIRMATIONMESSAGE,
    // User cancelled on confirmationMessageAndVerificationCodeChoice screen.
    USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE,
    #[default]
    UNKNOWN,
}


impl From<EndResult> for SmartIdClientError {
    fn from(val: EndResult) -> Self {
        match val {
            EndResult::USER_REFUSED => SmartIdClientError::UserRefusedVerificationChoiceException,
            EndResult::TIMEOUT => SmartIdClientError::SessionTimeoutException,
            EndResult::DOCUMENT_UNUSABLE => SmartIdClientError::DocumentUnusableException,
            EndResult::WRONG_VC => SmartIdClientError::UserSelectedWrongVerificationCodeException,
            EndResult::REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP => SmartIdClientError::RequiredInteractionNotSupportedByAppException,
            EndResult::USER_REFUSED_CERT_CHOICE => SmartIdClientError::UserRefusedCertChoiceException,
            EndResult::USER_REFUSED_DISPLAYTEXTANDPIN => SmartIdClientError::UserRefusedDisplayTextAndPinException,
            EndResult::USER_REFUSED_VC_CHOICE => SmartIdClientError::UserRefusedVerificationChoiceException,
            EndResult::USER_REFUSED_CONFIRMATIONMESSAGE => SmartIdClientError::UserRefusedConfirmationMessageException,
            EndResult::USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE => SmartIdClientError::UserRefusedConfirmationMessageWithVerificationChoiceException,
            _ => SmartIdClientError::SmartIdClientException("Unknown session end result"),
        }
    }
}