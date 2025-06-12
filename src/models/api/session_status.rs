use crate::error::Result;
use crate::error::SmartIdClientError;
use crate::models::api::response::SmartIdAPIResponse;
use crate::models::common::CertificateLevel;
use crate::models::interaction::InteractionFlow;
use crate::models::signature::{ResponseSignature, SignatureProtocol};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

pub(crate) type SessionResponse = SmartIdAPIResponse<SessionStatusResponse>;

/// Session Status
///
/// This struct represents the status of a session with the Smart ID service.
/// It is returned from the Smart ID service session status endpoint.
///
/// # Properties
///
/// * `state` - The current state of the session, either `RUNNING` or `COMPLETE`.
/// * `result` - The result of the session, if available. result.endResult will be `OK` if the session was successful.
/// * `signature_protocol` - The protocol used for the signature, if available.
/// * `signature` - The signature response, if available.
/// * `cert` - The session certificate, if available. Contains the level of the certificate and the certificate value DER+Base64 encoded.
/// * `ignored_properties` - Any values from requestProperties that were unsupported or ignored.
/// * `interaction_type_used` - The interaction flow used during the session, if available.
/// * `device_ip_address` - The IP address of the mobile device, if it was requested using "shareMdClientIpAddress" in the session creation parameters.
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SessionStatusResponse {
    pub state: SessionState,
    pub result: Option<SessionResult>,
    pub signature_protocol: Option<SignatureProtocol>,
    pub signature: Option<ResponseSignature>,
    pub cert: Option<SessionCertificate>,
    pub ignored_properties: Option<Vec<String>>,
    pub interaction_type_used: Option<InteractionFlow>,
    pub device_ip_address: Option<String>,
}

/// Session Certificate
///
/// This struct represents the certificate used in a session with the Smart ID service.
/// During an auth flow a certificate that is non-repudiation capable is returned, for signing flows a certificate that is digital signature capable is returned.
///
/// # Properties
///
/// * `value` - The certificate value, DER+Base64 encoded. The certificate itself contains info on whether the certificate is QSCD-enabled, data which is not represented by certificate level.
/// * `certificate_level` - The level of the certificate.
#[skip_serializing_none]
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SessionCertificate {
    // Certificate value, DER+Base64 encoded. The certificate itself contains info on whether the certificate is QSCD-enabled, data which is not represented by certificate level.
    pub value: String,
    pub certificate_level: CertificateLevel,
}

/// Session Result
///
/// This struct represents the result of a session with the Smart ID service.
/// It is part of the session status response.
///
/// # Properties
///
/// * `end_result` - The end result of the session. OK for success, otherwise an error.
/// * `document_number` - The document number associated with the session, if available. Can be used in further signature and authentication requests.
#[skip_serializing_none]
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    // User refused on interaction screen, i.e. displayed text and PIN, or verification code choice.
    USER_REFUSED_INTERACTION,
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
    // Failure in executing the protocol
    PROTOCOL_FAILURE,
    // Generic server error
    SERVER_ERROR,
    #[default]
    UNKNOWN,
}

impl EndResult {
    pub fn is_ok(&self) -> Result<()> {
        match self {
            EndResult::OK => Ok(()),
            EndResult::USER_REFUSED => {
                Err(SmartIdClientError::UserRefusedVerificationChoiceException)
            }
            EndResult::TIMEOUT => Err(SmartIdClientError::SessionTimeoutException),
            EndResult::DOCUMENT_UNUSABLE => Err(SmartIdClientError::DocumentUnusableException),
            EndResult::WRONG_VC => {
                Err(SmartIdClientError::UserSelectedWrongVerificationCodeException)
            }
            EndResult::REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP => {
                Err(SmartIdClientError::RequiredInteractionNotSupportedByAppException)
            }
            EndResult::USER_REFUSED_CERT_CHOICE => {
                Err(SmartIdClientError::UserRefusedCertChoiceException)
            }
            EndResult::USER_REFUSED_DISPLAYTEXTANDPIN => {
                Err(SmartIdClientError::UserRefusedDisplayTextAndPinException)
            }
            EndResult::USER_REFUSED_VC_CHOICE => {
                Err(SmartIdClientError::UserRefusedVerificationChoiceException)
            }
            EndResult::USER_REFUSED_CONFIRMATIONMESSAGE => {
                Err(SmartIdClientError::UserRefusedConfirmationMessageException)
            }
            EndResult::USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE => Err(
                SmartIdClientError::UserRefusedConfirmationMessageWithVerificationChoiceException,
            ),
            EndResult::PROTOCOL_FAILURE => Err(SmartIdClientError::ProtocolFailureException),
            EndResult::SERVER_ERROR => Err(SmartIdClientError::ServerErrorException),
            EndResult::UNKNOWN | _ => Err(SmartIdClientError::SmartIdClientException(
                "Unknown session end result",
            )),
        }
    }
}

impl From<EndResult> for SmartIdClientError {
    fn from(val: EndResult) -> Self {
        match val {
            EndResult::USER_REFUSED => SmartIdClientError::UserRefusedVerificationChoiceException,
            EndResult::TIMEOUT => SmartIdClientError::SessionTimeoutException,
            EndResult::DOCUMENT_UNUSABLE => SmartIdClientError::DocumentUnusableException,
            EndResult::WRONG_VC => SmartIdClientError::UserSelectedWrongVerificationCodeException,
            EndResult::REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP => {
                SmartIdClientError::RequiredInteractionNotSupportedByAppException
            }
            EndResult::USER_REFUSED_CERT_CHOICE => {
                SmartIdClientError::UserRefusedCertChoiceException
            }
            EndResult::USER_REFUSED_DISPLAYTEXTANDPIN => {
                SmartIdClientError::UserRefusedDisplayTextAndPinException
            }
            EndResult::USER_REFUSED_VC_CHOICE => {
                SmartIdClientError::UserRefusedVerificationChoiceException
            }
            EndResult::USER_REFUSED_CONFIRMATIONMESSAGE => {
                SmartIdClientError::UserRefusedConfirmationMessageException
            }
            EndResult::USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE => {
                SmartIdClientError::UserRefusedConfirmationMessageWithVerificationChoiceException
            }
            _ => SmartIdClientError::SmartIdClientException("Unknown session end result"),
        }
    }
}
