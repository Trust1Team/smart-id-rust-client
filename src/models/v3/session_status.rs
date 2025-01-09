use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use crate::models::v3::common::{CertificateLevel, InteractionFlow};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[skip_serializing_none]
#[serde(rename_all = "camelCase")]
pub struct SessionStatus {
    pub state: String,
    pub result: Option<SessionResult>,
    pub signature_protocol: Option<SignatureProtocol>,
    pub signature: Option<SessionSignature>,
    pub cert: Option<SessionCertificate>,
    pub ignored_properties: Option<Vec<String>>,
    pub interaction_flow_used: Option<InteractionFlow>,
    // IP address of the mobile device. Is present only when it has been previously requested by the RelyingParty within the session creation parameters.
    pub device_ip_address: Option<String>,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub enum SignatureProtocol {
    #[default]
    ACSP_V1,
    RAW_DIGEST_SIGNATURE,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SignatureAlgorithm {
    sha256WithRSAEncryption,
    sha384WithRSAEncryption,
    sha512WithRSAEncryption,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "signatureProtocol")]
pub enum SessionSignature {
    ACSP_V1 {
        value: String,
        // TODO: RP must validate that the value contains only valid Base64 characters, and that the length is not less than 24 characters.
        // A random value of 24 or more characters from Base64 alphabet, which is generated at RP API service side.
        // There are not any guarantees that the returned value length is the same in each call of the RP API.
        server_random: String,
        signature_algorithm: String,
    },
    RAW_DIGEST_SIGNATURE {
        value: String,
        signature_algorithm: String,
    },
}


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[skip_serializing_none]
#[serde(rename_all = "camelCase")]
pub struct SessionCertificate {
    // Certificate value, DER+Base64 encoded. The certificate itself contains info on whether the certificate is QSCD-enabled, data which is not represented by certificate level.
    pub value: String,
    pub certificate_level: CertificateLevel,
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
pub enum SessionState {
    #[default]
    RUNNING,
    COMPLETE,
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
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
