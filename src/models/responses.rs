use serde::{Deserialize, Serialize};
use crate::models::session::{SessionCertificate, SessionResult, SessionSignature};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationSessionResponse {
    #[serde(rename = "sessionID")]
    pub session_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignatureSessionResponse {
    #[serde(rename = "sessionID")]
    pub session_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CertificateChoiceResponse {
    #[serde(rename = "sessionID")]
    pub session_id: String,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionStatusResponse {
    pub state: String,
    pub result: Option<SessionResult>,
    pub signature: Option<SessionSignature>,
    pub cert: Option<SessionCertificate>,
    #[serde(rename = "ignoredProperties")]
    pub ignored_properties: Vec<String>,
    #[serde(rename = "interactionFlowUsed")]
    pub interaction_flow_used: String,
    #[serde(rename = "deviceIpAddress")]
    pub device_ip_address: String,
}