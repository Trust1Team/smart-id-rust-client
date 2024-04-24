use serde::{Deserialize, Serialize};

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