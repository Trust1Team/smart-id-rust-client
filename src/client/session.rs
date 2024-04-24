use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionCertificate {
    pub value: String,
    pub certificate_level: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionResult {
    #[serde(rename = "endResult")]
    pub end_result: String,
    #[serde(rename = "documentNumber")]
    pub document_number: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSignature {
    pub algorithm: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionStatus {
    pub state: String,
    pub result: SessionResult,
    pub signature: SessionSignature,
    pub cert: SessionCertificate,
    #[serde(rename = "ignoredProperties")]
    pub ignored_properties: Vec<String>,
    #[serde(rename = "interactionFlowUsed")]
    pub interaction_flow_used: String,
    #[serde(rename = "deviceIpAddress")]
    pub device_ip_address: String,
}