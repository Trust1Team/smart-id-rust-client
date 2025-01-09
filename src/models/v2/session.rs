use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionCertificate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "certificateLevel")]
    pub certificate_level: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionResult {
    #[serde(rename = "endResult")]
    pub end_result: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "documentNumber")]
    pub document_number: Option<String>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionSignature {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct SessionStatus {
    pub state: String,
    pub result: SessionResult,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SessionSignature>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert: Option<SessionCertificate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "ignoredProperties")]
    pub ignored_properties: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "interactionFlowUsed")]
    pub interaction_flow_used: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "deviceIpAddress")]
    pub device_ip_address: Option<String>,
}

