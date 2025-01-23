use crate::config::SmartIDConfig;
use crate::models::common::{CertificateLevel, RequestProperties};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

// region CertificateChoiceSessionRequest

/// Certificate Choice Request
///
/// This struct represents a request for choosing a certificate with the Smart ID service.
/// It includes various parameters required for the certificate choice process.
///
/// # Properties
///
/// * `relying_party_uuid` - The UUID of the relying party, provided by Smart ID.
/// * `relying_party_name` - The name of the relying party, provided by Smart ID.
/// * `certificate_level` - The level of the certificate required for the request.
/// * `nonce` - An optional nonce for the request.
/// * `capabilities` - Used only when agreed with Smart-ID provider. When omitted request capabilities are derived from certificateLevel parameter.
/// * `request_properties` - Optional properties for the request.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::certificate_choice_session::CertificateChoiceRequest;
///
/// fn create_certificate_choice_request(cfg: &SmartIDConfig) -> CertificateChoiceRequest {
///     CertificateChoiceRequest::new(cfg)
/// }
/// ```
#[skip_serializing_none]
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateChoiceRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub certificate_level: CertificateLevel,
    pub nonce: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub request_properties: Option<RequestProperties>,
}

impl CertificateChoiceRequest {
    pub fn new(cfg: &SmartIDConfig) -> Self {
        CertificateChoiceRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            certificate_level: CertificateLevel::QUALIFIED,
            ..Self::default()
        }
    }
}

// endregion

// region CertificateChoiceSessionResponse

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateChoiceResponse {
    #[serde(rename = "sessionID")]
    pub session_id: String,
}

// endregion
