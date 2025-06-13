use crate::config::SmartIDConfig;
use crate::models::api::response::SmartIdAPIResponse;
use crate::models::common::{CertificateLevel, RequestProperties};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

// region CertificateChoiceDeviceLinkSessionRequest

/// Certificate Choice Device link Request
///
/// This struct represents a request for choosing a certificate with the Smart ID service.
/// It includes various parameters required for the certificate choice process.
///
/// # Properties
///
/// * `relying_party_uuid` - The UUID of the relying party, provided by Smart ID.
/// * `relying_party_name` - The name of the relying party, provided by Smart ID.
/// * `initial_callback_url` - The initial callback URL for the request, used for device link flows (not required in QR flows).
/// * `certificate_level` - The level of the certificate required for the request.
/// * `nonce` - An optional nonce for the request.
/// * `capabilities` - Used only when agreed with Smart-ID provider. When omitted request capabilities are derived from certificateLevel parameter.
/// * `request_properties` - Optional properties for the request.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::api::certificate_choice_session::CertificateChoiceDeviceLinkRequest;
///
/// fn create_certificate_choice_request(cfg: &SmartIDConfig) -> CertificateChoiceDeviceLinkRequest {
///     CertificateChoiceDeviceLinkRequest::new(cfg)
/// }
/// ```
#[skip_serializing_none]
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateChoiceDeviceLinkRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub initial_callback_url: Option<String>,
    pub certificate_level: CertificateLevel,
    pub nonce: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub request_properties: Option<RequestProperties>,
}

impl CertificateChoiceDeviceLinkRequest {
    pub fn new(cfg: &SmartIDConfig) -> Self {
        CertificateChoiceDeviceLinkRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            certificate_level: CertificateLevel::QUALIFIED,
            ..Self::default()
        }
    }
}

#[allow(dead_code)]
pub(crate) type CertificateChoiceDeviceLinkResponse =
    SmartIdAPIResponse<CertificateChoiceDeviceLinkSession>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateChoiceDeviceLinkSession {
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub session_token: String,
    pub session_secret: String,
    pub device_link_base: String,
}

// endregion CertificateChoiceDeviceLinkSessionRequest

// region CertificateChoiceNotificationRequest

/// Certificate Choice Notification Request
///
/// This struct represents a request for choosing a certificate with the Smart ID service.
/// It includes various parameters required for the certificate choice process.
///
/// # Properties
///
/// * `relying_party_uuid` - The UUID of the relying party, provided by Smart ID.
/// * `relying_party_name` - The name of the relying party, provided by Smart ID.
/// * `initial_callback_url` - The initial callback URL for the request, used for device link flows (not be required in QR flows).
/// * `certificate_level` - The level of the certificate required for the request.
/// * `nonce` - An optional nonce for the request.
/// * `capabilities` - Used only when agreed with Smart-ID provider. When omitted request capabilities are derived from certificateLevel parameter.
/// * `request_properties` - Optional properties for the request.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::api::certificate_choice_session::CertificateChoiceDeviceLinkRequest;
///
/// fn create_certificate_choice_request(cfg: &SmartIDConfig) -> CertificateChoiceDeviceLinkRequest {
///     CertificateChoiceDeviceLinkRequest::new(cfg)
/// }
/// ```
#[skip_serializing_none]
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateChoiceNotificationRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub initial_callback_url: Option<String>,
    pub certificate_level: CertificateLevel,
    pub nonce: Option<String>,
    pub capabilities: Option<Vec<String>>,
    pub request_properties: Option<RequestProperties>,
}

impl CertificateChoiceNotificationRequest {
    pub fn new(cfg: &SmartIDConfig) -> Self {
        CertificateChoiceNotificationRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            certificate_level: CertificateLevel::QUALIFIED,
            ..Self::default()
        }
    }
}

pub(crate) type CertificateChoiceNotificationResponse =
    SmartIdAPIResponse<CertificateChoiceNotificationSession>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CertificateChoiceNotificationSession {
    #[serde(rename = "sessionID")]
    pub session_id: String,
}

// endregion CertificateChoiceNotificationRequest

// region SigningCertificateRequest

/// Request to fetch the signing certificate which has a specific document number.
///
/// # Properties
/// * `relying_party_uuid` - The UUID of the relying party, provided by Smart ID.
/// * `relying_party_name` - The name of the relying party, provided by Smart ID.
/// * `certificate_level` - The level of the certificate required for the request, either ADVANCED or QUALIFIED.
///
/// # Example
/// ```rust
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::api::certificate_choice_session::SigningCertificateRequest;use smart_id_rust_client::models::common::CertificateLevel;
/// fn create_signing_certificate_request(cfg: &SmartIDConfig) -> SigningCertificateRequest {
///    SigningCertificateRequest {
///        relying_party_uuid: cfg.relying_party_uuid.clone(),
///       relying_party_name: cfg.relying_party_name.clone(),
///       certificate_level: CertificateLevel::QUALIFIED,
///   }
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCertificateRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub certificate_level: CertificateLevel,
}

#[allow(dead_code)]
pub(crate) type SigningCertificateResponse = SmartIdAPIResponse<SigningCertificateResult>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCertificateResult {
    pub state: SigningCertificateResponseState,
    pub cert: SigningCertificate,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[allow(non_camel_case_types)]
pub enum SigningCertificateResponseState {
    OK,
    DOCUMENT_UNUSABLE,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SigningCertificate {
    pub value: String,                       // Base64 encoded DER certificate
    pub certificate_level: CertificateLevel, // ADVANCED or QUALIFIED only
}

// endregion: SigningCertificateRequest
