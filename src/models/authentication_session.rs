use crate::config::SmartIDConfig;
use crate::error::Result;
use crate::error::SmartIdClientError;
use crate::models::common::{CertificateLevel, RequestProperties, VCCodeType};
use crate::models::interaction::{encode_interactions_base_64, Interaction};
use crate::models::response::SmartIdAPIResponse;
use crate::models::signature::{
    HashingAlgorithm, SignatureAlgorithm, SignatureProtocol, SignatureProtocolParameters,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
// region AuthenticationDeviceLinkSessionRequest

/// Authentication Device Link Request
///
/// This struct represents a request for authentication using a device link or qr code with the Smart ID service.
/// It includes various parameters required for the authentication process.
///
/// # Properties
///
/// * `relying_party_uuid` - The UUID of the relying party, provided by Smart ID.
/// * `relying_party_name` - The name of the relying party, provided by Smart ID.
/// * `certificate_level` - The level of the certificate required for authentication.
/// * `signature_protocol` - The protocol used for the signature, currently only ACSP_V2 is supported.
/// * `signature_protocol_parameters` - The parameters for the signature protocol.
/// * `signature_algorithm_parameters` - The parameters for the signature algorithm.
/// * `interactions` - A vector of interactions allowed during the authentication session. At least one interaction is required.
/// * `request_properties` - Optional properties for the request.
/// * `capabilities` - Used only when agreed with Smart-ID provider. When omitted request capabilities are derived from certificateLevel parameter.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::error::Result;
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::authentication_session::{AuthenticationCertificateLevel, AuthenticationDeviceLinkRequest};
/// use smart_id_rust_client::models::interaction::Interaction;
/// use smart_id_rust_client::models::signature::{HashingAlgorithm, SignatureAlgorithm};
///
/// fn create_authentication_request(cfg: &SmartIDConfig) -> Result<AuthenticationDeviceLinkRequest> {
///     let interactions = vec![Interaction::DisplayTextAndPIN {
///         display_text_60: "Authenticate to Application: Test".to_string(),
///     }];
///     AuthenticationDeviceLinkRequest::new(
///         cfg,
///         interactions,
///         SignatureAlgorithm::RsassaPss,
///         AuthenticationCertificateLevel::QUALIFIED,
///        Some("https://example.com/callback".to_string()),
///        HashingAlgorithm::sha_256
///     )
/// }
/// ```
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationDeviceLinkRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub initial_callback_url: Option<String>,
    pub certificate_level: AuthenticationCertificateLevel,
    pub signature_protocol: SignatureProtocol,
    pub signature_protocol_parameters: SignatureProtocolParameters,
    pub interactions: String,
    pub request_properties: Option<RequestProperties>,
    pub capabilities: Option<Vec<String>>,
}

/// Creates a new `AuthenticationDeviceLinkRequest`.
///
/// # Arguments
///
/// * `cfg` - The configuration for the Smart-ID service.
/// * `interactions` - A vector of interactions allowed during the authentication session. At least one interaction is required.
/// * `signature_algorithm` - The algorithm used for the signature.
/// * `authentication_certificate_level` - The level of the certificate required for authentication.
/// * `initial_callback_url` - The initial callback URL for the authentication request, provided by Smart ID.
/// * `hash_algorithm` - The hashing algorithm used for the signature request.
///
/// # Errors
///
/// Returns an error if no interactions are defined or if any interaction has invalid text length.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::error::Result;
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::authentication_session::{AuthenticationDeviceLinkRequest, AuthenticationCertificateLevel};
/// use smart_id_rust_client::models::interaction::Interaction;
/// use smart_id_rust_client::models::signature::{HashingAlgorithm, SignatureAlgorithm};
///
/// fn create_authentication_request(cfg: &SmartIDConfig) -> Result<AuthenticationDeviceLinkRequest> {
///     let interactions = vec![Interaction::DisplayTextAndPIN {
///         display_text_60: "Authenticate to Application: Test".to_string(),
///     }];
///     AuthenticationDeviceLinkRequest::new(
///         cfg,
///         interactions,
///         SignatureAlgorithm::RsassaPss,
///         AuthenticationCertificateLevel::QUALIFIED,
///         Some("https://example.com/callback".to_string()),
///         HashingAlgorithm::sha_256
///     )
/// }
/// ```
impl AuthenticationDeviceLinkRequest {
    pub fn new(
        cfg: &SmartIDConfig,
        interactions: Vec<Interaction>,
        signature_algorithm: SignatureAlgorithm,
        authentication_certificate_level: AuthenticationCertificateLevel,
        initial_callback_url: Option<String>,
        hash_algorithm: HashingAlgorithm,
    ) -> Result<Self> {
        // At least one interaction is needed for every authentication request
        if interactions.is_empty() {
            return Err(SmartIdClientError::ConfigMissingException(
                "Define at least 1 interaction for an authentication request",
            ));
        };

        for interaction in &interactions {
            interaction.validate_text_length()?;
        }

        let encoded_interactions = encode_interactions_base_64(&interactions)?;

        Ok(AuthenticationDeviceLinkRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            initial_callback_url,
            certificate_level: authentication_certificate_level,

            signature_protocol: SignatureProtocol::ACSP_V2,
            signature_protocol_parameters: SignatureProtocolParameters::new_acsp_v2(
                signature_algorithm,
                hash_algorithm,
            ),
            interactions: encoded_interactions,
            request_properties: None,
            capabilities: None,
        })
    }
}

pub(crate) type AuthenticationDeviceLinkResponse =
    SmartIdAPIResponse<AuthenticationDeviceLinkSession>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationDeviceLinkSession {
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub session_secret: String,
    pub session_token: String,
    pub device_link_base: String,
}

// endregion AuthenticationDeviceLinkSessionRequest

// region AuthenticationNotificationRequest

/// Authentication Notification Request
///
/// This struct represents a request for authentication using a push notification with the Smart ID service.
/// It includes various parameters required for the authentication process.
///
/// # Properties
///
/// * `relying_party_uuid` - The UUID of the relying party, provided by Smart ID.
/// * `relying_party_name` - The name of the relying party, provided by Smart ID.
/// * `initial_callback_url` - The initial callback URL for the authentication request, provided by Smart ID.
/// * `certificate_level` - The level of the certificate required for authentication.
/// * `signature_protocol` - The protocol used for the signature, currently only ACSP_V2 is supported.
/// * `signature_protocol_parameters` - The parameters for the signature protocol.
/// * `signature_algorithm_parameters` - The parameters for the signature algorithm.
/// * `interactions` - A vector of interactions allowed during the authentication session. At least one interaction is required.
/// * `request_properties` - Optional properties for the request.
/// * `capabilities` - Used only when agreed with Smart-ID provider. When omitted request capabilities are derived from certificateLevel parameter.
/// * `vc_type` - The type of the verification code used in the authentication request. Always numeric right now.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::error::Result;
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::authentication_session::{AuthenticationCertificateLevel, AuthenticationNotificationRequest};
/// use smart_id_rust_client::models::interaction::Interaction;
/// use smart_id_rust_client::models::signature::{HashingAlgorithm, SignatureAlgorithm};
///
/// fn create_authentication_request(cfg: &SmartIDConfig) -> Result<AuthenticationNotificationRequest> {
///     let interactions = vec![Interaction::DisplayTextAndPIN {
///         display_text_60: "Authenticate to Application: Test".to_string(),
///     }];
///     AuthenticationNotificationRequest::new(
///         cfg,
///         interactions,
///         SignatureAlgorithm::RsassaPss,
///         AuthenticationCertificateLevel::QUALIFIED,
///         Some("https://example.com/callback".to_string()),
///         HashingAlgorithm::sha_256,
///     )
/// }
/// ```
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationNotificationRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub initial_callback_url: String,
    pub certificate_level: AuthenticationCertificateLevel,
    pub signature_protocol: SignatureProtocol,
    pub signature_protocol_parameters: SignatureProtocolParameters,
    pub interactions: String,
    pub request_properties: Option<RequestProperties>,
    pub capabilities: Option<Vec<String>>,
    pub vc_type: VCCodeType,
}

/// Creates a new `AuthenticationNotificationRequest`.
///
/// # Arguments
///
/// * `cfg` - The configuration for the Smart-ID service.
/// * `interactions` - A vector of interactions allowed during the authentication session. At least one interaction is required.
/// * `signature_algorithm` - The algorithm used for the signature.
/// * `authentication_certificate_level` - The level of the certificate required for authentication.
/// * `initial_callback_url` - The initial callback URL for the authentication request, provided by Smart ID.
/// * `hash_algorithm` - The hashing algorithm used for the signature request.
///
/// # Errors
///
/// Returns an error if no interactions are defined or if any interaction has invalid text length.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::error::Result;
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::authentication_session::{AuthenticationNotificationRequest, AuthenticationCertificateLevel};
/// use smart_id_rust_client::models::interaction::Interaction;
/// use smart_id_rust_client::models::signature::{HashingAlgorithm, SignatureAlgorithm};
///
/// fn create_authentication_request(cfg: &SmartIDConfig) -> Result<AuthenticationNotificationRequest> {
///     let interactions = vec![Interaction::DisplayTextAndPIN {
///         display_text_60: "Authenticate to Application: Test".to_string(),
///     }];
///     AuthenticationNotificationRequest::new(
///         cfg,
///         interactions,
///         SignatureAlgorithm::RsassaPss,
///         AuthenticationCertificateLevel::QUALIFIED,
///         Some("https://example.com/callback".to_string()),
///         HashingAlgorithm::sha_256
///     )
/// }
/// ```
impl AuthenticationNotificationRequest {
    pub fn new(
        cfg: &SmartIDConfig,
        interactions: Vec<Interaction>,
        signature_algorithm: SignatureAlgorithm,
        authentication_certificate_level: AuthenticationCertificateLevel,
        initial_callback_url: Option<String>,
        hash_algorithm: HashingAlgorithm,
    ) -> Result<Self> {
        // At least one interaction is needed for every authentication request
        if interactions.is_empty() {
            return Err(SmartIdClientError::ConfigMissingException(
                "Define at least 1 interaction for an authentication request",
            ));
        };

        for interaction in &interactions {
            interaction.validate_text_length()?;
        }

        let encoded_interactions = encode_interactions_base_64(&interactions)?;

        Ok(AuthenticationNotificationRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            initial_callback_url: initial_callback_url.unwrap_or("".to_string()),
            certificate_level: authentication_certificate_level,

            signature_protocol: SignatureProtocol::ACSP_V2,
            signature_protocol_parameters: SignatureProtocolParameters::new_acsp_v2(
                signature_algorithm,
                hash_algorithm,
            ),
            interactions: encoded_interactions,
            request_properties: None,
            capabilities: None,
            vc_type: VCCodeType::numeric4,
        })
    }
}

pub(crate) type AuthenticationNotificationResponse =
    SmartIdAPIResponse<AuthenticationNotificationSession>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticationNotificationSession {
    #[serde(rename = "sessionID")]
    pub session_id: String,
}

// endregion AuthenticationNotificationRequest

// region enums

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum AuthenticationCertificateLevel {
    QUALIFIED,
    ADVANCED,
}

impl From<AuthenticationCertificateLevel> for CertificateLevel {
    fn from(val: AuthenticationCertificateLevel) -> Self {
        match val {
            AuthenticationCertificateLevel::QUALIFIED => CertificateLevel::QUALIFIED,
            AuthenticationCertificateLevel::ADVANCED => CertificateLevel::ADVANCED,
        }
    }
}

// endregion enums
