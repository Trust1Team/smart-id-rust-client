use crate::config::SmartIDConfig;
use crate::error::Result;
use crate::error::SmartIdClientError;
use crate::models::common::{CertificateLevel, RequestProperties, VCCode};
use crate::models::interaction::Interaction;
use crate::models::response::SmartIdAPIResponse;
use crate::models::signature::{SignatureAlgorithm, SignatureRequestParameters};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
// region AuthenticationSessionRequest

/// Authentication Request
///
/// This struct represents a request for authentication with the Smart ID service.
/// It includes various parameters required for the authentication process.
///
/// # Properties
///
/// * `relying_party_uuid` - The UUID of the relying party, provided by Smart ID.
/// * `relying_party_name` - The name of the relying party, provided by Smart ID.
/// * `certificate_level` - The level of the certificate required for authentication.
/// * `signature_protocol` - The protocol used for the signature, currently only ACSP_V1 is supported.
/// * `signature_protocol_parameters` - The parameters for the signature protocol.
/// * `allowed_interactions_order` - A list of allowed interactions for the authentication, at least one is required.
/// * `request_properties` - Optional properties for the request.
/// * `capabilities` - Used only when agreed with Smart-ID provider. When omitted request capabilities are derived from certificateLevel parameter.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::error::Result;
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::authentication_session::{AuthenticationCertificateLevel, AuthenticationRequest};
/// use smart_id_rust_client::models::interaction::Interaction;
/// use smart_id_rust_client::models::signature::SignatureAlgorithm;
///
/// fn create_authentication_request(cfg: &SmartIDConfig) -> Result<AuthenticationRequest> {
///     let interactions = vec![Interaction::DisplayTextAndPIN {
///         display_text_60: "Authenticate to Application: Test".to_string(),
///     }];
///     AuthenticationRequest::new(
///         cfg,
///         interactions,
///         SignatureAlgorithm::sha256WithRSAEncryption,
///         AuthenticationCertificateLevel::QUALIFIED,
///     )
/// }
/// ```
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub certificate_level: AuthenticationCertificateLevel,
    pub signature_protocol: AuthenticationSignatureProtocol,
    pub signature_protocol_parameters: SignatureRequestParameters,
    pub allowed_interactions_order: Vec<Interaction>,
    pub request_properties: Option<RequestProperties>,
    pub capabilities: Option<Vec<String>>,
}

/// Creates a new `AuthenticationRequest`.
///
/// # Arguments
///
/// * `cfg` - The configuration for the Smart-ID service.
/// * `interactions` - A vector of interactions allowed during the authentication session. At least one interaction is required.
/// * `signature_algorithm` - The algorithm used for the signature.
/// * `authentication_certificate_level` - The level of the certificate required for authentication.
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
/// use smart_id_rust_client::models::authentication_session::{AuthenticationRequest, AuthenticationCertificateLevel};
/// use smart_id_rust_client::models::interaction::Interaction;
/// use smart_id_rust_client::models::signature::SignatureAlgorithm;
///
/// fn create_authentication_request(cfg: &SmartIDConfig) -> Result<AuthenticationRequest> {
///     let interactions = vec![Interaction::DisplayTextAndPIN {
///         display_text_60: "Authenticate to Application: Test".to_string(),
///     }];
///     AuthenticationRequest::new(
///         cfg,
///         interactions,
///         SignatureAlgorithm::sha256WithRSAEncryption,
///         AuthenticationCertificateLevel::QUALIFIED,
///     )
/// }
/// ```
impl AuthenticationRequest {
    pub fn new(
        cfg: &SmartIDConfig,
        interactions: Vec<Interaction>,
        signature_algorithm: SignatureAlgorithm,
        authentication_certificate_level: AuthenticationCertificateLevel,
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

        Ok(AuthenticationRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            certificate_level: authentication_certificate_level,
            signature_protocol: AuthenticationSignatureProtocol::ACSP_V1,
            signature_protocol_parameters: SignatureRequestParameters::new_acsp_v1(
                signature_algorithm,
            ),
            allowed_interactions_order: interactions,
            request_properties: None,
            capabilities: None,
        })
    }
}

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

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AuthenticationSignatureProtocol {
    ACSP_V1,
}

// endregion

// region AuthenticationSessionResponse

pub(crate) type AuthenticationDeviceLinkResponse =
    SmartIdAPIResponse<AuthenticationDeviceLinkSession>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticationDeviceLinkSession {
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub session_secret: String,
    pub session_token: String,
}

pub(crate) type AuthenticationNotificationResponse =
    SmartIdAPIResponse<AuthenticationNotificationSession>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthenticationNotificationSession {
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub vc: VCCode,
}

// endregion
