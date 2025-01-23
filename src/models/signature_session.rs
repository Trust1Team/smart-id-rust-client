use crate::config::SmartIDConfig;
use crate::error::Result;
use crate::error::SmartIdClientError;
use crate::models::common::{CertificateLevel, RequestProperties, VCCode};
use crate::models::interaction::Interaction;
use crate::models::response::SmartIdAPIResponse;
use crate::models::signature::{SignatureAlgorithm, SignatureProtocol, SignatureRequestParameters};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

// region SignatureSessionRequest

/// Signature Request
///
/// This struct represents a request for a signature session with the Smart ID service.
/// It includes various parameters required for the signature process.
///
/// # Properties
///
/// * `relying_party_uuid` - The UUID of the relying party, provided by Smart ID.
/// * `relying_party_name` - The name of the relying party, provided by Smart ID.
/// * `certificate_level` - The level of the certificate required for the signature.
/// * `signature_protocol` - The protocol used for the signature.
/// * `signature_protocol_parameters` - The parameters for the signature protocol.
/// * `allowed_interactions_order` - A list of allowed interactions for the signature session, at least one is required.
/// * `nonce` - An optional nonce for the request.
/// * `request_properties` - Optional properties for the request.
/// * `capabilities` - Used only when agreed with Smart-ID provider. When omitted, request capabilities are derived from the `certificate_level` parameter.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::signature_session::SignatureRequest;
/// use smart_id_rust_client::models::interaction::Interaction;
/// use smart_id_rust_client::models::signature::SignatureAlgorithm;
/// use smart_id_rust_client::error::Result;
///
/// fn create_signature_request(cfg: &SmartIDConfig) -> Result<SignatureRequest> {
///     let interactions = vec![Interaction::DisplayTextAndPIN {
///         display_text_60: "Sign document".to_string(),
///     }];
///     SignatureRequest::new(
///         cfg,
///         interactions,
///         "base64-encoded-digest".to_string(),
///         SignatureAlgorithm::sha256WithRSAEncryption,
///     )
/// }
/// ```
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub certificate_level: CertificateLevel,
    pub signature_protocol: SignatureProtocol,
    pub signature_protocol_parameters: SignatureRequestParameters,
    pub allowed_interactions_order: Vec<Interaction>,
    pub nonce: Option<String>,
    pub request_properties: Option<RequestProperties>,
    /// Used only when agreed with Smart-ID provider. When omitted request capabilities are derived from certificateLevel parameter.
    pub capabilities: Option<Vec<String>>,
}

impl SignatureRequest {
    /// Creates a new `SignatureRequest`.
    ///
    /// # Arguments
    ///
    /// * `cfg` - The configuration for the Smart-ID service.
    /// * `interactions` - A vector of interactions allowed during the signature session. At least one interaction is required. Interactions are limited based on the flow type, look at the Interaction documentation for more information.
    /// * `digest` - The digest to be signed. Base64 encoded.
    /// * `signature_algorithm` - The algorithm used for the signature.
    ///
    /// # Errors
    ///
    /// Returns an error if no interactions are defined or if any interaction has invalid text length.
    pub fn new(
        cfg: &SmartIDConfig,
        interactions: Vec<Interaction>,
        digest: String,
        signature_algorithm: SignatureAlgorithm,
    ) -> Result<Self> {
        if interactions.is_empty() {
            return Err(SmartIdClientError::ConfigMissingException(
                "Define at least 1 interaction for an authentication request",
            )
            .into());
        };

        for interaction in &interactions {
            interaction.validate_text_length()?;
        }

        BASE64_STANDARD.decode(&digest).map_err(|_| {
            SmartIdClientError::InvalidDigestException("Digest not encoded in base64")
        })?;

        Ok(SignatureRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            certificate_level: CertificateLevel::QUALIFIED,
            signature_protocol: SignatureProtocol::RAW_DIGEST_SIGNATURE,
            signature_protocol_parameters: SignatureRequestParameters::RAW_DIGEST_SIGNATURE {
                digest,
                signature_algorithm,
            },
            nonce: None,
            allowed_interactions_order: interactions,
            request_properties: None,
            capabilities: None,
        })
    }
}

// endregion

// region SignatureSessionResponse

pub(crate) type SignatureResponse = SmartIdAPIResponse<SignatureSession>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureSession {
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub session_secret: String,
    pub session_token: String,
}

pub(crate) type SignatureNotificationResponse = SmartIdAPIResponse<SignatureNotificationSession>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureNotificationSession {
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub vc: VCCode,
}

// endregion
