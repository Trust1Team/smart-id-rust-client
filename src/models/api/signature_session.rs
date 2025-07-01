use crate::config::SmartIDConfig;
use crate::error::Result;
use crate::error::SmartIdClientError;
use crate::models::api::response::SmartIdAPIResponse;
use crate::models::common::{CertificateLevel, RequestProperties, VCCode};
use crate::models::interaction::{encode_interactions_base_64, hash_encode_digest, Interaction};
use crate::models::signature::{
    HashingAlgorithm, SignatureAlgorithm, SignatureProtocol, SignatureProtocolParameters,
    SignatureRequestAlgorithmParameters,
};
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

// region SignatureSessionDeviceLinkRequest

/// Signature Device Link Request
///
/// This struct represents a request for a signature session triggered by clicking on a link or scanning a qr code.
///
/// # Properties
///
/// * `relying_party_uuid` - The UUID of the relying party, provided by Smart ID.
/// * `relying_party_name` - The name of the relying party, provided by Smart ID.
/// * `initial_callback_url` - The initial callback URL for the signature session. This is used to redirect the user after the signature is completed.
/// * `certificate_level` - The level of the certificate required for the signature.
/// * `signature_protocol` - The protocol used for the signature.
/// * `signature_protocol_parameters` - The parameters for the signature protocol.
/// * `interactions` - A base64 encoded JSON string of interactions allowed during the signature session. At least one interaction is required. Interactions are limited based on the flow type, look at the Interaction documentation for more information.
/// * `nonce` - An optional nonce for the request.
/// * `request_properties` - Optional properties for the request.
/// * `capabilities` - Used only when agreed with Smart-ID provider. When omitted, request capabilities are derived from the `certificate_level` parameter.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::api::signature_session::SignatureDeviceLinkRequest;
/// use smart_id_rust_client::models::interaction::Interaction;
/// use smart_id_rust_client::models::signature::{HashingAlgorithm, SignatureAlgorithm};
/// use smart_id_rust_client::error::Result;
///
/// fn create_signature_request(cfg: &SmartIDConfig) -> Result<SignatureDeviceLinkRequest> {
///     let interactions = vec![Interaction::DisplayTextAndPIN {
///         display_text_60: "Sign document".to_string(),
///     }];
///     SignatureDeviceLinkRequest::new(
///         cfg,
///         interactions,
///         "base64-encoded-digest".to_string(),
///         SignatureAlgorithm::RsassaPss,
///         HashingAlgorithm::sha_256,
///         Some("https://example.com/callback".to_string()),
///     )
/// }
/// ```
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureDeviceLinkRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub initial_callback_url: Option<String>,
    pub certificate_level: CertificateLevel,
    pub signature_protocol: SignatureProtocol,
    pub signature_protocol_parameters: SignatureProtocolParameters,
    pub nonce: Option<String>,
    pub interactions: String,
    pub request_properties: Option<RequestProperties>,
    /// Used only when agreed with Smart-ID provider. When omitted request capabilities are derived from certificateLevel parameter.
    pub capabilities: Option<Vec<String>>,
}

impl SignatureDeviceLinkRequest {
    /// Creates a new `SignatureRequest`.
    ///
    /// # Arguments
    ///
    /// * `cfg` - The configuration for the Smart-ID service.
    /// * `interactions` - A vector of interactions allowed during the signature session. At least one interaction is required. Interactions are limited based on the flow type, look at the Interaction documentation for more information.
    /// * `digest` - The digest to be signed. Base64 encoded.
    /// * `signature_algorithm` - The algorithm used for the signature.
    /// * `hash_algorithm` - The hashing algorithm used for the signature.
    /// * `initial_callback_url` - An optional initial callback URL for the signature session. This is used to redirect the user after the signature is completed.
    ///
    /// # Errors
    ///
    /// Returns an error if no interactions are defined or if any interaction has invalid text length.
    pub fn new(
        cfg: &SmartIDConfig,
        interactions: Vec<Interaction>,
        digest: String,
        signature_algorithm: SignatureAlgorithm,
        hash_algorithm: HashingAlgorithm,
        initial_callback_url: Option<String>,
    ) -> Result<Self> {
        if interactions.is_empty() {
            return Err(SmartIdClientError::ConfigMissingException(
                "Define at least 1 interaction for an authentication request",
            ));
        };

        for interaction in &interactions {
            interaction.validate_text_length()?;
        }

        let encoded_interactions = encode_interactions_base_64(&interactions)?;

        let hashed_and_encoded_digest = hash_encode_digest(&digest, &hash_algorithm)?;

        Ok(SignatureDeviceLinkRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            initial_callback_url,
            certificate_level: CertificateLevel::QUALIFIED,
            signature_protocol: SignatureProtocol::RAW_DIGEST_SIGNATURE,
            signature_protocol_parameters: SignatureProtocolParameters::RAW_DIGEST_SIGNATURE {
                digest,
                signature_algorithm,
                signature_algorithm_parameters: SignatureRequestAlgorithmParameters {
                    hash_algorithm,
                },
            },
            nonce: None,
            interactions: encoded_interactions,
            request_properties: None,
            capabilities: None,
        })
    }
}

pub(crate) type SignatureDeviceLinkResponse = SmartIdAPIResponse<SignatureDeviceLinkSession>;

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureDeviceLinkSession {
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub session_secret: String,
    pub session_token: String,
    pub device_link_base: String,
}

// endregion: SignatureSessionDeviceLinkRequest

// region SignatureNotificationRequest

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
/// * `interactions` - A base64 encoded JSON string of interactions allowed during the signature session. At least one interaction is required. Interactions are limited based on the flow type, look at the Interaction documentation for more information.
/// * `nonce` - An optional nonce for the request.
/// * `request_properties` - Optional properties for the request.
/// * `capabilities` - Used only when agreed with Smart-ID provider. When omitted, request capabilities are derived from the `certificate_level` parameter.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::api::signature_session::SignatureNotificationRequest;
/// use smart_id_rust_client::models::interaction::Interaction;
/// use smart_id_rust_client::models::signature::{HashingAlgorithm, SignatureAlgorithm};
/// use smart_id_rust_client::error::Result;///
///
/// use smart_id_rust_client::models::common::SessionConfig::SignatureNotification;
///
/// fn create_signature_request(cfg: &SmartIDConfig) -> Result<SignatureNotificationRequest> {
///     let interactions = vec![Interaction::DisplayTextAndPIN {
///         display_text_60: "Sign document".to_string(),
///     }];
///     SignatureNotificationRequest::new(
///         cfg,
///         interactions,
///         "base64-encoded-digest".to_string(),
///         SignatureAlgorithm::RsassaPss,
///         HashingAlgorithm::sha_256,
///     )
/// }
/// ```
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureNotificationRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub certificate_level: CertificateLevel,
    pub signature_protocol: SignatureProtocol,
    pub signature_protocol_parameters: SignatureProtocolParameters,
    pub nonce: Option<String>,
    pub interactions: String,
    pub request_properties: Option<RequestProperties>,
    /// Used only when agreed with Smart-ID provider. When omitted request capabilities are derived from certificateLevel parameter.
    pub capabilities: Option<Vec<String>>,
}

impl SignatureNotificationRequest {
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
        hash_algorithm: HashingAlgorithm,
    ) -> Result<Self> {
        if interactions.is_empty() {
            return Err(SmartIdClientError::ConfigMissingException(
                "Define at least 1 interaction for an authentication request",
            ));
        };

        for interaction in &interactions {
            interaction.validate_text_length()?;
        }

        let encoded_interactions = encode_interactions_base_64(&interactions)?;

        let hashed_and_encoded_digest = hash_encode_digest(&digest, &hash_algorithm)?;

        Ok(SignatureNotificationRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            certificate_level: CertificateLevel::QUALIFIED,
            signature_protocol: SignatureProtocol::RAW_DIGEST_SIGNATURE,
            signature_protocol_parameters: SignatureProtocolParameters::RAW_DIGEST_SIGNATURE {
                digest: hashed_and_encoded_digest,
                signature_algorithm,
                signature_algorithm_parameters: SignatureRequestAlgorithmParameters {
                    hash_algorithm,
                },
            },
            nonce: None,
            interactions: encoded_interactions,
            request_properties: None,
            capabilities: None,
        })
    }
}

pub(crate) type SignatureNotificationResponse = SmartIdAPIResponse<SignatureNotificationSession>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureNotificationSession {
    #[serde(rename = "sessionID")]
    pub session_id: String,
    pub vc: VCCode,
}

// endregion: SignatureNotificationRequest

// region SignatureNotificationLinkedRequest

/// Signature Notification Linked Request
///
/// This struct represents a request for a signature session with the Smart ID service using a push notification that is linked to a previous certificate choice session (No verification code required).
///
/// # Properties
///
/// * `relying_party_uuid` - The UUID of the relying party, provided by Smart ID.
/// * `relying_party_name` - The name of the relying party, provided by Smart ID.
/// * `certificate_level` - The level of the certificate required for the signature.
/// * `signature_protocol` - The protocol used for the signature.
/// * `signature_protocol_parameters` - The parameters for the signature protocol.
/// * `linked_session_id` - The session ID of the linked certificate choice session.
/// * `interactions` - A base64 encoded JSON string of interactions allowed during the signature session. At least one interaction is required. Interactions are limited based on the flow type, look at the Interaction documentation for more information.
/// * `nonce` - An optional nonce for the request.
/// * `request_properties` - Optional properties for the request.
/// * `capabilities` - Used only when agreed with Smart-ID provider. When omitted, request capabilities are derived from the `certificate_level` parameter.
///
/// # Example
///
/// ```rust
/// use smart_id_rust_client::config::SmartIDConfig;
/// use smart_id_rust_client::models::api::signature_session::SignatureNotificationLinkedRequest;
/// use smart_id_rust_client::models::interaction::Interaction;
/// use smart_id_rust_client::models::signature::{HashingAlgorithm, SignatureAlgorithm};
/// use smart_id_rust_client::error::Result;
///
/// fn create_signature_request(cfg: &SmartIDConfig) -> Result<SignatureNotificationLinkedRequest> {
///     let interactions = vec![Interaction::DisplayTextAndPIN {
///         display_text_60: "Sign document".to_string(),
///     }];
///     SignatureNotificationLinkedRequest::new(
///         cfg,
///         interactions,
///         "base64-encoded-digest".to_string(),
///         SignatureAlgorithm::RsassaPss,
///         "56e1c1d0-dc07-4c71-890b-6200856b8c75".to_string(),
///         HashingAlgorithm::sha_256,
///     )
/// }
/// ```
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignatureNotificationLinkedRequest {
    #[serde(rename = "relyingPartyUUID")]
    pub relying_party_uuid: String,
    pub relying_party_name: String,
    pub certificate_level: CertificateLevel,
    pub signature_protocol: SignatureProtocol,
    pub signature_protocol_parameters: SignatureProtocolParameters,
    #[serde(rename = "linkedSessionID")]
    pub linked_session_id: String, // The session ID of the linked certificate choice session
    pub nonce: Option<String>,
    pub interactions: String, // Base64 encoded JSON of interactions
    pub request_properties: Option<RequestProperties>,
    /// Used only when agreed with Smart-ID provider. When omitted request capabilities are derived from certificateLevel parameter.
    pub capabilities: Option<Vec<String>>,
}

impl SignatureNotificationLinkedRequest {
    /// Creates a new `SignatureNotificationLinkedRequest`.
    ///
    /// # Arguments
    ///
    /// * `cfg` - The configuration for the Smart-ID service.
    /// * `interactions` - A vector of interactions allowed during the signature session. At least one interaction is required. Interactions are limited based on the flow type, look at the Interaction documentation for more information.
    /// * `digest` - The digest to be signed. Base64 encoded.
    /// * `signature_algorithm` - The algorithm used for the signature.
    /// * `linked_session_id` - The session ID of the linked certificate choice session.
    ///
    /// # Errors
    ///
    /// Returns an error if no interactions are defined or if any interaction has invalid text length.
    pub fn new(
        cfg: &SmartIDConfig,
        interactions: Vec<Interaction>,
        digest: String,
        signature_algorithm: SignatureAlgorithm,
        linked_session_id: String,
        hash_algorithm: HashingAlgorithm,
    ) -> Result<Self> {
        if interactions.is_empty() {
            return Err(SmartIdClientError::ConfigMissingException(
                "Define at least 1 interaction for an authentication request",
            ));
        };

        for interaction in &interactions {
            interaction.validate_text_length()?;
        }

        let encoded_interactions = encode_interactions_base_64(&interactions)?;

        let hashed_and_encoded_digest = hash_encode_digest(&digest, &hash_algorithm)?;

        Ok(SignatureNotificationLinkedRequest {
            relying_party_uuid: cfg.relying_party_uuid.clone(),
            relying_party_name: cfg.relying_party_name.clone(),
            linked_session_id,
            certificate_level: CertificateLevel::QUALIFIED,
            signature_protocol: SignatureProtocol::RAW_DIGEST_SIGNATURE,
            signature_protocol_parameters: SignatureProtocolParameters::RAW_DIGEST_SIGNATURE {
                digest: hashed_and_encoded_digest,
                signature_algorithm,
                signature_algorithm_parameters: SignatureRequestAlgorithmParameters {
                    hash_algorithm,
                },
            },
            nonce: None,
            interactions: encoded_interactions,
            request_properties: None,
            capabilities: None,
        })
    }
}

pub(crate) type SignatureNotificationLinkedResponse =
    SmartIdAPIResponse<SignatureNotificationLinkedSession>;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureNotificationLinkedSession {
    #[serde(rename = "sessionID")]
    pub session_id: String,
}

// endregion: SignatureNotificationLinkedRequest
