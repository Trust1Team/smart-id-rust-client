use crate::error::Result;
use crate::error::SmartIdClientError;
use crate::models::api::authentication_session::{
    AuthenticationDeviceLinkRequest, AuthenticationDeviceLinkSession,
    AuthenticationNotificationRequest, AuthenticationNotificationSession,
};
use crate::models::api::certificate_choice_session::{
    CertificateChoiceDeviceLinkRequest, CertificateChoiceDeviceLinkSession,
    CertificateChoiceNotificationRequest, CertificateChoiceNotificationSession,
};
use crate::models::api::session_status::SessionStatusResponse;
use crate::models::api::signature_session::{
    SignatureDeviceLinkRequest, SignatureDeviceLinkSession, SignatureNotificationLinkedRequest,
    SignatureNotificationLinkedSession, SignatureNotificationRequest, SignatureNotificationSession,
};
use crate::models::signature::{
    ResponseSignature, SignatureAlgorithm, SignatureProtocol, SignatureProtocolParameters,
};
use base64::engine::general_purpose::STANDARD;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use strum_macros::{AsRefStr, Display, EnumString};
use tracing::error;

/// Request Properties
///
/// This struct represents the properties of a request to the Smart ID service.
/// Currently, it only includes one property, `share_md_client_ip_address`.
///
/// # Properties
///
/// * `share_md_client_ip_address` - A boolean flag indicating whether the RP API server should share the user's mobile device IP address with the RP. By default, it is set to false. The RP must have proper privilege to use this property. See section IP sharing for details.
#[non_exhaustive]
#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestProperties {
    /// Whether the RP API server should share user mobile device IP address with the RP. By default it is set to false. The RP must have proper privilege to use this property. See section IP sharing for details.
    pub share_md_client_ip_address: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum CertificateLevel {
    #[default]
    QUALIFIED,
    ADVANCED,
    QSCD,
}

impl CertificateLevel {
    fn rank(&self) -> u8 {
        match self {
            CertificateLevel::ADVANCED => 0,
            CertificateLevel::QUALIFIED => 1,
            CertificateLevel::QSCD => 2,
        }
    }
}

impl PartialOrd for CertificateLevel {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.rank().cmp(&other.rank()))
    }
}
impl Ord for CertificateLevel {
    fn cmp(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SessionConfig {
    AuthenticationDeviceLink {
        // Response values
        session_id: String,
        session_secret: String,
        session_token: String,
        device_link_base: String,

        // Request values
        scheme_name: SchemeName,
        relying_party_uuid: String,
        relying_party_name: String,
        initial_callback_url: Option<String>,
        certificate_level: CertificateLevel,
        signature_protocol: SignatureProtocol,
        signature_protocol_parameters: SignatureProtocolParameters,
        interactions: String,

        // Calculated values
        rp_challenge: String,
        session_start_time: DateTime<Utc>,
    },
    AuthenticationNotification {
        // Response values
        session_id: String,

        // Request values
        scheme_name: SchemeName,
        relying_party_uuid: String,
        relying_party_name: String,
        certificate_level: CertificateLevel,
        signature_protocol: SignatureProtocol,
        signature_protocol_parameters: SignatureProtocolParameters,
        interactions: String,
        vc_type: VCCodeType,

        // Calculated values
        rp_challenge: String,
        session_start_time: DateTime<Utc>,
    },
    SignatureDeviceLink {
        // Response values
        session_id: String,
        session_secret: String,
        session_token: String,
        device_link_base: String,

        // Request values
        scheme_name: SchemeName,
        relying_party_uuid: String,
        relying_party_name: String,
        initial_callback_url: Option<String>,
        certificate_level: CertificateLevel,
        signature_protocol: SignatureProtocol,
        signature_protocol_parameters: SignatureProtocolParameters,
        interactions: String,

        // Calculated values
        digest: String,
        session_start_time: DateTime<Utc>,
    },
    SignatureNotification {
        // Response values
        session_id: String,
        vc: VCCode,

        // Request values
        scheme_name: SchemeName,
        relying_party_uuid: String,
        relying_party_name: String,
        certificate_level: CertificateLevel,
        signature_protocol: SignatureProtocol,
        signature_protocol_parameters: SignatureProtocolParameters,
        interactions: String,

        // Calculated values
        digest: String,
        session_start_time: DateTime<Utc>,
    },
    SignatureNotificationLinked {
        // Response values
        session_id: String,

        // Request values
        scheme_name: SchemeName,
        relying_party_uuid: String,
        relying_party_name: String,
        certificate_level: CertificateLevel,
        signature_protocol: SignatureProtocol,
        signature_protocol_parameters: SignatureProtocolParameters,
        linked_session_id: String,
        interactions: String,

        // Calculated values
        digest: String,
        session_start_time: DateTime<Utc>,
    },
    CertificateChoiceDeviceLink {
        // Response values
        session_id: String,
        session_token: String,
        session_secret: String,
        device_link_base: String,

        // Request values
        scheme_name: SchemeName,
        relying_party_uuid: String,
        relying_party_name: String,
        initial_callback_url: Option<String>,
        certificate_level: CertificateLevel,

        // Calculated values
        session_start_time: DateTime<Utc>,
    },
    CertificateChoiceNotification {
        // Response values
        session_id: String,

        // Request values
        scheme_name: SchemeName,
        relying_party_uuid: String,
        relying_party_name: String,
        certificate_level: CertificateLevel,

        // Calculated values
        session_start_time: DateTime<Utc>,
    },
}

impl SessionConfig {
    pub fn session_id(&self) -> &String {
        match self {
            SessionConfig::AuthenticationDeviceLink { session_id, .. } => session_id,
            SessionConfig::AuthenticationNotification { session_id, .. } => session_id,
            SessionConfig::CertificateChoiceDeviceLink { session_id, .. } => session_id,
            SessionConfig::CertificateChoiceNotification { session_id, .. } => session_id,
            SessionConfig::SignatureDeviceLink { session_id, .. } => session_id,
            SessionConfig::SignatureNotification { session_id, .. } => session_id,
            SessionConfig::SignatureNotificationLinked { session_id, .. } => session_id,
        }
    }

    pub(crate) fn requested_certificate_level(&self) -> &CertificateLevel {
        match self {
            SessionConfig::AuthenticationDeviceLink {
                certificate_level, ..
            } => certificate_level,
            SessionConfig::AuthenticationNotification {
                certificate_level, ..
            } => certificate_level,
            SessionConfig::CertificateChoiceDeviceLink {
                certificate_level, ..
            } => certificate_level,
            SessionConfig::CertificateChoiceNotification {
                certificate_level, ..
            } => certificate_level,
            SessionConfig::SignatureDeviceLink {
                certificate_level, ..
            } => certificate_level,
            SessionConfig::SignatureNotification {
                certificate_level, ..
            } => certificate_level,
            SessionConfig::SignatureNotificationLinked {
                certificate_level, ..
            } => certificate_level,
        }
    }

    pub fn from_authentication_device_link_response(
        authentication_response: AuthenticationDeviceLinkSession,
        authentication_request: AuthenticationDeviceLinkRequest,
        scheme_name: &SchemeName,
    ) -> Result<SessionConfig> {
        Ok(SessionConfig::AuthenticationDeviceLink {
            scheme_name: scheme_name.clone(),
            session_id: authentication_response.session_id,
            session_secret: authentication_response.session_secret,
            session_token: authentication_response.session_token,
            device_link_base: authentication_response.device_link_base,
            relying_party_uuid: authentication_request.relying_party_uuid,
            relying_party_name: authentication_request.relying_party_name,
            initial_callback_url: authentication_request.initial_callback_url,
            certificate_level: authentication_request.certificate_level.into(),
            signature_protocol: authentication_request.signature_protocol,
            signature_protocol_parameters: authentication_request
                .signature_protocol_parameters
                .clone(),
            interactions: authentication_request.interactions,
            rp_challenge: authentication_request
                .signature_protocol_parameters
                .get_rp_challenge()
                .ok_or(SmartIdClientError::InvalidSignatureProtocal(
                    "RP challenge missing from authentication request",
                ))?,
            session_start_time: Utc::now(),
        })
    }

    pub fn from_authentication_notification_response(
        authentication_notification_response: AuthenticationNotificationSession,
        authentication_request: AuthenticationNotificationRequest,
        scheme_name: &SchemeName,
    ) -> Result<SessionConfig> {
        Ok(SessionConfig::AuthenticationNotification {
            scheme_name: scheme_name.clone(),
            session_id: authentication_notification_response.session_id,
            relying_party_uuid: authentication_request.relying_party_uuid,
            relying_party_name: authentication_request.relying_party_name,
            certificate_level: authentication_request.certificate_level.into(),
            signature_protocol: authentication_request.signature_protocol,
            signature_protocol_parameters: authentication_request
                .signature_protocol_parameters
                .clone(),
            interactions: authentication_request.interactions,
            vc_type: authentication_request.vc_type,
            rp_challenge: authentication_request
                .signature_protocol_parameters
                .get_rp_challenge()
                .ok_or(SmartIdClientError::InvalidSignatureProtocal(
                    "RP challenge missing from authentication request",
                ))?,
            session_start_time: Utc::now(),
        })
    }

    pub fn from_signature_device_link_request_response(
        signature_request_response: SignatureDeviceLinkSession,
        signature_request: SignatureDeviceLinkRequest,
        scheme_name: &SchemeName,
    ) -> Result<SessionConfig> {
        Ok(SessionConfig::SignatureDeviceLink {
            scheme_name: scheme_name.clone(),
            session_id: signature_request_response.session_id,
            session_secret: signature_request_response.session_secret,
            session_token: signature_request_response.session_token,
            device_link_base: signature_request_response.device_link_base,
            relying_party_uuid: signature_request.relying_party_uuid,
            relying_party_name: signature_request.relying_party_name,
            digest: signature_request
                .signature_protocol_parameters
                .get_digest()
                .ok_or(SmartIdClientError::InvalidSignatureProtocal(
                    "Digest missing from signature request",
                ))?,
            certificate_level: signature_request.certificate_level,
            signature_protocol: signature_request.signature_protocol,
            signature_protocol_parameters: signature_request.signature_protocol_parameters.clone(),
            session_start_time: Utc::now(),
            initial_callback_url: signature_request.initial_callback_url,
            interactions: signature_request.interactions,
        })
    }

    pub fn from_signature_notification_response(
        signature_notification_response: SignatureNotificationSession,
        signature_request: SignatureNotificationRequest,
        scheme_name: &SchemeName,
    ) -> Result<SessionConfig> {
        Ok(SessionConfig::SignatureNotification {
            scheme_name: scheme_name.clone(),
            session_id: signature_notification_response.session_id,
            relying_party_uuid: signature_request.relying_party_uuid,
            relying_party_name: signature_request.relying_party_name,
            digest: signature_request
                .signature_protocol_parameters
                .get_digest()
                .ok_or(SmartIdClientError::InvalidSignatureProtocal(
                    "Digest missing from signature request",
                ))?,
            certificate_level: signature_request.certificate_level,
            signature_protocol: signature_request.signature_protocol,
            signature_protocol_parameters: signature_request.signature_protocol_parameters.clone(),
            session_start_time: Utc::now(),
            interactions: signature_request.interactions,
            vc: signature_notification_response.vc,
        })
    }

    pub fn from_signature_notification_linked_response(
        signature_notification_response: SignatureNotificationLinkedSession,
        signature_request: SignatureNotificationLinkedRequest,
        scheme_name: &SchemeName,
    ) -> Result<SessionConfig> {
        Ok(SessionConfig::SignatureNotificationLinked {
            scheme_name: scheme_name.clone(),
            session_id: signature_notification_response.session_id,
            relying_party_uuid: signature_request.relying_party_uuid,
            relying_party_name: signature_request.relying_party_name,
            certificate_level: signature_request.certificate_level,
            signature_protocol: signature_request.signature_protocol,
            signature_protocol_parameters: signature_request.signature_protocol_parameters.clone(),
            linked_session_id: signature_request.linked_session_id,
            session_start_time: Utc::now(),
            digest: signature_request
                .signature_protocol_parameters
                .get_digest()
                .ok_or(SmartIdClientError::InvalidSignatureProtocal(
                    "Digest missing from signature request",
                ))?,
            interactions: "".to_string(),
        })
    }

    pub fn from_certificate_choice_device_link_response(
        certificate_choice_response: CertificateChoiceDeviceLinkSession,
        certificate_choice_request: CertificateChoiceDeviceLinkRequest,
        scheme_name: &SchemeName,
    ) -> SessionConfig {
        SessionConfig::CertificateChoiceDeviceLink {
            scheme_name: scheme_name.clone(),
            session_id: certificate_choice_response.session_id,
            session_token: certificate_choice_response.session_token,
            session_secret: certificate_choice_response.session_secret,
            device_link_base: certificate_choice_response.device_link_base,
            relying_party_uuid: certificate_choice_request.relying_party_uuid,
            relying_party_name: certificate_choice_request.relying_party_name,
            initial_callback_url: certificate_choice_request.initial_callback_url,
            certificate_level: certificate_choice_request.certificate_level,
            session_start_time: Utc::now(),
        }
    }

    pub fn from_certificate_choice_notification_response(
        certificate_choice_response: CertificateChoiceNotificationSession,
        certificate_choice_request: CertificateChoiceNotificationRequest,
        scheme_name: &SchemeName,
    ) -> SessionConfig {
        SessionConfig::CertificateChoiceNotification {
            scheme_name: SchemeName::smart_id,
            session_id: certificate_choice_response.session_id,
            relying_party_uuid: certificate_choice_request.relying_party_uuid,
            relying_party_name: certificate_choice_request.relying_party_name,
            certificate_level: certificate_choice_request.certificate_level,
            session_start_time: Utc::now(),
        }
    }

    pub fn get_digest(&self, session_status: SessionStatusResponse) -> Option<String> {
        match self {
            SessionConfig::SignatureDeviceLink { digest, .. } => Some(digest.clone()),
            SessionConfig::SignatureNotification { digest, .. } => Some(digest.clone()),
            SessionConfig::SignatureNotificationLinked { digest, .. } => Some(digest.clone()),
            SessionConfig::AuthenticationDeviceLink {
                relying_party_name,

                interactions,
                rp_challenge,
                scheme_name,
                signature_protocol,
                signature_protocol_parameters,
                ..
            } => {
                // The authentication digest requires the challenge and protocol which are available before the session is started
                // It also requires the server random which is only available after the session result is returned

                let interaction_type_used = match session_status.interaction_type_used.clone() {
                    Some(interaction) => interaction,
                    None => {
                        error!("Session status does not contain interaction type used, defaulting to DisplayTextAndPIN");
                        return None;
                    }
                };

                if let Some(ResponseSignature::ACSP_V2 {
                    server_random,
                    user_challenge,
                    flow_type,
                    ..
                }) = session_status.signature
                {
                    let ascp_digest = SignatureAlgorithm::build_acsp_v2_digest(
                        scheme_name.clone(),
                        signature_protocol.clone(),
                        &server_random,
                        rp_challenge,
                        &user_challenge,
                        &BASE64_STANDARD.encode(relying_party_name),
                        "",
                        interactions,
                        interaction_type_used,
                        "",
                        flow_type.clone(),
                        signature_protocol_parameters.get_hashing_algorithm(),
                    );

                    Some(STANDARD.encode(ascp_digest))
                } else {
                    // Authentication device link can only be ACSP_V2, so this should never happen if the session is complete and successful
                    None
                }
            }
            SessionConfig::AuthenticationNotification {
                scheme_name,
                signature_protocol,
                signature_protocol_parameters,
                relying_party_name,
                interactions,
                rp_challenge,
                ..
            } => {
                // The authentication digest requires the challenge and protocol which are available before the session is started
                // It also requires the server random which is only available after the session result is returned
                let interaction_type_used = match session_status.interaction_type_used.clone() {
                    Some(interaction) => interaction,
                    None => {
                        error!("Session status does not contain interaction type used, defaulting to DisplayTextAndPIN");
                        return None;
                    }
                };

                if let Some(ResponseSignature::ACSP_V2 {
                    server_random,
                    user_challenge,
                    flow_type,
                    ..
                }) = session_status.signature
                {
                    let ascp_digest = SignatureAlgorithm::build_acsp_v2_digest(
                        scheme_name.clone(),
                        signature_protocol.clone(),
                        &server_random,
                        rp_challenge,
                        &user_challenge,
                        &BASE64_STANDARD.encode(relying_party_name),
                        "",
                        interactions,
                        interaction_type_used,
                        "",
                        flow_type.clone(),
                        signature_protocol_parameters.get_hashing_algorithm(),
                    );

                    Some(STANDARD.encode(ascp_digest))
                } else {
                    // Authentication device link can only be ACSP_V2, so this should never happen if the session is complete and successful
                    None
                }
            }
            SessionConfig::CertificateChoiceDeviceLink { .. } => None, // Certificate choice does not have a digest
            SessionConfig::CertificateChoiceNotification { .. } => None, // Certificate choice does not have a digest
        }
    }

    // Calculate the VC code for notification-based authentication using the RP challenge.
    // Based on documentation https://sk-eid.github.io/smart-id-documentation/rp-api/notification_based_flows.html
    pub fn calculate_vc_code(&self) -> Result<VCCode> {
        match self {
            SessionConfig::AuthenticationNotification {
                vc_type,
                rp_challenge,
                ..
            } => {
                let rp_challenge_bytes = base64::engine::general_purpose::STANDARD
                    .decode(rp_challenge)
                    .map_err(|_| {
                        SmartIdClientError::InvalidSignatureProtocal("Invalid RP challenge")
                    })?;
                let sha256_hash = Sha256::digest(&rp_challenge_bytes);
                let result = (((sha256_hash[30] as u16) << 8) + (sha256_hash[31] as u16)) % 10000;
                let verification_code: String = format!("{:04}", result);

                Ok(VCCode {
                    vc_type: vc_type.clone(),
                    value: verification_code,
                })
            }
            _ => Err(SmartIdClientError::InvalidSignatureProtocal(
                "VC code can only be calculated for AuthenticationNotification session",
            )),
        }
    }
}

/// Represents a VC (Verification Code) used in the notification-based authentication session.
/// This code is displayed to the user in their Smart ID app.
///
/// # Fields
///
/// * `vc_type` - The type of the VC code. Currently, the only allowed type is `alphaNumeric4`.
/// * `value` - The value of the VC code.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct VCCode {
    #[serde(rename = "type")]
    pub vc_type: VCCodeType,
    pub value: String,
}

/// Enum representing the type of the VC code.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum VCCodeType {
    numeric4,
}

/// Enum representing the scheme (environment) name.
/// Refer to to the 'Environment' docs for more details https://sk-eid.github.io/smart-id-documentation/environments.html
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, AsRefStr, Display, EnumString)]
#[strum(serialize_all = "kebab-case")]
#[serde(rename_all = "kebab-case")]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum SchemeName {
    smart_id,
    smart_id_demo,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::signature::{HashingAlgorithm, SignatureRequestAlgorithmParameters};

    // Based on the example from the documentation, their example return value is incorrect though.
    // https://sk-eid.github.io/smart-id-documentation/rp-api/notification_based_flows.html
    #[test]
    fn test_verification_code_calculation() {
        let session_config = SessionConfig::AuthenticationNotification {
            scheme_name: SchemeName::smart_id,
            session_id: "test_session_id".to_string(),
            relying_party_uuid: "test_relying_party_uuid".to_string(),
            relying_party_name: "Test Relying Party".to_string(),
            certificate_level: CertificateLevel::QUALIFIED,
            signature_protocol: SignatureProtocol::ACSP_V2,
            signature_protocol_parameters: SignatureProtocolParameters::ACSP_V2 {
                rp_challenge: "GYS+yoah6emAcVDNIajwSs6UB/M95XrDxMzXBUkwQJ9YFDipXXzGpPc7raWcuc2+TEoRc7WvIZ/7dU/iRXenYg==".to_string(),
                signature_algorithm: SignatureAlgorithm::RsassaPss,
                signature_algorithm_parameters: SignatureRequestAlgorithmParameters {
                    hash_algorithm: HashingAlgorithm::sha_256,
                },
            },
            interactions: "Test interactions".to_string(),
            vc_type: VCCodeType::numeric4,
            rp_challenge: "dGVzdF9jaGFsbGVuZ2U=".to_string(), // Base64 encoded "test_challenge"
            session_start_time: Default::default(),
        };

        let vc_code = session_config.calculate_vc_code().unwrap();
        assert_eq!(vc_code.value, "9158"); // The example from the docs has an incorrect return value.
        assert_eq!(vc_code.vc_type, VCCodeType::numeric4);
    }
}
