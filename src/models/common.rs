use crate::error::Result;
use crate::error::SmartIdClientError;
use crate::models::authentication_session::{
    AuthenticationDynamicLinkSession, AuthenticationNotificationSession, AuthenticationRequest,
};
use crate::models::certificate_choice_session::{
    CertificateChoiceRequest, CertificateChoiceSession,
};
use crate::models::session_status::SessionStatus;
use crate::models::signature::{ResponseSignature, SignatureProtocol};
use crate::models::signature_session::{
    SignatureNotificationSession, SignatureRequest, SignatureSession,
};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

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
    AuthenticationDynamicLink {
        session_id: String,
        session_secret: String,
        session_token: String,
        random_challenge: String,
        requested_certificate_level: CertificateLevel,
        session_start_time: DateTime<Utc>,
    },
    Signature {
        session_id: String,
        session_secret: String,
        session_token: String,
        digest: String,
        requested_certificate_level: CertificateLevel,
        session_start_time: DateTime<Utc>,
    },
    AuthenticationNotification {
        session_id: String,
        random_challenge: String,
        requested_certificate_level: CertificateLevel,
        session_start_time: DateTime<Utc>,
        vc: VCCode,
    },
    SignatureNotification {
        session_id: String,
        digest: String,
        requested_certificate_level: CertificateLevel,
        session_start_time: DateTime<Utc>,
        vccode: VCCode,
    },
    CertificateChoice {
        session_id: String,
        requested_certificate_level: CertificateLevel,
        session_start_time: DateTime<Utc>,
    },
}

impl SessionConfig {
    pub fn session_id(&self) -> &String {
        match self {
            SessionConfig::AuthenticationDynamicLink { session_id, .. } => session_id,
            SessionConfig::Signature { session_id, .. } => session_id,
            SessionConfig::CertificateChoice { session_id, .. } => session_id,
            SessionConfig::AuthenticationNotification { session_id, .. } => session_id,
            SessionConfig::SignatureNotification { session_id, .. } => session_id,
        }
    }

    pub(crate) fn requested_certificate_level(&self) -> &CertificateLevel {
        match self {
            SessionConfig::AuthenticationDynamicLink {
                requested_certificate_level,
                ..
            } => requested_certificate_level,
            SessionConfig::Signature {
                requested_certificate_level,
                ..
            } => requested_certificate_level,
            SessionConfig::CertificateChoice {
                requested_certificate_level,
                ..
            } => requested_certificate_level,
            SessionConfig::AuthenticationNotification {
                requested_certificate_level,
                ..
            } => requested_certificate_level,
            SessionConfig::SignatureNotification {
                requested_certificate_level,
                ..
            } => requested_certificate_level,
        }
    }

    pub fn from_authentication_dynamic_link_response(
        authentication_response: AuthenticationDynamicLinkSession,
        authentication_request: AuthenticationRequest,
    ) -> Result<SessionConfig> {
        Ok(SessionConfig::AuthenticationDynamicLink {
            session_id: authentication_response.session_id,
            session_secret: authentication_response.session_secret,
            session_token: authentication_response.session_token,
            requested_certificate_level: authentication_request.certificate_level.into(),
            random_challenge: authentication_request
                .signature_protocol_parameters
                .get_random_challenge()
                .ok_or(SmartIdClientError::InvalidSignatureProtocal(
                    "Random challenge missing from authentication request",
                ))?,
            session_start_time: Utc::now(),
        })
    }

    pub fn from_authentication_notification_response(
        authentication_notification_response: AuthenticationNotificationSession,
        authentication_request: AuthenticationRequest,
    ) -> Result<SessionConfig> {
        Ok(SessionConfig::AuthenticationNotification {
            session_id: authentication_notification_response.session_id,
            vc: authentication_notification_response.vc,
            requested_certificate_level: authentication_request.certificate_level.into(),
            random_challenge: authentication_request
                .signature_protocol_parameters
                .get_random_challenge()
                .ok_or(SmartIdClientError::InvalidSignatureProtocal(
                    "Random challenge missing from authentication request",
                ))?,
            session_start_time: Utc::now(),
        })
    }

    pub fn from_signature_dynamic_link_request_response(
        signature_request_response: SignatureSession,
        signature_request: SignatureRequest,
    ) -> Result<SessionConfig> {
        Ok(SessionConfig::Signature {
            session_id: signature_request_response.session_id,
            session_secret: signature_request_response.session_secret,
            session_token: signature_request_response.session_token,
            digest: signature_request
                .signature_protocol_parameters
                .get_digest()
                .ok_or(SmartIdClientError::InvalidSignatureProtocal(
                    "Digest missing from signature request",
                ))?,
            requested_certificate_level: signature_request.certificate_level,
            session_start_time: Utc::now(),
        })
    }

    pub fn from_signature_notification_response(
        signature_notification_response: SignatureNotificationSession,
        signature_request: SignatureRequest,
    ) -> Result<SessionConfig> {
        Ok(SessionConfig::SignatureNotification {
            session_id: signature_notification_response.session_id,
            vccode: signature_notification_response.vc,
            requested_certificate_level: signature_request.certificate_level,
            session_start_time: Default::default(),
            digest: signature_request
                .signature_protocol_parameters
                .get_digest()
                .ok_or(SmartIdClientError::InvalidSignatureProtocal(
                    "Digest missing from signature request",
                ))?,
        })
    }

    pub fn from_certificate_choice_response(
        certificate_choice_response: CertificateChoiceSession,
        certificate_choice_request: CertificateChoiceRequest,
    ) -> SessionConfig {
        SessionConfig::CertificateChoice {
            session_id: certificate_choice_response.session_id,
            requested_certificate_level: certificate_choice_request.certificate_level,
            session_start_time: Utc::now(),
        }
    }

    pub fn get_digest(&self, session_status: SessionStatus) -> Option<String> {
        match self {
            SessionConfig::Signature { digest, .. } => Some(digest.clone()),
            SessionConfig::SignatureNotification { digest, .. } => Some(digest.clone()),
            SessionConfig::AuthenticationDynamicLink {
                random_challenge, ..
            } => {
                // The authentication digest requires the challenge and protocol which are available before the session is started
                // It also requires the server random which is only available after the session result is returned
                if let Some(ResponseSignature::ACSP_V1 { server_random, .. }) =
                    session_status.signature
                {
                    Some(format!(
                        "{:?};{};{}",
                        SignatureProtocol::ACSP_V1,
                        server_random,
                        random_challenge
                    ))
                } else {
                    // Authentication dynamic link can only be ACSP_V1, so this should never happen if the session is complete and successful
                    None
                }
            }
            SessionConfig::AuthenticationNotification {
                random_challenge, ..
            } => {
                // The authentication digest requires the challenge and protocol which are available before the session is started
                // It also requires the server random which is only available after the session result is returned
                if let Some(ResponseSignature::ACSP_V1 { server_random, .. }) =
                    session_status.signature
                {
                    Some(format!(
                        "{:?};{};{}",
                        SignatureProtocol::ACSP_V1,
                        server_random,
                        random_challenge
                    ))
                } else {
                    // Authentication notification can only be ACSP_V1, so this should never happen if the session is complete and successful
                    None
                }
            }
            SessionConfig::CertificateChoice { .. } => None, // Certificate choice does not have a digest
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
    alphaNumeric4,
}
