use crate::error::SmartIdClientError;
use crate::models::authentication_session::{AuthenticationRequest, AuthenticationResponse};
use crate::models::certificate_choice_session::{
    CertificateChoiceRequest, CertificateChoiceResponse,
};
use crate::models::signature_session::{SignatureRequest, SignatureRequestResponse};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

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

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SessionConfig {
    Authentication {
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
    CertificateChoice {
        session_id: String,
        requested_certificate_level: CertificateLevel,
        session_start_time: DateTime<Utc>,
    },
}

impl SessionConfig {
    pub fn session_id(&self) -> &String {
        match self {
            SessionConfig::Authentication { session_id, .. } => session_id,
            SessionConfig::Signature { session_id, .. } => session_id,
            SessionConfig::CertificateChoice { session_id, .. } => session_id,
        }
    }

    pub(crate) fn requested_certificate_level(&self) -> &CertificateLevel {
        match self {
            SessionConfig::Authentication {
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
        }
    }

    pub fn from_authentication_response(
        authentication_response: AuthenticationResponse,
        authentication_request: AuthenticationRequest,
    ) -> Result<SessionConfig> {
        Ok(SessionConfig::Authentication {
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

    pub fn from_signature_request_response(
        signature_request_response: SignatureRequestResponse,
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

    pub fn from_certificate_choice_response(
        certificate_choice_response: CertificateChoiceResponse,
        certificate_choice_request: CertificateChoiceRequest,
    ) -> SessionConfig {
        SessionConfig::CertificateChoice {
            session_id: certificate_choice_response.session_id,
            requested_certificate_level: certificate_choice_request.certificate_level,
            session_start_time: Utc::now(),
        }
    }
}
