use crate::error::SmartIdClientError;
use crate::models::authentication_session::{AuthenticationRequest, AuthenticationResponse};
use crate::models::certificate_choice_session::{
    CertificateChoiceRequest, CertificateChoiceResponse,
};
use crate::models::signature_session::{SignatureRequest, SignatureRequestResponse};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestProperties {
    pub share_md_client_ip_address: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum CertificateLevel {
    #[default]
    QUALIFIED,
    ADVANCED,
    QSCD,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SessionConfig {
    Authentication {
        session_id: String,
        session_secret: String,
        session_token: String,
        random_challenge: String,
        certificate_level: CertificateLevel,
        session_start_time: DateTime<Utc>,
    },
    Signature {
        session_id: String,
        session_secret: String,
        session_token: String,
        digest: String,
        certificate_level: CertificateLevel,
        session_start_time: DateTime<Utc>,
    },
    CertificateChoice {
        session_id: String,
        certificate_level: CertificateLevel,
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

    pub fn from_authentication_response(
        authentication_response: AuthenticationResponse,
        authentication_request: AuthenticationRequest,
    ) -> Result<SessionConfig> {
        Ok(SessionConfig::Authentication {
            session_id: authentication_response.session_id,
            session_secret: authentication_response.session_secret,
            session_token: authentication_response.session_token,
            certificate_level: authentication_request.certificate_level.into(),
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
            certificate_level: signature_request.certificate_level,
            session_start_time: Utc::now(),
        })
    }

    pub fn from_certificate_choice_response(
        certificate_choice_response: CertificateChoiceResponse,
        certificate_choice_request: CertificateChoiceRequest,
    ) -> SessionConfig {
        SessionConfig::CertificateChoice {
            session_id: certificate_choice_response.session_id,
            certificate_level: certificate_choice_request.certificate_level,
            session_start_time: Utc::now(),
        }
    }
}
