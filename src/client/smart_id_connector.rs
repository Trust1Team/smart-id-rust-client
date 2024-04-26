use time_unit::TimeUnit;
use crate::models::common::{SemanticsIdentifier};
use crate::models::session::SessionStatus;
use anyhow::Result;
use tracing::debug;
use tracing::log::info;
use crate::client::reqwest_generic::get;
use crate::models::requests::{CertificateRequest, SignatureSessionRequest};
use crate::models::responses::{AuthenticationSessionResponse, CertificateChoiceResponse, SignatureSessionResponse};
use crate::config::SmartIDConfig;

// region: Path definitions
const PATH_SESSION_STATUS_URI: &'static str = "/session";
const PATH_CERTIFICATE_CHOICE_BY_DOCUMENT_NUMBER: &'static str = "/certificatechoice/document";
const PATH_CERTIFICATE_CHOICE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER_PATH: &'static str = "/certificatechoice/etsi";
const SIGNATURE_BY_DOCUMENT_NUMBER_PATH: &'static str = "/signature/document";
const SIGNATURE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER_PATH: &'static str = "/signature/etsi";
const AUTHENTICATE_BY_DOCUMENT_NUMBER_PATH: &'static str = "/authentication/document";
const AUTHENTICATE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER_PATH: &'static str = "/authentication/etsi";

fn path_session_status_uri(session_id: String) -> String {
    format!("{}/{}", PATH_SESSION_STATUS_URI, session_id)
}

fn path_certificate_choice_by_document_number(document_number: String) -> String {
    format!("{}/{}", PATH_CERTIFICATE_CHOICE_BY_DOCUMENT_NUMBER, document_number)
}

fn path_certificate_choice_by_natural_person_semantics_identifier(semantic_identifier: String) -> String {
    format!("{}/{}", PATH_CERTIFICATE_CHOICE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER_PATH, semantic_identifier)
}

fn path_signature_by_document_number(document_number: String) -> String {
    format!("{}/{}", SIGNATURE_BY_DOCUMENT_NUMBER_PATH, document_number)
}

fn path_signature_by_natural_person_semantics_identifier(semantic_identifier: String) -> String {
    format!("{}/{}", SIGNATURE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER_PATH, semantic_identifier)
}

fn path_authenticate_by_document_number(document_number: String) -> String {
    format!("{}/{}", AUTHENTICATE_BY_DOCUMENT_NUMBER_PATH, document_number)
}

fn path_authenticate_by_natural_person_semantics_identifier(semantic_identifier: String) -> String {
    format!("{}/{}", AUTHENTICATE_BY_NATURAL_PERSON_SEMANTICS_IDENTIFIER_PATH, semantic_identifier)
}
// endregion: Path definitions

#[derive(Debug)]
pub struct SmartIdConnector {
    pub cfg: SmartIDConfig,
    pub session_status_response_socket_open_time_unit: TimeUnit,
    pub session_status_response_socket_open_time_value: i64,
}

impl Default for SmartIdConnector {
    fn default() -> Self {
        SmartIdConnector {
            cfg: SmartIDConfig::default(),
            session_status_response_socket_open_time_unit: TimeUnit::Seconds,
            session_status_response_socket_open_time_value: 30,
        }
    }
}

impl SmartIdConnector {
    pub async fn new_with_time_interval(cfg: SmartIDConfig, time_unit: TimeUnit, time_value: i64) -> Self {
        SmartIdConnector {
            cfg,
            session_status_response_socket_open_time_unit: time_unit,
            session_status_response_socket_open_time_value: time_value,
            ..Default::default()
        }
    }

    pub async fn new(cfg: SmartIDConfig) -> Self {
        SmartIdConnector {
            cfg,
            ..Default::default()
        }
    }

    pub async fn get_session_status(&self, session_id: impl Into<String>) -> Result<SessionStatus> {
        let path = path_session_status_uri(session_id.into());

        Ok(SessionStatus::default())
    }

    pub async fn get_certificate(&self, document_number: String) -> Result<CertificateChoiceResponse> {
        let path = format!("{}{}", self.cfg.url, path_certificate_choice_by_document_number(document_number));
        debug!("smart_id_client::get_certificate: {}", path);
        match get::<CertificateChoiceResponse>(path.as_str(), None, None).await {
            Ok(res) => Ok(res),
            Err(e) => Err(e),
        }
    }

    pub async fn get_certificate_by_semantic_identifier(&self, id: SemanticsIdentifier, req: CertificateRequest) -> Result<CertificateChoiceResponse> {
        todo!();
        Ok(CertificateChoiceResponse::default())
    }

    pub async fn sign(&self, document_number: String, req: SignatureSessionRequest) -> Result<SignatureSessionResponse> {
        todo!();
        Ok(SignatureSessionResponse::default())
    }

    pub async fn sign_by_semantic_identifier(&self, id: SemanticsIdentifier, req: SignatureSessionRequest) -> Result<SignatureSessionResponse> {
        todo!();
        Ok(SignatureSessionResponse::default())
    }

    pub async fn authenticate(&self, document_number: String, req: SignatureSessionRequest) -> Result<AuthenticationSessionResponse> {
        todo!();
        Ok(AuthenticationSessionResponse::default())
    }

    pub async fn authenticate_by_semantic_identifier(&self, id: SemanticsIdentifier, req: SignatureSessionRequest) -> Result<AuthenticationSessionResponse> {
        todo!();
        Ok(AuthenticationSessionResponse::default())
    }

    pub async fn set_session_status_response_socket_open_time(&self, session_status_res_socket_open_time_unit: TimeUnit, session_status_res_socket_open_time_value: i64) -> Result<()> {
        todo!();
        Ok(())
    }
}