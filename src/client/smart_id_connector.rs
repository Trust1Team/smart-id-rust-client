use crate::models::common::{SemanticsIdentifier};
use crate::models::session::SessionStatus;
use anyhow::Result;
use tracing::{debug, info, instrument};
use crate::client::reqwest_generic::{get, post};
use crate::models::requests::{AuthenticationSessionRequest, CertificateRequest, SignatureSessionRequest};
use crate::models::responses::{AuthenticationSessionResponse, CertificateChoiceResponse, SignatureSessionResponse};
use crate::config::SmartIDConfig;
use crate::error::SmartIdClientError;
use crate::error::SmartIdClientError::SmartIdClientException;

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
}

impl Default for SmartIdConnector {
    fn default() -> Self {
        SmartIdConnector {
            cfg: SmartIDConfig::default(),
        }
    }
}

impl SmartIdConnector {
    #[instrument]
    pub async fn new_with_time_interval(cfg: SmartIDConfig) -> Self {
        SmartIdConnector {
            cfg,
            ..Default::default()
        }
    }

    #[instrument]
    pub async fn new(cfg: &SmartIDConfig) -> Self {
        SmartIdConnector {
            cfg: cfg.clone(),
            ..Default::default()
        }
    }

    /// Request long poll timeout value. If not provided, a default is used.
    /// This parameter is used for a long poll method, meaning the request method might not return until a timeout expires
    #[instrument]
    pub async fn get_session_status(&self, session_id: &str) -> Result<SessionStatus> {
        let path = format!("{}{}", self.cfg.url, path_session_status_uri(session_id.into()));
        debug!("smart_id_client::get_session_status: {}", path);
        match get::<SessionStatus>(path.as_str(), self.cfg.client_request_timeout).await {
            Ok(res) => {
                info!("smart_id_client::get_session_status::SESSION_STATUS: {:#?}", res.state);
                if res.state == "COMPLETE" {
                    Ok(res)
                } else {
                    Err(SmartIdClientError::SessionRetryException.into())
                }
            }
            Err(e) => {
                info!("smart_id_client::get_session_status::ERROR: {:#?}", e);
                Err(SmartIdClientError::SessionTimeoutException.into())
            }
        }
    }

    #[instrument]
    pub async fn get_certificate_by_document_number(&self, document_number: String, req: &CertificateRequest) -> Result<CertificateChoiceResponse> {
        let path = format!("{}{}", self.cfg.url, path_certificate_choice_by_document_number(document_number));
        debug!("smart_id_client::get_certificate_by_document_number: {}", path);
        debug!("smart_id_client::get_certificate_by_document_number::body {:#?}", serde_json::to_string(req));
        post::<CertificateRequest, CertificateChoiceResponse>(path.as_str(), req, self.cfg.client_request_timeout).await
    }

    #[instrument]
    pub async fn get_certificate_by_semantic_identifier(&self, id: SemanticsIdentifier, req: &CertificateRequest) -> Result<CertificateChoiceResponse> {
        let path = format!("{}{}", self.cfg.url, path_certificate_choice_by_natural_person_semantics_identifier(id.identifier));
        debug!("smart_id_client::get_certificate_by_semantic_identifier: {}", path);
        debug!("smart_id_client::get_certificate_by_semantic_identifier::body {:#?}", serde_json::to_string(req));
        post::<CertificateRequest, CertificateChoiceResponse>(path.as_str(), req, self.cfg.client_request_timeout).await
    }

    #[instrument]
    pub async fn authenticate_by_document_number(&self, document_number: String, req: &AuthenticationSessionRequest) -> Result<AuthenticationSessionResponse> {
        let path = format!("{}{}", self.cfg.url, path_authenticate_by_document_number(document_number));
        debug!("smart_id_client::authenticate_by_document_number: {}", path);
        debug!("smart_id_client::authenticate_by_document_number::body {:#?}", serde_json::to_string(req));
        post::<AuthenticationSessionRequest,AuthenticationSessionResponse>(path.as_str(), req, self.cfg.client_request_timeout).await
    }

    #[instrument]
    pub async fn authenticate_by_semantic_identifier(&self, id: SemanticsIdentifier, req: &AuthenticationSessionRequest) -> Result<AuthenticationSessionResponse> {
        let path = format!("{}{}", self.cfg.url, path_authenticate_by_natural_person_semantics_identifier(id.identifier));
        debug!("smart_id_client::authenticate_by_semantic_identifier: {}", path);
        debug!("smart_id_client::authenticate_by_document_number::body {:#?}", serde_json::to_string(req));
        post::<AuthenticationSessionRequest,AuthenticationSessionResponse>(path.as_str(), req, self.cfg.client_request_timeout).await
    }

    #[instrument]
    pub async fn sign_by_document_number(&self, document_number: String, req: &SignatureSessionRequest) -> Result<SignatureSessionResponse> {
        let path = format!("{}{}", self.cfg.url, path_signature_by_document_number(document_number));
        debug!("smart_id_client::sign_by_document_number: {}", path);
        debug!("smart_id_client::sign_by_document_number::body {:#?}", serde_json::to_string(req));
        post::<SignatureSessionRequest,SignatureSessionResponse>(path.as_str(), req, self.cfg.client_request_timeout).await
    }

    #[instrument]
    pub async fn sign_by_semantic_identifier(&self, id: SemanticsIdentifier, req: &SignatureSessionRequest) -> Result<SignatureSessionResponse> {
        let path = format!("{}{}", self.cfg.url, path_signature_by_natural_person_semantics_identifier(id.identifier));
        debug!("smart_id_client::sign_by_semantic_identifier: {}", path);
        debug!("smart_id_client::sign_by_semantic_identifier::body {:#?}", serde_json::to_string(req));
        post::<SignatureSessionRequest,SignatureSessionResponse>(path.as_str(), req, self.cfg.client_request_timeout).await
    }


}