use std::sync::{Arc, Mutex};
use crate::client::reqwest_generic::{get, post};
use crate::client::v2::smart_id_connector::SmartIdConnector;
use crate::common::SemanticsIdentifier;
use crate::config::SmartIDConfig;
use crate::error::SmartIdClientError;
use crate::error::SmartIdClientError::{NoSessionException, SmartIdClientException};
use crate::models::v3::common::SessionConfig;
use crate::models::v3::session_status::SessionStatus;
use anyhow::Result;
use tracing::{debug, info};
use crate::models::v3::authentication_session::{AuthenticationRequest, AuthenticationResponse};
use crate::models::v3::certificate_choice_session::{CertificateChoiceResponse, CertificateRequest};
use crate::models::v3::signature_session::{SignatureRequest, SignatureResponse};

// region: Path definitions
// Copied from https://github.com/SK-EID/smart-id-java-client/blob/81e48f519bf882db8584a344b161db378b959093/src/main/java/ee/sk/smartid/v3/rest/SmartIdRestConnector.java#L79
const SESSION_STATUS_URI: &'static str = "/session";
const NOTIFICATION_CERTIFICATE_CHOICE_WITH_SEMANTIC_IDENTIFIER_PATH: &'static str = "/certificatechoice/notification/etsi";
const NOTIFICATION_CERTIFICATE_CHOICE_WITH_DOCUMENT_NUMBER_PATH: &'static str = "/certificatechoice/notification/document";

const DYNAMIC_LINK_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH: &'static str = "/signature/dynamic-link/etsi";
const DYNAMIC_LINK_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH: &'static str = "/signature/dynamic-link/document";
const NOTIFICATION_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH: &'static str = "/signature/notification/etsi";
const NOTIFICATION_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH: &'static str = "/signature/notification/document";

const ANONYMOUS_DYNAMIC_LINK_AUTHENTICATION_PATH: &'static str = "/authentication/dynamic-link/anonymous";
const DYNAMIC_LINK_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH: &'static str = "/authentication/dynamic-link/etsi";
const DYNAMIC_LINK_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH: &'static str = "/authentication/dynamic-link/document";
const NOTIFICATION_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH: &'static str = "/authentication/notification/etsi";
const NOTIFICATION_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH: &'static str = "/authentication/notification/document";
// endregion: Path definitions

#[derive(Debug, Default)]
pub struct SmartIdClientV3 {
    pub cfg: SmartIDConfig,
    // This tracks session state and is used to make subsequent requests
    // For example to generate QR codes or to poll for session status
    pub(crate) session_config: Arc<Mutex<Option<SessionConfig>>>,
}

impl SmartIdClientV3 {
    pub async fn new(cfg: &SmartIDConfig) -> Self {
        SmartIdClientV3 {
            cfg: cfg.clone(),
            session_config: Arc::new(Mutex::new(None)),
        }
    }

    pub async fn get_session_status(&self, timeoutMs: i32) -> Result<SessionStatus> {
        let session_config = self.get_session()?;

        let path = format!(
            "{}{}/{}?timeoutMs={}",
            self.cfg.url,
            SESSION_STATUS_URI,
            session_config.session_id.clone(),
            timeoutMs
        );

        match get::<SessionStatus>(path.as_str(), self.cfg.client_request_timeout).await {
            Ok(res) => {
                debug!("Session status: {:#?}", res);
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

    // region: Authentication

    pub async fn start_authentication_dynamic_link_anonymous_session(&self, authentication_request: AuthenticationRequest) -> Result<()> {
        let path = format!(
            "{}{}",
            self.cfg.url,
            ANONYMOUS_DYNAMIC_LINK_AUTHENTICATION_PATH,
        );

        let session = post::<AuthenticationRequest, AuthenticationResponse>(path.as_str(), &authentication_request, self.cfg.client_request_timeout).await?;
        self.set_session(session.into())
    }

    pub async fn start_authentication_dynamic_link_document_session(&self, authentication_request: AuthenticationRequest, document_number: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            DYNAMIC_LINK_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let session = post::<AuthenticationRequest, AuthenticationResponse>(path.as_str(), &authentication_request, self.cfg.client_request_timeout).await?;
        self.set_session(session.into())
    }

    pub async fn start_authentication_dynamic_link_etsi_session(&self, authentication_request: AuthenticationRequest, etsi: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            DYNAMIC_LINK_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let session = post::<AuthenticationRequest, AuthenticationResponse>(path.as_str(), &authentication_request, self.cfg.client_request_timeout).await?;
        self.set_session(session.into())
    }

    pub async fn start_signature_dynamic_link_etis_session(&self, authentication_request: SignatureRequest, etsi: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            DYNAMIC_LINK_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let session = post::<SignatureRequest, SignatureResponse>(path.as_str(), &authentication_request, self.cfg.client_request_timeout).await?;
        self.set_session(session.into())
    }

    // endregion: Authentication

    // region: Signature

    pub async fn start_signature_dynamic_link_document_session(&self, authentication_request: SignatureRequest, document_number: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            DYNAMIC_LINK_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let session = post::<SignatureRequest, SignatureResponse>(path.as_str(), &authentication_request, self.cfg.client_request_timeout).await?;
        self.set_session(session.into())
    }

    // endregion: Signature

    // region: Certificate Choice

    pub async fn start_certificate_choice_notification_etsi_session(&self, certificate_request: CertificateRequest, etsi: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            NOTIFICATION_CERTIFICATE_CHOICE_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi.to_string(),
        );

        let session = post::<CertificateRequest, CertificateChoiceResponse>(path.as_str(), &certificate_request, self.cfg.client_request_timeout).await?;
        self.set_session(session.into())
    }

    pub async fn start_certificate_choice_notification_document_session(&self, certificate_request: CertificateRequest, document_number: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            NOTIFICATION_CERTIFICATE_CHOICE_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let session = post::<CertificateRequest, CertificateChoiceResponse>(path.as_str(), &certificate_request, self.cfg.client_request_timeout).await?;
        self.set_session(session.into())
    }

    // endregion

    fn get_session(&self) -> Result<SessionConfig> {
        match self.session_config.lock() {
            Ok(guard) => match guard.clone() {
                Some(s) => Ok(s),
                None => {
                    debug!("Can't get session there is no running session");
                    Err(NoSessionException.into())
                }
            },
            Err(e) => {
                debug!("Failed to lock session config: {:?}", e);
                Err(SmartIdClientError::GetSessionException.into())
            }
        }
    }

    fn set_session(&self, session: SessionConfig) -> Result<()> {
        match self.session_config.lock() {
            Ok(mut guard) => {
                *guard = Some(session);
                Ok(())
            }
            Err(e) => {
                debug!("Failed to lock session config: {:?}", e);
                Err(SmartIdClientError::SetSessionException.into())
            }
        }
    }
}