use std::convert::identity;
use std::io::Read;
use std::sync::{Arc, Mutex};
use crate::client::reqwest_generic::{get, post};
use crate::client::v2::smart_id_connector::SmartIdConnector;
use crate::common::SemanticsIdentifier;
use crate::config::SmartIDConfig;
use crate::error::SmartIdClientError;
use crate::error::SmartIdClientError::{NoSessionException, SmartIdClientException};
use crate::models::v3::common::SessionConfig;
use crate::models::v3::session_status::{EndResult, SessionState, SessionStatus};
use anyhow::{bail, Result};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use tracing::{debug, info};
use x509_parser::certificate::X509Certificate;
use x509_parser::nom::combinator::into;
use x509_parser::prelude::FromDer;
use crate::models::v3::authentication_session::{AuthenticationRequest, AuthenticationResponse};
use crate::models::v3::certificate_choice_session::{CertificateChoiceResponse, CertificateChoiceRequest};
use crate::models::v3::dynamic_link::{DynamicLink, DynamicLinkType, SessionType};
use crate::models::v3::dynamic_link::SessionType::sign;
use crate::models::v3::signature::SignatureResponse;
use crate::models::v3::signature_session::{SignatureRequest, SignatureRequestResponse};
use crate::SessionResult;
use crate::utils::sec_x509::validate_certificate;

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

    // region: Session Status

    pub async fn get_session_status(&self, timeoutMs: i32) -> Result<SessionStatus> {
        let session_config = self.get_session()?;

        let path = format!(
            "{}{}/{}?timeoutMs={}",
            self.cfg.url,
            SESSION_STATUS_URI,
            session_config.session_id(),
            timeoutMs
        );

        let session_status = get::<SessionStatus>(path.as_str(), self.cfg.client_request_timeout).await?;

        match session_status.state {
            SessionState::COMPLETE => {
                match session_config {
                    SessionConfig::CertificateChoice { session_id, .. } => {
                        self.validate_certificate_choice_session_status(&session_status, session_id).await
                    }
                    SessionConfig::Authentication { session_id, session_secret, session_token, random_challenge, .. } => {
                        self.validate_authentication_session_status(session_status.clone(), session_id, session_secret, session_token, random_challenge).await
                    }
                    SessionConfig::Signature { session_id, session_secret, session_token, .. } => {
                        self.validate_signature_session_status(&session_status, session_id, session_secret, session_token).await
                    }
                }?;

                self.clear_session();
                Ok(session_status)
            }
            SessionState::RUNNING => Err(SmartIdClientError::SessionDidNotCompleteInTimoutError.into())
        }
    }

    pub async fn validate_authentication_session_status(&self, session_status: SessionStatus, session_id: String, session_secret: String, session_token: String, random_challenge: String) -> Result<()> {
        match session_status.result {
            Some(session_result) => {
                let cert = match session_status.cert {
                    Some(cert) => cert,
                    None => return Err(SmartIdClientError::SessionResponseMissingCertificate.into())
                };

                // Response verification as described here https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.2/response_verification.html

                // Check that the certificate is trusted, not expired, etc
                validate_certificate(&cert.value)?;

                // Check that the certificate level is high enough
                // TODO: Find the certificate level ordering
                // cert.certificate_level


                // The identity of the authenticated person is in the subject field or subjectAltName extension of the X.509 certificate.
                let decoded_cert = BASE64_STANDARD.decode(&cert.value).map_err(|_| SmartIdClientError::FailedToValidateSessionResponseCertificate("Could not decode base64 certificate"))?;
                let (_, parsed_cert) = X509Certificate::from_der(decoded_cert.as_slice()).map_err(|_| SmartIdClientError::FailedToValidateSessionResponseCertificate("Failed to parse certificate"))?;
                let subject = parsed_cert.subject().clone();
                let subject_alt_name = parsed_cert.subject_alternative_name();
                // TODO: Find the subject to validate against

                // TODO:
                // signature.value is the valid signature over the expected hash as described in Signature protocols, which was submitted by the RP verified using the public key from cert.value.
                Ok(())
            }
            None => {
                match session_status.state {
                    SessionState::RUNNING => {
                        Ok(())
                    }
                    SessionState::COMPLETE => {
                        Err(SmartIdClientError::AuthenticationSessionCompletedWithoutResult.into())
                    }
                }
            }
        }
    }

    pub async fn validate_signature_session_status(&self, session_status: &SessionStatus, session_id: String, session_secret: String, session_token: String) -> Result<()> {
        todo!()
    }

    pub async fn validate_certificate_choice_session_status(&self, session_status: &SessionStatus, session_id: String) -> Result<()> {
        todo!()
    }

    // endregion: Session Status

    // region: Authentication

    pub async fn start_authentication_dynamic_link_anonymous_session(&self, authentication_request: AuthenticationRequest) -> Result<()> {
        let path = format!(
            "{}{}",
            self.cfg.url,
            ANONYMOUS_DYNAMIC_LINK_AUTHENTICATION_PATH,
        );

        let session = post::<AuthenticationRequest, AuthenticationResponse>(path.as_str(), &authentication_request, self.cfg.client_request_timeout).await?;
        self.set_session(SessionConfig::from_authentication_response(session, authentication_request)?)
    }

    pub async fn start_authentication_dynamic_link_document_session(&self, authentication_request: AuthenticationRequest, document_number: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            DYNAMIC_LINK_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let session = post::<AuthenticationRequest, AuthenticationResponse>(path.as_str(), &authentication_request, self.cfg.client_request_timeout).await?;
        self.set_session(SessionConfig::from_authentication_response(session, authentication_request)?)
    }

    pub async fn start_authentication_dynamic_link_etsi_session(&self, authentication_request: AuthenticationRequest, etsi: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            DYNAMIC_LINK_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let session = post::<AuthenticationRequest, AuthenticationResponse>(path.as_str(), &authentication_request, self.cfg.client_request_timeout).await?;
        self.set_session(SessionConfig::from_authentication_response(session, authentication_request)?)
    }

    // endregion: Authentication

    // region: Signature

    pub async fn start_signature_dynamic_link_etis_session(&self, signature_request: SignatureRequest, etsi: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            DYNAMIC_LINK_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let session = post::<SignatureRequest, SignatureRequestResponse>(path.as_str(), &signature_request, self.cfg.client_request_timeout).await?;
        self.set_session(SessionConfig::from_signature_request_response(session, signature_request))
    }

    pub async fn start_signature_dynamic_link_document_session(&self, signature_request: SignatureRequest, document_number: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            DYNAMIC_LINK_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let session = post::<SignatureRequest, SignatureRequestResponse>(path.as_str(), &signature_request, self.cfg.client_request_timeout).await?;
        self.set_session(SessionConfig::from_signature_request_response(session, signature_request))
    }

    // endregion: Signature

    // region: Certificate Choice

    pub async fn start_certificate_choice_notification_etsi_session(&self, certificate_choice_request: CertificateChoiceRequest, etsi: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            NOTIFICATION_CERTIFICATE_CHOICE_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi.to_string(),
        );

        let session = post::<CertificateChoiceRequest, CertificateChoiceResponse>(path.as_str(), &certificate_choice_request, self.cfg.client_request_timeout).await?;
        self.set_session(SessionConfig::from_certificate_choice_response(session, certificate_choice_request))
    }

    pub async fn start_certificate_choice_notification_document_session(&self, certificate_choice_request: CertificateChoiceRequest, document_number: String) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.url,
            NOTIFICATION_CERTIFICATE_CHOICE_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let session = post::<CertificateChoiceRequest, CertificateChoiceResponse>(path.as_str(), &certificate_choice_request, self.cfg.client_request_timeout).await?;
        self.set_session(SessionConfig::from_certificate_choice_response(session, certificate_choice_request))
    }

    // endregion


    // 2 letter language code according to ISO 639-1
    pub fn generate_dynamic_link(&self, dynamic_link_type: DynamicLinkType, language_code: String) -> Result<String> {
        let session: SessionConfig = self.get_session()?;

        match session {
            SessionConfig::Authentication { session_secret, session_token, session_start_time, .. } => {
                let dynamic_link = DynamicLink {
                    url: self.cfg.url.clone(),
                    version: "0.1".to_string(), //TODO: store this somewhere
                    session_token,
                    session_secret,
                    dynamic_link_type: dynamic_link_type.clone(),
                    session_type: SessionType::auth,
                    session_start_time,
                    language_code,
                };
                let dynamic_link = dynamic_link.generate_dynamic_link();
                debug!("Generated dynamic link: {}", dynamic_link);
                Ok(dynamic_link)
            }
            SessionConfig::Signature { session_secret, session_token, session_start_time, .. } => {
                let dynamic_link = DynamicLink {
                    url: self.cfg.url.clone(),
                    version: "0.1".to_string(), //TODO: store this somewhere
                    session_token,
                    session_secret,
                    dynamic_link_type: dynamic_link_type.clone(),
                    session_type: SessionType::sign,
                    session_start_time,
                    language_code,
                };
                let dynamic_link = dynamic_link.generate_dynamic_link();
                debug!("Generated dynamic link: {}", dynamic_link);
                Ok(dynamic_link)
            }
            SessionConfig::CertificateChoice { .. }  => {
                Err(SmartIdClientError::GenerateDynamicLinkException("Can't generate dynamic link for certificate choice session").into())
            }
            _ => {
                debug!("Can't generate dynamic link for this session type");
                Err(SmartIdClientError::GetSessionException.into())
            }
        }
    }

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

    fn clear_session(&self) {
        match self.session_config.lock() {
            Ok(mut guard) => {
                *guard = None;
            }
            Err(e) => {
                debug!("Failed to lock session config: {:?}", e);
            }
        }
    }
}