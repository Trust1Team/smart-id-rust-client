use crate::client::reqwest_generic::{get, post};
use crate::config::SmartIDConfig;
use crate::error::SmartIdClientError;
use crate::error::SmartIdClientError::NoSessionException;
use crate::models::authentication_session::{AuthenticationRequest, AuthenticationResponse};
use crate::models::certificate_choice_session::{
    CertificateChoiceRequest, CertificateChoiceResponse,
};
use crate::models::common::SessionConfig;
use crate::models::dynamic_link::{DynamicLink, DynamicLinkType, SessionType};
use crate::models::session_status::{SessionState, SessionStatus};
use crate::models::signature_session::{SignatureRequest, SignatureRequestResponse};
use crate::utils::sec_x509::validate_certificate;
use anyhow::Result;
use base64::prelude::BASE64_STANDARD;
use base64::Engine;
use std::sync::{Arc, Mutex};
use tracing::debug;
use x509_parser::certificate::X509Certificate;
use x509_parser::prelude::FromDer;

// region: Path definitions
// Copied from https://github.com/SK-EID/smart-id-java-client/blob/81e48f519bf882db8584a344b161db378b959093/src/main/java/ee/sk/smartid/v3/rest/SmartIdRestConnector.java#L79
const SESSION_STATUS_URI: &str = "/session";
const NOTIFICATION_CERTIFICATE_CHOICE_WITH_SEMANTIC_IDENTIFIER_PATH: &str =
    "/certificatechoice/notification/etsi";
const NOTIFICATION_CERTIFICATE_CHOICE_WITH_DOCUMENT_NUMBER_PATH: &str =
    "/certificatechoice/notification/document";

const DYNAMIC_LINK_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH: &str = "/signature/dynamic-link/etsi";
const DYNAMIC_LINK_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH: &str = "/signature/dynamic-link/document";
#[allow(dead_code)]
const NOTIFICATION_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH: &str = "/signature/notification/etsi";
#[allow(dead_code)]
const NOTIFICATION_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH: &str = "/signature/notification/document";

const ANONYMOUS_DYNAMIC_LINK_AUTHENTICATION_PATH: &str = "/authentication/dynamic-link/anonymous";
const DYNAMIC_LINK_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH: &str =
    "/authentication/dynamic-link/etsi";
const DYNAMIC_LINK_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH: &str =
    "/authentication/dynamic-link/document";
#[allow(dead_code)]
const NOTIFICATION_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH: &str =
    "/authentication/notification/etsi";
#[allow(dead_code)]
const NOTIFICATION_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH: &str =
    "/authentication/notification/document";

// endregion: Path definitions

#[derive(Debug)]
pub struct SmartIdClientV3 {
    pub cfg: SmartIDConfig,
    // This tracks session state and is used to make subsequent requests
    // For example to generate QR codes or to poll for session status
    pub(crate) session_config: Arc<Mutex<Option<SessionConfig>>>,
}

impl SmartIdClientV3 {
    /// Creates a new SmartIdClientV3 instance with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `cfg` - A reference to the SmartIDConfig.
    ///
    /// # Returns
    ///
    /// A new instance of SmartIdClientV3.
    pub async fn new(cfg: &SmartIDConfig) -> Self {
        SmartIdClientV3 {
            cfg: cfg.clone(),
            session_config: Arc::new(Mutex::new(None)),
        }
    }

    // region: Session Status

    /// Retrieves the session status with a specified timeout.
    /// The session must first be started with one of the start session methods.
    ///
    /// # Arguments
    ///
    /// * `timeoutMs` - Timeout in milliseconds.  The upper bound of timeout: 120000, minimum 1000.
    ///
    /// # Returns
    ///
    /// A Result containing the SessionStatus or an error.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The session is not found or not running.
    /// - The session status request fails.
    /// - The session did not complete within the specified timeout.
    /// - The session response endResult is not OK.
    /// - The session response is missing a certificate.
    /// - The session response is missing a signature.
    /// - The session response certificate is invalid.
    /// - The session response signature is invalid.
    pub async fn get_session_status(&self, timeout_ms: i32) -> Result<SessionStatus> {
        let session_config = self.get_session()?;

        let path = format!(
            "{}{}/{}?timeoutMs={}",
            self.cfg.api_url(),
            SESSION_STATUS_URI,
            session_config.session_id(),
            timeout_ms
        );

        let session_status =
            get::<SessionStatus>(path.as_str(), self.cfg.client_request_timeout).await?;

        match session_status.state {
            SessionState::COMPLETE => {
                self.validate_session_status(session_status.clone(), session_config)?;
                self.clear_session();
                Ok(session_status)
            }
            SessionState::RUNNING => {
                Err(SmartIdClientError::SessionDidNotCompleteInTimoutError.into())
            }
        }
    }

    // endregion: Session Status

    // region: Authentication

    /// Starts an authentication session using a dynamic link.
    /// Use the create dynamic link methods to generate the dynamic link to send to the user to continue the authentication process.
    /// Use the get_session_status method to poll for the result.
    ///
    /// # Arguments
    ///
    /// * `authentication_request` - The authentication request.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub async fn start_authentication_dynamic_link_anonymous_session(
        &self,
        authentication_request: AuthenticationRequest,
    ) -> Result<()> {
        let path = format!(
            "{}{}",
            self.cfg.api_url(),
            ANONYMOUS_DYNAMIC_LINK_AUTHENTICATION_PATH,
        );

        let session = post::<AuthenticationRequest, AuthenticationResponse>(
            path.as_str(),
            &authentication_request,
            self.cfg.client_request_timeout,
        )
        .await?;
        self.set_session(SessionConfig::from_authentication_response(
            session,
            authentication_request,
        )?)
    }

    /// Starts an authentication session with a document using a dynamic link.
    /// Use the create dynamic link methods to generate the dynamic link to send to the user to continue the authentication process.
    /// Use the get_session_status method to poll for the result.
    ///
    /// # Arguments
    ///
    /// * `authentication_request` - The authentication request.
    /// * `document_number` - The document number.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub async fn start_authentication_dynamic_link_document_session(
        &self,
        authentication_request: AuthenticationRequest,
        document_number: String,
    ) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            DYNAMIC_LINK_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let session = post::<AuthenticationRequest, AuthenticationResponse>(
            path.as_str(),
            &authentication_request,
            self.cfg.client_request_timeout,
        )
        .await?;
        self.set_session(SessionConfig::from_authentication_response(
            session,
            authentication_request,
        )?)
    }

    /// Starts an authentication session with an etsi using a dynamic link.
    /// Use the create dynamic link methods to generate the dynamic link to send to the user to continue the authentication process.
    /// Use the get_session_status method to poll for the result.
    ///
    /// # Arguments
    ///
    /// * `authentication_request` - The authentication request.
    /// * `etsi` - The ETSI semantic identifier.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub async fn start_authentication_dynamic_link_etsi_session(
        &self,
        authentication_request: AuthenticationRequest,
        etsi: String,
    ) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            DYNAMIC_LINK_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let session = post::<AuthenticationRequest, AuthenticationResponse>(
            path.as_str(),
            &authentication_request,
            self.cfg.client_request_timeout,
        )
        .await?;
        self.set_session(SessionConfig::from_authentication_response(
            session,
            authentication_request,
        )?)
    }

    // endregion: Authentication

    // region: Signature

    /// Starts a signature session using a dynamic link and an ETSI identifier.
    /// Use the create dynamic link methods to generate the dynamic link to send to the user to continue the signature process.
    /// Use the get_session_status method to poll for the result.
    ///
    /// # Arguments
    ///
    /// * `signature_request` - The signature request.
    /// * `etsi` - The ETSI identifier.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub async fn start_signature_dynamic_link_etsi_session(
        &self,
        signature_request: SignatureRequest,
        etsi: String,
    ) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            DYNAMIC_LINK_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let session = post::<SignatureRequest, SignatureRequestResponse>(
            path.as_str(),
            &signature_request,
            self.cfg.client_request_timeout,
        )
        .await?;
        self.set_session(SessionConfig::from_signature_request_response(
            session,
            signature_request,
        )?)
    }

    /// Starts a signature session using a dynamic link and a document number.
    /// Use the create dynamic link methods to generate the dynamic link to send to the user to continue the signature process.
    /// Use the get_session_status method to poll for the result.
    ///
    /// # Arguments
    ///
    /// * `signature_request` - The signature request.
    /// * `document_number` - The document number.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub async fn start_signature_dynamic_link_document_session(
        &self,
        signature_request: SignatureRequest,
        document_number: String,
    ) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            DYNAMIC_LINK_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let session = post::<SignatureRequest, SignatureRequestResponse>(
            path.as_str(),
            &signature_request,
            self.cfg.client_request_timeout,
        )
        .await?;
        self.set_session(SessionConfig::from_signature_request_response(
            session,
            signature_request,
        )?)
    }

    // endregion: Signature

    // region: Certificate Choice

    /// Starts a certificate choice session using a notification and an ETSI identifier.
    /// Use the get_session_status method to poll for the result.
    ///
    /// # Arguments
    ///
    /// * `certificate_choice_request` - The certificate choice request.
    /// * `etsi` - The ETSI identifier.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub async fn start_certificate_choice_notification_etsi_session(
        &self,
        certificate_choice_request: CertificateChoiceRequest,
        etsi: String,
    ) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            NOTIFICATION_CERTIFICATE_CHOICE_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let session = post::<CertificateChoiceRequest, CertificateChoiceResponse>(
            path.as_str(),
            &certificate_choice_request,
            self.cfg.client_request_timeout,
        )
        .await?;
        self.set_session(SessionConfig::from_certificate_choice_response(
            session,
            certificate_choice_request,
        ))
    }

    /// Starts a certificate choice session using a notification and document id.
    /// Use the get_session_status method to poll for the result.
    ///
    /// # Arguments
    ///
    /// * `certificate_choice_request` - The certificate choice request.
    /// * `document_number` - The document number.
    ///
    /// # Returns
    ///
    /// A Result indicating success or failure.
    pub async fn start_certificate_choice_notification_document_session(
        &self,
        certificate_choice_request: CertificateChoiceRequest,
        document_number: String,
    ) -> Result<()> {
        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            NOTIFICATION_CERTIFICATE_CHOICE_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let session = post::<CertificateChoiceRequest, CertificateChoiceResponse>(
            path.as_str(),
            &certificate_choice_request,
            self.cfg.client_request_timeout,
        )
        .await?;
        self.set_session(SessionConfig::from_certificate_choice_response(
            session,
            certificate_choice_request,
        ))
    }

    // endregion

    /// Generates a dynamic link for the current session.
    /// The link will redirect the device to the Smart-ID app.
    /// The link must be refreshed every 1 second.
    ///
    /// # Arguments
    ///
    /// * `dynamic_link_type` - This can be a QR, Web2App or App2App link.
    /// * `language_code` - The language code (3-letter ISO 639-2 code).
    ///
    /// # Returns
    ///
    /// A `Result` containing the generated dynamic link as a `String` or an error.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - There is no running session.
    /// - The session type is `CertificateChoice`.
    pub fn generate_dynamic_link(
        &self,
        dynamic_link_type: DynamicLinkType,
        language_code: &str,
    ) -> Result<String> {
        let session: SessionConfig = self.get_session()?;

        match session {
            SessionConfig::Authentication {
                session_secret,
                session_token,
                session_start_time,
                ..
            } => {
                let dynamic_link = DynamicLink {
                    url: self.cfg.api_url(),
                    version: "0.1".to_string(), //TODO: store this somewhere
                    session_token,
                    session_secret,
                    dynamic_link_type: dynamic_link_type.clone(),
                    session_type: SessionType::auth,
                    session_start_time,
                    language_code: language_code.to_string(),
                };
                let dynamic_link = dynamic_link.generate_dynamic_link();
                debug!("Generated dynamic link: {}", dynamic_link);
                Ok(dynamic_link)
            }
            SessionConfig::Signature {
                session_secret,
                session_token,
                session_start_time,
                ..
            } => {
                let dynamic_link = DynamicLink {
                    url: self.cfg.api_url(),
                    version: "0.1".to_string(), //TODO: store this somewhere
                    session_token,
                    session_secret,
                    dynamic_link_type: dynamic_link_type.clone(),
                    session_type: SessionType::sign,
                    session_start_time,
                    language_code: language_code.to_string(),
                };
                let dynamic_link = dynamic_link.generate_dynamic_link();
                debug!("Generated dynamic link: {}", dynamic_link);
                Ok(dynamic_link)
            }
            SessionConfig::CertificateChoice { .. } => {
                Err(SmartIdClientError::GenerateDynamicLinkException(
                    "Can't generate dynamic link for certificate choice session",
                )
                .into())
            }
        }
    }

    // region: Utility functions

    /// Validates the session status and ensures that the session has completed successfully.
    ///
    /// If the session is running returns Ok(()).
    ///
    /// If the session is complete, this function performs several checks to validate the session status:
    /// - Ensures that the session result is present.
    /// - Validates the certificate chain and checks for expiration.
    /// - Verifies the identity of the authenticated person using the subject field or subjectAltName extension of the X.509 certificate.
    /// - Checks that the certificate level is high enough.
    /// - Validates the signature using the public key from the certificate.
    /// - Checks the session result is OK.
    ///
    /// # Arguments
    ///
    /// * `session_status` - The status of the session to be validated.
    /// * `session_config` - The configuration of the session.
    ///
    /// # Returns
    ///
    /// A `Result` indicating success or failure. If the validation is successful, it returns `Ok(())`.
    /// If any validation step fails, it returns an appropriate `SmartIdClientError`.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - The session result is missing.
    /// - The certificate is missing or invalid.
    /// - The signature is missing or invalid.
    /// - The session did not complete successfully.
    /// - The session result is not OK.
    fn validate_session_status(
        &self,
        session_status: SessionStatus,
        session_config: SessionConfig,
    ) -> Result<()> {
        match session_status.result {
            Some(session_result) => {
                // Return an error if the session result is not OK
                session_result.end_result.is_ok()?;

                let cert = match session_status.cert {
                    Some(cert) => cert,
                    None => {
                        return Err(SmartIdClientError::SessionResponseMissingCertificate.into())
                    }
                };

                // Validate the certificate chain and check for expiration
                validate_certificate(&cert.value)?;

                let decoded_cert = BASE64_STANDARD.decode(&cert.value).map_err(|_| {
                    SmartIdClientError::FailedToValidateSessionResponseCertificate(
                        "Could not decode base64 certificate",
                    )
                })?;
                let (_, parsed_cert) =
                    X509Certificate::from_der(decoded_cert.as_slice()).map_err(|_| {
                        SmartIdClientError::FailedToValidateSessionResponseCertificate(
                            "Failed to parse certificate",
                        )
                    })?;

                // The identity of the authenticated person is in the subject field or subjectAltName extension of the X.509 certificate.
                // TODO: Find the subject to validate against
                let _subject = parsed_cert.subject().clone();
                let _subject_alt_name = parsed_cert.subject_alternative_name();

                // Check that the certificate level is high enough
                // TODO: Implement this

                // signature.value is the valid signature over the expected hash as described in Signature protocols, which was submitted by the RP verified using the public key from cert.value.
                let signature = match session_status.signature {
                    Some(signature) => signature,
                    None => return Err(SmartIdClientError::SessionResponseMissingSignature.into()),
                };

                match session_config {
                    SessionConfig::Authentication {
                        random_challenge, ..
                    } => signature.validate_acsp_v1(
                        random_challenge,
                        parsed_cert.public_key().clone().subject_public_key,
                    ),
                    SessionConfig::Signature { digest, .. } => signature.validate_raw_digest(
                        digest,
                        parsed_cert.public_key().clone().subject_public_key,
                    ),
                    SessionConfig::CertificateChoice { .. } => {
                        debug!("No validation needed for certificate choice session");
                        Ok(())
                    }
                }?;

                Ok(())
            }
            None => match session_status.state {
                SessionState::RUNNING => Ok(()),
                SessionState::COMPLETE => {
                    Err(SmartIdClientError::AuthenticationSessionCompletedWithoutResult.into())
                }
            },
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

    // endregion: Utility functions
}
