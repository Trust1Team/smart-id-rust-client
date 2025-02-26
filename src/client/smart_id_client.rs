use crate::client::reqwest_generic::{get, post};
use crate::config::SmartIDConfig;
use crate::error::Result;
use crate::error::SmartIdClientError;
use crate::error::SmartIdClientError::NoSessionException;
use crate::models::authentication_session::{
    AuthenticationDynamicLinkResponse, AuthenticationNotificationResponse, AuthenticationRequest,
};
use crate::models::certificate_choice_session::{
    CertificateChoiceRequest, CertificateChoiceResponse,
};
use crate::models::common::{SessionConfig, VCCode};
use crate::models::dynamic_link::{DynamicLink, DynamicLinkType, SessionType};
use crate::models::session_status::{
    SessionCertificate, SessionResponse, SessionState, SessionStatus,
};
use crate::models::signature::ResponseSignature;
use crate::models::signature_session::{
    SignatureNotificationResponse, SignatureRequest, SignatureResponse,
};
use crate::models::user_identity::UserIdentity;
use crate::utils::demo_certificates::{demo_intermediate_certificates, demo_root_certificates};
use crate::utils::production_certificates::{
    production_intermediate_certificates, production_root_certificates,
};
use crate::utils::sec_x509::verify_certificate;
use std::sync::{Arc, Mutex};
use tracing::debug;

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

/// Smart ID Client
///
/// This struct provides methods to interact with the Smart ID service, including starting authentication,
/// certificate choice, and signature sessions using dynamic links. It also includes methods to generate
/// dynamic links, retrieve session status, and validate session responses.
///
/// The client maintains session state and authenticated user identity to ensure the correct user is signing
/// and to validate session responses.
#[derive(Debug)]
pub struct SmartIdClient {
    pub cfg: SmartIDConfig,
    /// This tracks session state and is used to make subsequent requests
    /// For example to generate QR codes or to poll for session status
    pub(crate) session_config: Arc<Mutex<Option<SessionConfig>>>,
    /// Is checked against returned certificates to ensure the correct user is signing
    pub(crate) authenticated_identity: Arc<Mutex<Option<UserIdentity>>>,
    /// List of root certificates used to validate the smart id certificates. If not provided, only the default root certificates will be used.
    /// If you are using an older version of this library, you will need to provide the latest root certificates yourself.
    pub(crate) root_certificates: Vec<String>,
    /// List of intermediate certificates used to validate the smart id certificates. If not provided, only the default intermediate certificates will be used.
    /// If you are using an older version of this library, you will need to provide the latest intermediate certificates yourself.
    pub(crate) intermediate_certificates: Vec<String>,
}

impl SmartIdClient {
    /// Creates a new SmartIdClient instance with the given configuration.
    ///
    /// # Arguments
    ///
    /// * `cfg` - A reference to the SmartIDConfig.
    /// * `user_identity` - An optional UserIdentity. This will be compared with the certificate subject to ensure the correct user is signing. If not provided, the UserIdentity will be set from the certificate during the first successful authentication.
    /// * `root_certificates` - A vector of base64 der encoded root certificates (not bundles), this is used to validate the smart id certificate chain. If not provided, only the default root certificates will be used. If you are using an older version of this library, you will need to provide the latest root certificates yourself.
    /// * `intermediate_certificates` - A vector of base64 der encoded intermediate certificates (not bundles), this is used to validate the smart id certificate chain. If not provided, only the default intermediate certificates will be used. If you are using an older version of this library, you will need to provide the latest intermediate certificates yourself
    ///
    /// # Returns
    ///
    /// A new instance of SmartIdClient.
    pub fn new(
        cfg: &SmartIDConfig,
        user_identity: Option<UserIdentity>,
        root_certificates: Vec<String>,
        intermediate_certificates: Vec<String>,
    ) -> Self {
        SmartIdClient {
            cfg: cfg.clone(),
            session_config: Arc::new(Mutex::new(None)),
            authenticated_identity: Arc::new(Mutex::new(user_identity)),
            root_certificates,
            intermediate_certificates,
        }
    }

    /// Creates a new SmartIdClient instance with the given session configuration.
    /// This should not be used to start a new session!
    /// This should be used when you need to cache the session configuration in a serialized form between requests.
    ///
    /// Example Use Case:
    /// After starting an authentication session, you can cache the session_configuration (serialized).
    /// Then, when you receive a request for session status, you rebuild the client. After you cache the session_configuration again.
    /// Then, when you receive a request for a Dynamic Link, you can rebuild the client from the session_configuration.
    ///
    /// # Arguments
    ///
    /// * `cfg` - A reference to the SmartIDConfig.
    /// * `session_config` - The session configuration from a previous session.
    /// * `user_identity` - An optional UserIdentity. This will be compared with the certificate subject to ensure the correct user is signing. If not provided, the UserIdentity will be set from the certificate during the first successful authentication.
    /// * `root_certificates` - A vector of root certificates, this is used to validate the smart id certificate chain. If not provided, only the default root certificates will be used. If you are using an older version of this library, you will need to provide the latest root certificates yourself.
    /// * `intermediate_certificates` - A vector of intermediate certificates, this is used to validate the smart id certificate chain. If not provided, only the default intermediate certificates will be used. If you are using an older version of this library, you will need to provide the latest intermediate certificates yourself
    ///
    /// # Returns
    ///
    /// A new instance of SmartIdClient.
    pub fn from_session(
        cfg: &SmartIDConfig,
        session_config: SessionConfig,
        user_identity: Option<UserIdentity>,
        root_certificates: Vec<String>,
        intermediate_certificates: Vec<String>,
    ) -> Self {
        SmartIdClient {
            cfg: cfg.clone(),
            session_config: Arc::new(Mutex::new(Some(session_config))),
            authenticated_identity: Arc::new(Mutex::new(user_identity)),
            root_certificates,
            intermediate_certificates,
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
    pub async fn get_session_status(&self) -> Result<SessionStatus> {
        let session_config = self.get_session()?;

        let path = format!(
            "{}{}/{}?timeoutMs={}",
            self.cfg.api_url(),
            SESSION_STATUS_URI,
            session_config.session_id(),
            self.cfg.long_polling_timeout,
        );

        let session_response =
            get::<SessionResponse>(path.as_str(), Some(self.cfg.long_polling_timeout + 100))
                .await?; // Add 100ms to allow SmartId to respond with a long polling timeout error instead of reqwest creating a connection error

        let session_status = session_response.into_result()?;

        match session_status.state {
            SessionState::COMPLETE => {
                self.validate_session_status(session_status.clone(), session_config)?;
                Ok(session_status)
            }
            SessionState::RUNNING => {
                Err(SmartIdClientError::StatusRequestLongPollingTimeoutException)
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
        self.clear_session();

        let path = format!(
            "{}{}",
            self.cfg.api_url(),
            ANONYMOUS_DYNAMIC_LINK_AUTHENTICATION_PATH,
        );

        let authentication_response =
            post::<AuthenticationRequest, AuthenticationDynamicLinkResponse>(
                path.as_str(),
                &authentication_request,
                self.cfg.client_request_timeout,
            )
            .await?;

        let session = authentication_response.into_result()?;

        self.set_session(SessionConfig::from_authentication_dynamic_link_response(
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
        self.clear_session();

        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            DYNAMIC_LINK_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let authentication_response =
            post::<AuthenticationRequest, AuthenticationDynamicLinkResponse>(
                path.as_str(),
                &authentication_request,
                self.cfg.client_request_timeout,
            )
            .await?;

        let session = authentication_response.into_result()?;

        self.set_session(SessionConfig::from_authentication_dynamic_link_response(
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
        self.clear_session();

        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            DYNAMIC_LINK_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let authentication_response =
            post::<AuthenticationRequest, AuthenticationDynamicLinkResponse>(
                path.as_str(),
                &authentication_request,
                self.cfg.client_request_timeout,
            )
            .await?;

        let session = authentication_response.into_result()?;

        self.set_session(SessionConfig::from_authentication_dynamic_link_response(
            session,
            authentication_request,
        )?)
    }

    /// Starts an authentication session using a notification.
    /// Use the `get_session_status` method to poll for the result.
    ///
    /// # Arguments
    ///
    /// * `authentication_request` - The authentication request.
    /// * `etsi` - The ETSI identifier of the user.
    ///
    /// # Returns
    ///
    /// A `Result` containing the verification code the user will see on screen.
    pub async fn start_authentication_notification_etsi_session(
        &self,
        authentication_request: AuthenticationRequest,
        etsi: String,
    ) -> Result<VCCode> {
        self.clear_session();

        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            NOTIFICATION_AUTHENTICATION_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let authentication_response =
            post::<AuthenticationRequest, AuthenticationNotificationResponse>(
                path.as_str(),
                &authentication_request,
                self.cfg.client_request_timeout,
            )
            .await?;

        let session = authentication_response.into_result()?;

        self.set_session(SessionConfig::from_authentication_notification_response(
            session.clone(),
            authentication_request,
        )?)?;

        Ok(session.vc)
    }

    /// Starts an authentication session using a notification.
    /// Use the `get_session_status` method to poll for the result.
    ///
    /// # Arguments
    ///
    /// * `authentication_request` - The authentication request.
    /// * `document_number` - The document number.
    ///
    /// # Returns
    ///
    /// A `Result` containing the verification code the user will see on screen.
    pub async fn start_authentication_notification_document_session(
        &self,
        authentication_request: AuthenticationRequest,
        document_number: String,
    ) -> Result<VCCode> {
        self.clear_session();

        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            NOTIFICATION_AUTHENTICATION_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let authentication_response =
            post::<AuthenticationRequest, AuthenticationNotificationResponse>(
                path.as_str(),
                &authentication_request,
                self.cfg.client_request_timeout,
            )
            .await?;

        let session = authentication_response.into_result()?;

        self.set_session(SessionConfig::from_authentication_notification_response(
            session.clone(),
            authentication_request,
        )?)?;

        Ok(session.vc)
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
        self.clear_session();

        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            DYNAMIC_LINK_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let signature_response = post::<SignatureRequest, SignatureResponse>(
            path.as_str(),
            &signature_request,
            self.cfg.client_request_timeout,
        )
        .await?;

        let session = signature_response.into_result()?;

        self.set_session(SessionConfig::from_signature_dynamic_link_request_response(
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
        self.clear_session();

        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            DYNAMIC_LINK_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let signature_response = post::<SignatureRequest, SignatureResponse>(
            path.as_str(),
            &signature_request,
            self.cfg.client_request_timeout,
        )
        .await?;

        let session = signature_response.into_result()?;

        self.set_session(SessionConfig::from_signature_dynamic_link_request_response(
            session,
            signature_request,
        )?)
    }

    /// Starts a signature session using a notification.
    /// Use the `get_session_status` method to poll for the result.
    ///
    /// # Arguments
    ///
    /// * `signature_request` - The signature request.
    /// * `etsi` - The ETSI identifier.
    ///
    /// # Returns
    ///
    /// A `Result` containing the verification code the user will see on screen.
    pub async fn start_signature_notification_etsi_session(
        &self,
        signature_request: SignatureRequest,
        etsi: String,
    ) -> Result<VCCode> {
        self.clear_session();

        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            NOTIFICATION_SIGNATURE_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let signature_response = post::<SignatureRequest, SignatureNotificationResponse>(
            path.as_str(),
            &signature_request,
            self.cfg.client_request_timeout,
        )
        .await?;

        let session = signature_response.into_result()?;

        self.set_session(SessionConfig::from_signature_notification_response(
            session.clone(),
            signature_request,
        )?)?;

        Ok(session.vc)
    }

    /// Starts a signature session using a notification.
    /// Use the `get_session_status` method to poll for the result.
    ///
    /// # Arguments
    ///
    /// * `signature_request` - The signature request.
    /// * `document_number` - The document number.
    ///
    /// # Returns
    ///
    /// A `Result` containing the verification code the user will see on screen.
    pub async fn start_signature_notification_document_session(
        &self,
        signature_request: SignatureRequest,
        document_number: String,
    ) -> Result<VCCode> {
        self.clear_session();

        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            NOTIFICATION_SIGNATURE_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let signature_response = post::<SignatureRequest, SignatureNotificationResponse>(
            path.as_str(),
            &signature_request,
            self.cfg.client_request_timeout,
        )
        .await?;

        let session = signature_response.into_result()?;

        self.set_session(SessionConfig::from_signature_notification_response(
            session.clone(),
            signature_request,
        )?)?;

        Ok(session.vc)
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
        self.clear_session();

        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            NOTIFICATION_CERTIFICATE_CHOICE_WITH_SEMANTIC_IDENTIFIER_PATH,
            etsi,
        );

        let certificate_choice_response =
            post::<CertificateChoiceRequest, CertificateChoiceResponse>(
                path.as_str(),
                &certificate_choice_request,
                self.cfg.client_request_timeout,
            )
            .await?;

        let session = certificate_choice_response.into_result()?;

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
        self.clear_session();

        let path = format!(
            "{}{}/{}",
            self.cfg.api_url(),
            NOTIFICATION_CERTIFICATE_CHOICE_WITH_DOCUMENT_NUMBER_PATH,
            document_number,
        );

        let certificate_choice_response =
            post::<CertificateChoiceRequest, CertificateChoiceResponse>(
                path.as_str(),
                &certificate_choice_request,
                self.cfg.client_request_timeout,
            )
            .await?;

        let session = certificate_choice_response.into_result()?;

        self.set_session(SessionConfig::from_certificate_choice_response(
            session,
            certificate_choice_request,
        ))
    }

    // endregion: Certificate Choice

    // region: Dynamic Link

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
            SessionConfig::AuthenticationDynamicLink {
                session_secret,
                session_token,
                session_start_time,
                ..
            } => {
                let dynamic_link = DynamicLink {
                    url: self.cfg.dynamic_link_url(),
                    version: "0.1".to_string(), //TODO: store this somewhere
                    session_token,
                    session_secret,
                    dynamic_link_type: dynamic_link_type.clone(),
                    session_type: SessionType::auth,
                    session_start_time,
                    language_code: language_code.to_string(),
                };
                let dynamic_link = dynamic_link.generate_dynamic_link();
                Ok(dynamic_link)
            }
            SessionConfig::Signature {
                session_secret,
                session_token,
                session_start_time,
                ..
            } => {
                let dynamic_link = DynamicLink {
                    url: self.cfg.dynamic_link_url(),
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
            _ => {
                Err(SmartIdClientError::GenerateDynamicLinkException(
                    "Can only generate dynamic links for authentication or signature dynamic link sessions",
                ))
            }

        }
    }

    // endregion: Dynamic Link

    // region: Validation

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
    /// * `user_identity` - The subject of the certificate.
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
    /// - The provided identity does not match the certificate.
    fn validate_session_status(
        &self,
        session_status: SessionStatus,
        session_config: SessionConfig,
    ) -> Result<()> {
        match session_status.result {
            Some(session_result) => {
                // Check the result is OK
                session_result.end_result.is_ok()?;

                // Validate the certificate is present (Required for OK status)
                let cert = session_status
                    .cert
                    .ok_or(SmartIdClientError::SessionResponseMissingCertificate)?;

                // Verify the certificate chain
                self.verify_certificate(cert.value.clone())?;

                // Check certificate level is high enough
                if &cert.certificate_level < session_config.requested_certificate_level() {
                    Err(
                        SmartIdClientError::FailedToValidateSessionResponseCertificate(format!(
                            "Certificate level is not high enough: {:?} < {:?}",
                            cert.certificate_level,
                            session_config.requested_certificate_level()
                        )),
                    )?
                };

                // Validate signature is correct
                self.validate_signature(session_config, session_status.signature, cert.clone())?;

                // Check that the identity matches the certificate
                if let Some(user_identity) = self.get_user_identity()? {
                    user_identity.identity_matches_certificate(cert.value)?
                }

                Ok(())
            }
            None => match session_status.state {
                SessionState::RUNNING => Ok(()),
                SessionState::COMPLETE => {
                    Err(SmartIdClientError::AuthenticationSessionCompletedWithoutResult)
                }
            },
        }
    }

    /// Verifies a certificate chain using the root and intermediate certificates.
    ///
    /// This is done automatically when validating the session response. You only need to call this method if you want to validate a certificate that has not just been returned from a session.
    ///
    /// # Arguments
    /// * `cert` - The base64 der encoded certificate to be validated.
    /// # Returns
    /// A `Result` indicating success or failure. If the validation is successful, it returns `Ok(())`.
    pub fn verify_certificate(&self, cert: String) -> Result<()> {
        if self.cfg.is_demo() {
            let mut root_certs = demo_root_certificates();
            root_certs.extend(self.root_certificates.clone());
            let mut intermediate_certs = demo_intermediate_certificates();
            intermediate_certs.extend(self.intermediate_certificates.clone());
            verify_certificate(&cert, intermediate_certs, root_certs)
        } else {
            let mut root_certs = production_root_certificates();
            root_certs.extend(self.root_certificates.clone());
            let mut intermediate_certs = production_intermediate_certificates();
            intermediate_certs.extend(self.intermediate_certificates.clone());
            verify_certificate(
                &cert,
                production_root_certificates(),
                production_intermediate_certificates(),
            )
        }
    }

    fn validate_signature(
        &self,
        session_config: SessionConfig,
        signature: Option<ResponseSignature>,
        cert: SessionCertificate,
    ) -> Result<()> {
        match session_config {
            SessionConfig::AuthenticationDynamicLink {
                random_challenge, ..
            } => {
                let signature =
                    signature.ok_or(SmartIdClientError::SessionResponseMissingSignature)?;

                signature.validate_acsp_v1(random_challenge, cert.value.clone())?;

                // If no user identity is set, set it from the certificate
                // This happens during all anonymous sessions
                if self.get_user_identity()?.is_none() {
                    self.set_user_identity(UserIdentity::from_certificate(cert.value.clone())?)?
                };

                Ok(())
            }
            SessionConfig::AuthenticationNotification {
                random_challenge, ..
            } => {
                let signature =
                    signature.ok_or(SmartIdClientError::SessionResponseMissingSignature)?;

                signature.validate_acsp_v1(random_challenge, cert.value.clone())?;

                // If no user identity is set, set it from the certificate
                // This happens during all anonymous sessions
                if self.get_user_identity()?.is_none() {
                    self.set_user_identity(UserIdentity::from_certificate(cert.value.clone())?)?
                };

                Ok(())
            }
            SessionConfig::Signature { digest, .. } => {
                let signature =
                    signature.ok_or(SmartIdClientError::SessionResponseMissingSignature)?;

                // TODO: CHeck this with prod
                if self.cfg.is_demo() {
                    return Ok(());
                }

                signature.validate_raw_digest(digest, cert.value.clone())
            }
            SessionConfig::SignatureNotification { digest, .. } => {
                let signature =
                    signature.ok_or(SmartIdClientError::SessionResponseMissingSignature)?;

                // TODO: CHeck this with prod
                if self.cfg.is_demo() {
                    return Ok(());
                }

                signature.validate_raw_digest(digest, cert.value.clone())
            }
            _ => {
                debug!("Signature validation only needed for dynamic link authentication and signature sessions");
                Ok(())
            }
        }
    }

    // endregion: Validation

    // region: Utility functions

    /// Resets the current session by clearing the session configuration and the authenticated user identity.
    ///
    /// If a different user wants to log in you must call this method to clear the current session identity.
    pub fn reset_session(&self) {
        self.clear_session();
        self.clear_user_identity();
    }

    pub fn get_session(&self) -> Result<SessionConfig> {
        match self.session_config.lock() {
            Ok(guard) => match guard.clone() {
                Some(s) => Ok(s),
                None => {
                    debug!("Can't get session there is no running session");
                    Err(NoSessionException)
                }
            },
            Err(e) => {
                debug!("Failed to lock session config: {:?}", e);
                Err(SmartIdClientError::GetSessionException)
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
                Err(SmartIdClientError::SetSessionException)
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

    pub fn get_user_identity(&self) -> Result<Option<UserIdentity>> {
        match self.authenticated_identity.lock() {
            Ok(guard) => match guard.clone() {
                Some(s) => Ok(Some(s)),
                None => Ok(None),
            },
            Err(e) => {
                debug!("Failed to lock authenticated identity: {:?}", e);
                Err(SmartIdClientError::GetUserIdentityException)
            }
        }
    }

    fn set_user_identity(&self, user_identity: UserIdentity) -> Result<()> {
        match self.authenticated_identity.lock() {
            Ok(mut guard) => {
                *guard = Some(user_identity);
                Ok(())
            }
            Err(e) => {
                debug!("Failed to lock authenticated identity: {:?}", e);
                Err(SmartIdClientError::SetUserIdentityException)
            }
        }
    }

    #[allow(dead_code)]
    fn clear_user_identity(&self) {
        match self.authenticated_identity.lock() {
            Ok(mut guard) => {
                *guard = None;
            }
            Err(e) => {
                debug!("Failed to lock authenticated identity: {:?}", e);
            }
        }
    }

    // endregion: Utility functions
}
