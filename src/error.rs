use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum SmartIdClientError {
    /// Config Exception
    #[error("Configuration missing: {0}")]
    ConfigMissingException(&'static str),

    /// Session not found
    #[error("Session not found: {0}")]
    SessionNotFound(String),

    #[error("Invalid request")]
    InvalidRequest,

    /// Unprocessable
    #[error("Unprocessable exception: {0}")]
    UnprocessableSmartIdResponseException(&'static str),

    ///RelyingPartyAccountConfigurationException
    #[error("Relying Party account configuration exception: {0}")]
    RelyingPartyAccountConfigurationException(&'static str),

    ///ServerMaintenanceException
    #[error("Server maintenance exception: {0}")]
    ServerMaintenanceException(&'static str),

    ///SmartIdClientException
    #[error("Smart ID client exception: {0}")]
    SmartIdClientException(&'static str),

    /// Client-side integration or how Relying Party account has been configured by Smart-ID operator or Smart-ID server is under maintenance
    /// With these types of errors there is not recommended to ask the user for immediate retry
    #[error("Enduring Smart ID exception: {0}")]
    EnduringSmartIdException(&'static str),

    /// User's action triggered ending session.
    /// General practise is to ask the user to try again.
    #[error("User action exception: {0}, try use case again")]
    UserActionException(&'static str),

    /// Session timed out without getting any response from user
    #[error("Session timed out without getting any response from user")]
    SessionTimeoutException,

    /// Session exception when Retry is required
    #[error("Session exception when Retry is required")]
    SessionRetryException,

    /// There is no running session
    #[error("There is no running session")]
    NoSessionException,

    /// Failed to get the running session
    #[error("Failed to get the running session")]
    GetSessionException,

    /// Failed to set the running session
    #[error("Failed to set the running session")]
    SetSessionException,

    /// Authentication session completed without result
    #[error("Authentication session completed without result")]
    AuthenticationSessionCompletedWithoutResult,

    /// Session did not complete within timeout
    #[error("Session did not complete within timeout")]
    SessionDidNotCompleteInTimoutError,

    /// Session does not exist or has expired
    #[error("Session does not exist or has expired")]
    SessionDoesNotExistOrHasExpired,

    /// Api client is too old and is not supported anymore
    #[error("Api client is too old and is not supported anymore")]
    ApiClientIsTooOldException,

    /// System is under maintenance and is not available
    #[error("System is under maintenance and is not available")]
    SystemIsUnderMaintenanceException,

    /// Session response missing certificate
    #[error("Session response missing certificate")]
    SessionResponseMissingCertificate,

    /// Session response missing signature
    #[error("Session response missing signature")]
    SessionResponseMissingSignature,

    /// Session response signature verification failed
    #[error("Session response signature verification failed: {0}")]
    InvalidResponseSignature(String),

    /// User has multiple accounts and pressed Cancel on device choice screen on any device
    #[error("User has multiple accounts and pressed Cancel on device choice screen on any device")]
    UserRefusedCertChoiceException,

    /// User cancelled on confirmationMessage screen
    #[error("User cancelled on confirmationMessage screen")]
    UserRefusedConfirmationMessageException,

    /// User cancelled on confirmationMessageAndVerificationCodeChoice screen
    #[error("User cancelled on confirmationMessageAndVerificationCodeChoice screen")]
    UserRefusedConfirmationMessageWithVerificationChoiceException,

    /// User pressed Cancel on PIN screen
    #[error("User pressed Cancel on PIN screen")]
    UserRefusedDisplayTextAndPinException,

    /// User cancelled verificationCodeChoice screen
    #[error("User cancelled verificationCodeChoice screen")]
    UserRefusedVerificationChoiceException,

    /// User selected wrong verification code
    #[error("User selected wrong verification code")]
    UserSelectedWrongVerificationCodeException,

    /// Something is wrong with user's Smart-ID account (or app) configuration.
    /// General practise is to ask the user to try again.
    #[error("User action exception: {0}")]
    UserAccountException(&'static str),

    /// Signer's certificate is below requested certificate level
    #[error("Signer's certificate is below requested certificate level")]
    CertificateLevelMismatchException,

    /// DOCUMENT_UNUSABLE. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason.
    #[error("DOCUMENT_UNUSABLE. User must either check his/her Smart-ID mobile application or turn to customer support for getting the exact reason")]
    DocumentUnusableException,

    /// No suitable account of requested type found, but user has some other accounts
    #[error("No suitable account of requested type found, but user has some other accounts")]
    NoSuitableAccountOfRequestedTypeFoundException,

    /// Person should view Smart-ID app or Smart-ID self-service portal now
    #[error("Person should view Smart-ID app or Smart-ID self-service portal now")]
    PersonShouldViewSmartIdPortalException,

    /// User app version does not support any of the allowedInteractionsOrder interactions
    #[error("User app version does not support any of the allowedInteractionsOrder interactions")]
    RequiredInteractionNotSupportedByAppException,

    #[error("Interaction parameters are invalid: {0}")]
    InvalidInteractionParametersException(&'static str),

    /// User account not found
    #[error("User account not found")]
    UserAccountNotFoundException,

    /// Certificate Decryption error
    #[error("Certificate Decryption error")]
    DecryptionError,

    /// Failed to generate dynamic link
    #[error("Failed to generate dynamic link: {0}")]
    GenerateDynamicLinkException(&'static str),

    /// Invalid signature protocol
    #[error("Invalid signature protocol: {0}")]
    InvalidSignatureProtocal(&'static str),

    /// Failed to validate session response certificate
    #[error("Failed to validate session response certificate: {0}")]
    FailedToValidateSessionResponseCertificate(&'static str),
    
    /// User should view Smart-ID app or portal
    #[error("User should view Smart-ID app or portal")]
    UserShouldViewSmartIDAppOrPortalException,
}