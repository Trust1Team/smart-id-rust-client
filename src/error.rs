use thiserror::Error;

pub type Result<T> = std::result::Result<T, SmartIdClientError>;

#[derive(Error, Debug)]
#[non_exhaustive]
#[allow(dead_code)]
pub enum SmartIdClientError {
    /// Config Exception
    #[error("Configuration missing: {0}")]
    ConfigMissingException(&'static str),

    ///RelyingPartyAccountConfigurationException
    #[error("Relying Party account configuration exception: {0}")]
    RelyingPartyAccountConfigurationException(&'static str),

    ///SmartIdClientException
    #[error("Smart ID client exception: {0}")]
    SmartIdClientException(&'static str),

    ///SmartIDAPIException
    #[error("Smart ID API Exception: {0}")]
    SmartIDAPIException(String),

    /// Session timed out without getting any response from user
    #[error("Session timed out without getting any response from user")]
    SessionTimeoutException,

    /// There is no running session
    #[error("There is no running session")]
    NoSessionException,

    /// Failed to get the running session
    #[error("Failed to get the running session")]
    GetSessionException,

    /// Failed to set the running session
    #[error("Failed to set the running session")]
    SetSessionException,

    /// Failed to get user identity
    #[error("Failed to get user identity")]
    GetUserIdentityException,

    /// Failed to set user identity
    #[error("Failed to set user identity")]
    SetUserIdentityException,

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

    /// Interaction parameters are invalid
    #[error("Interaction parameters are invalid: {0}")]
    InvalidInteractionParametersException(&'static str),

    /// Failed to generate dynamic link
    #[error("Failed to generate dynamic link: {0}")]
    GenerateDynamicLinkException(&'static str),

    /// Invalid signature protocol
    #[error("Invalid signature protocol: {0}")]
    InvalidSignatureProtocal(&'static str),

    /// Failed to validate session response certificate
    #[error("Failed to validate session response certificate: {0}")]
    FailedToValidateSessionResponseCertificate(&'static str),

    /// Digest is not in valid format
    #[error("Digest is not in valid format: {0}")]
    InvalidDigestException(&'static str),

    /// User should view Smart-ID app or portal
    #[error("User should view Smart-ID app or portal")]
    UserShouldViewSmartIDAppOrPortalException,

    /// Not found exception from Smart ID API
    #[error("Not found exception from Smart ID API")]
    NotFoundException,

    /// Bad request exception from Smart ID API
    #[error("Bad request exception from Smart ID API")]
    BadRequestException,

    /// Smart ID client is outdated
    #[error("Smart ID client is outdated")]
    ClientOutdatedException,

    /// Invalid semantic identifier
    #[error("Invalid semantic identifier: {0}")]
    InvalidSemanticIdentifierException(String),
}
