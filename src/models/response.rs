use crate::error::{Result, SmartIdClientError};
use serde::{Deserialize, Serialize};

/// Represents the response from the Smart-ID API.
///
/// This enum can either be a success response containing the data of type `T`,
/// or an error response containing a `SmartIDErrorResponse`.
///
/// It allows you to easily handle receiving two completely different response structures from the API.
///
/// # Example
/// // We define a type for the response, which is a `SessionStatus`.
/// pub(crate) type SessionResponse = SmartIdAPIResponse<SessionStatus>;
/// // Get will now return a `SessionResponse` that contains either a `SessionStatus` or a `SmartIDErrorResponse`.
/// let session_response = get::<SessionResponse>("path".to_string(), None).await?;
/// // If the response was an error, this line will pass the error to the caller. Otherwise, it will assign the data to `session_status`.
///  let session_status = session_response.into_result()?;
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum SmartIdAPIResponse<T> {
    Success(T),
    Error(SmartIDErrorResponse),
}

impl<T> SmartIdAPIResponse<T> {
    /// Converts the `SmartIdAPIResponse` into a `Result<T>`.
    /// Read the documentation for `SmartIdAPIResponse` for more information.
    ///
    /// If the response is a success, it returns `Ok(T)`.
    /// If the response is an error, it maps the error response to the appropriate error and returns it.
    pub fn into_result(self) -> Result<T> {
        match self {
            SmartIdAPIResponse::Success(data) => Ok(data),
            SmartIdAPIResponse::Error(error) => match error.status {
                400 => Err(SmartIdClientError::BadRequestException),
                401 => Err(
                    SmartIdClientError::RelyingPartyAccountConfigurationException(
                        "Request is unauthorized",
                    ),
                ),
                403 => Err(
                    SmartIdClientError::RelyingPartyAccountConfigurationException(
                        "Request is forbidden",
                    ),
                ),
                404 => Err(SmartIdClientError::NotFoundException),
                471 => Err(SmartIdClientError::NoSuitableAccountOfRequestedTypeFoundException),
                472 => Err(SmartIdClientError::PersonShouldViewSmartIdPortalException),
                480 => Err(SmartIdClientError::ClientOutdatedException),
                580 => Err(SmartIdClientError::SystemIsUnderMaintenanceException),
                _ => Err(SmartIdClientError::SmartIDAPIException(format!(
                    "Unknown error: {}",
                    error.status
                ))),
            },
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SmartIDErrorResponse {
    #[serde(rename = "type")]
    pub error_type: String,
    pub title: String,
    pub status: i64,
    pub detail: String,
    // pub instance: Option<_>,
    // pub properties: Option<_>,
    pub code: i64,
    pub message: String,
}
