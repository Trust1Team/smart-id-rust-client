use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequestProperties {
    pub share_md_client_ip_address: bool,
}

#[derive(Default, Debug, Clone, PartialEq)]
pub(crate) struct SessionConfig {
    pub(crate) session_id: String,
    pub(crate) session_secret: String,
    pub(crate) session_token: String,
    pub(crate) session_start_time: DateTime<Utc>, // Used to calculated elapsed seconds since session start
}