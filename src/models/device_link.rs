use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE};
use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum DeviceLinkType {
    QR,
    Web2App,
    App2App,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum SessionType {
    auth,
    sign,
    certificateChoice,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DeviceLink {
    pub(crate) url: String,
    pub(crate) version: String,
    pub(crate) session_token: String,
    pub(crate) session_secret: String,
    pub(crate) device_link_type: DeviceLinkType,
    pub(crate) session_type: SessionType,
    pub(crate) session_start_time: DateTime<Utc>, // Used to calculated elapsed seconds since session start
    pub(crate) language_code: String,             // 3 letter language code according to ISO 639-2
}

impl DeviceLink {
    pub(crate) fn payload(&self) -> String {
        let link = format!(
            "{:?}.{:?}.{}",
            self.device_link_type.clone(),
            self.session_type.clone(),
            self.elapsed_seconds()
        );
        link
    }

    pub fn generate_device_link(&self) -> String {
        format!(
            "{}?version={}&sessionToken={}&deviceLinkType={:?}&sessionType={:?}&elapsedSeconds={}&lang={}&authCode={}",
            self.url.clone(),
            self.version.clone(),
            self.session_token.clone(),
            self.device_link_type.clone(),
            self.session_type.clone(),
            self.elapsed_seconds(),
            self.language_code,
            self.generate_auth_code(),  
        )
    }

    /// Generate a HMAC SHA256 code for the session
    /// As described here https://sk-eid.github.io/smart-id-documentation/rp-api/device_link_flows.html
    pub(crate) fn generate_auth_code(&self) -> String {
        let secret = BASE64_STANDARD
            .decode(self.session_secret.clone())
            .expect("Failed to decode session secret");
        let payload = self.payload();

        let mut mac =
            HmacSha256::new_from_slice(secret.as_slice()).expect("HMAC can take key of any size");
        mac.update(payload.as_bytes());

        let result = mac.finalize();
        let code_bytes = result.into_bytes();

        BASE64_URL_SAFE.encode(code_bytes)
    }

    fn elapsed_seconds(&self) -> i64 {
        let now = Utc::now();
        let duration = now.signed_duration_since(self.session_start_time);
        duration.num_seconds()
    }
}

// region: Device Link Tests
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use tracing_test::traced_test;

    fn qr_device_link() -> DeviceLink {
        DeviceLink {
            url: "https://sid.demo.sk.ee/device-link".to_string(),
            version: "0.1".to_string(),
            session_token: "sessionToken".to_string(),
            session_secret: "qKzzHX6SG0ovfEdMuDEzCgTu".to_string(),
            device_link_type: DeviceLinkType::QR,
            session_type: SessionType::auth,
            session_start_time: Utc::now(),
            language_code: "eng".to_string(),
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_payload_generation() {
        let device_link = qr_device_link();
        assert_eq!(device_link.payload(), "QR.auth.0");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_payload_generation_elapsed_seconds() {
        let device_link = DeviceLink {
            session_start_time: Utc::now() - Duration::seconds(20),
            ..qr_device_link()
        };

        assert_eq!(device_link.payload(), "QR.auth.20");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_generate_auth_code() {
        let device_link = DeviceLink {
            session_secret: "ZspUAbC9eWgT3OXEu+vMyvUA".to_string(),
            device_link_type: DeviceLinkType::QR,
            session_type: SessionType::auth,
            ..qr_device_link()
        };

        println!("{:?}", device_link.generate_device_link());
        assert_eq!(
            device_link.generate_auth_code(),
            "WTtkXm95Hz1tImwoH96hfy8WjM2lAFg6P7d-B9Z73Ss="
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_generate_auth_code_elapsed_seconds() {
        let device_link = DeviceLink {
            session_start_time: Utc::now() - Duration::seconds(20),
            ..qr_device_link()
        };
        assert_eq!(
            device_link.generate_auth_code(),
            "IoJzCv6p28yRiOmKFlxFkCINPCXbhkiJWq7zWiaE580="
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_generate_qr_code_url() {
        let device_link = qr_device_link();
        assert_eq!(device_link.generate_device_link(), "https://sid.demo.sk.ee/device-link?version=0.1&sessionToken=sessionToken&deviceLinkType=QR&sessionType=auth&elapsedSeconds=0&lang=eng&authCode=E4xBQkwfmyspaZAfJoY5Pdz6-bAWytBe-wyiX3SQS5o=");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_generate_web2app_url() {
        let device_link = DeviceLink {
            device_link_type: DeviceLinkType::Web2App,
            ..qr_device_link()
        };
        assert_eq!(device_link.generate_device_link(), "https://sid.demo.sk.ee/device-link?version=0.1&sessionToken=sessionToken&deviceLinkType=Web2App&sessionType=auth&elapsedSeconds=0&lang=eng&authCode=ofcBeca9ATRjdO5Dr17RRvGnamYA5s5C3rmKXyuDN4g=");
    }
}

// endregion: Device Link Tests
