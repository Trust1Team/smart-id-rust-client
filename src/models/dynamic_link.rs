use base64::prelude::{BASE64_STANDARD, BASE64_URL_SAFE};
use base64::Engine;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub enum DynamicLinkType {
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
pub(crate) struct DynamicLink {
    pub(crate) url: String,
    pub(crate) version: String,
    pub(crate) session_token: String,
    pub(crate) session_secret: String,
    pub(crate) dynamic_link_type: DynamicLinkType,
    pub(crate) session_type: SessionType,
    pub(crate) session_start_time: DateTime<Utc>, // Used to calculated elapsed seconds since session start
    pub(crate) language_code: String,             // 3 letter language code according to ISO 639-2
}

impl DynamicLink {
    pub(crate) fn payload(&self) -> String {
        let link = format!(
            "{:?}.{:?}.{}",
            self.dynamic_link_type.clone(),
            self.session_type.clone(),
            self.elapsed_seconds()
        );
        link
    }

    pub fn generate_dynamic_link(&self) -> String {
        format!(
            "{}?version={}&sessionToken={}&dynamicLinkType={:?}&sessionType={:?}&elapsedSeconds={}&lang={}&authCode={}",
            self.url.clone(),
            self.version.clone(),
            self.session_token.clone(),
            self.dynamic_link_type.clone(),
            self.session_type.clone(),
            self.elapsed_seconds(),
            self.language_code,
            self.generate_auth_code(),
        )
    }

    /// Generate a HMAC SHA256 code for the session
    /// As described here https://sk-eid.github.io/smart-id-documentation/rp-api/3.0.2/dynamic_link_flows.html#_dynamic_link_calculation
    pub(crate) fn generate_auth_code(&self) -> String {
        let secret = BASE64_STANDARD.decode(self.session_secret.clone()).expect("Failed to decode session secret");
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

// region: Dynamic Link Tests
#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use tracing_test::traced_test;

    fn qr_dynamic_link() -> DynamicLink {
        DynamicLink {
            url: "https://sid.demo.sk.ee/dynamic-link/".to_string(),
            version: "0.1".to_string(),
            session_token: "sessionToken".to_string(),
            session_secret: "sessionSecret".to_string(),
            dynamic_link_type: DynamicLinkType::QR,
            session_type: SessionType::auth,
            session_start_time: Utc::now(),
            language_code: "eng".to_string(),
        }
    }

    #[traced_test]
    #[tokio::test]
    async fn test_payload_generation() {
        let dynamic_link = qr_dynamic_link();
        assert_eq!(dynamic_link.payload(), "QR.auth.0");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_payload_generation_elapsed_seconds() {
        let dynamic_link = DynamicLink {
            session_start_time: Utc::now() - Duration::seconds(20),
            ..qr_dynamic_link()
        };

        assert_eq!(dynamic_link.payload(), "QR.auth.20");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_generate_auth_code() {
        let dynamic_link = DynamicLink {
            session_secret: "ZspUAbC9eWgT3OXEu+vMyvUA".to_string(),
            dynamic_link_type: DynamicLinkType::QR,
            session_type: SessionType::auth,
            ..qr_dynamic_link()
        };

        println!("{:?}", dynamic_link.generate_dynamic_link());
        assert_eq!(
            dynamic_link.generate_auth_code(),
            "WTtkXm95Hz1tImwoH96hfy8WjM2lAFg6P7d-B9Z73Ss="
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_generate_auth_code_elapsed_seconds() {
        let dynamic_link = DynamicLink {
            session_start_time: Utc::now() - Duration::seconds(20),
            ..qr_dynamic_link()
        };
        assert_eq!(
            dynamic_link.generate_auth_code(),
            "zQR5yqKtjlrxXVhAEsijUBhVnT7RlHgch26MB5beprQ="
        );
    }

    #[traced_test]
    #[tokio::test]
    async fn test_generate_qr_code_url() {
        let dynamic_link = qr_dynamic_link();
        assert_eq!(dynamic_link.generate_dynamic_link(), "https://sid.demo.sk.ee/dynamic-link/?version=0.1&sessionToken=sessionToken&dynamicLinkType=QR&sessionType=auth&elapsedSeconds=0&lang=eng&authCode=Up2D2TKv9Bm7xnaHm2+/0TKTpCQwNJNlto0r2opNmZo=");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_generate_web1app_url() {
        let dynamic_link = DynamicLink {
            dynamic_link_type: DynamicLinkType::Web2App,
            ..qr_dynamic_link()
        };
        assert_eq!(dynamic_link.generate_dynamic_link(), "https://sid.demo.sk.ee/dynamic-link/?version=0.1&sessionToken=sessionToken&dynamicLinkType=Web2App&sessionType=auth&elapsedSeconds=0&lang=eng&authCode=NIzRld8sfsiG41kunWZMTv8II5dXf/g9pVwzQmFmSmA=");
    }
}

// endregion: Dynamic Link Tests
