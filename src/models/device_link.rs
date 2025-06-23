use crate::models::common::SchemeName;
use crate::models::signature::SignatureProtocol;
use base64::prelude::BASE64_URL_SAFE;
use base64::{alphabet, engine, engine::general_purpose, Engine as _};
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use strum_macros::{AsRefStr, Display};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, AsRefStr, Display)]
#[allow(non_camel_case_types)]
pub enum DeviceLinkType {
    QR,
    Web2App,
    App2App,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, AsRefStr, Display)]
#[allow(non_camel_case_types)]
pub enum SessionType {
    auth,
    sign,
    cert,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, AsRefStr, Display)]
pub(crate) enum DeviceLink {
    /// Represents a device link for the same device, i.e web2app or app2app.
    SameDeviceLink {
        // Device link parts
        device_link_base: String,
        device_link_type: DeviceLinkType,
        session_token: String,
        session_type: SessionType,
        version: String,
        language_code: String, // 3 letter language code according to ISO 639-2
        session_secret: String,

        // Auth code parts
        scheme_name: SchemeName,
        signature_protocol: Option<SignatureProtocol>,
        rp_challenge_or_digest: String,
        relying_party_name: String,
        brokered_rp_name: String,
        interactions: String,
        initial_callback_url: Option<String>,
    },
    /// Represents a device link for cross-device flows, i.e QR code.
    CrossDeviceLink {
        // Device link parts
        device_link_base: String,
        device_link_type: DeviceLinkType,
        session_start_time: DateTime<Utc>, // Used to calculated elapsed seconds since session start
        session_token: String,
        session_type: SessionType,
        version: String,
        language_code: String, // 3 letter language code according to ISO 639-2
        session_secret: String,

        // Auth code parts
        scheme_name: SchemeName,
        signature_protocol: Option<SignatureProtocol>,
        rp_challenge_or_digest: String,
        relying_party_name: String,
        brokered_rp_name: String,
        interactions: String,
        initial_callback_url: Option<String>,
    },
}

impl DeviceLink {
    pub fn generate_device_link(&self) -> String {
        match self {
            DeviceLink::SameDeviceLink {
                device_link_base,
                device_link_type,
                session_token,
                session_type,
                version,
                language_code,
                ..
            } => {
                let auth_code = self.generate_auth_code();
                format!("{}?deviceLinkType={}&sessionToken={}&sessionType={}&version={}&lang={}&authCode={}", device_link_base, device_link_type, session_token, session_type, version, language_code, auth_code).to_string()
            }
            DeviceLink::CrossDeviceLink {
                device_link_base,
                device_link_type,
                session_start_time,
                session_token,
                session_type,
                version,
                language_code,
                ..
            } => {
                let elapsed_seconds = self.elapsed_seconds(session_start_time);
                let auth_code = self.generate_auth_code();
                format!("{}?deviceLinkType={}&elapsedSeconds={}&sessionToken={}&sessionType={}&version={}&lang={}&authCode={}", device_link_base, device_link_type, elapsed_seconds, session_token, session_type, version, language_code, auth_code).to_string()
            }
        }
    }

    pub fn generate_unprotected_device_link(&self) -> String {
        match self {
            DeviceLink::SameDeviceLink {
                device_link_base,
                device_link_type,
                session_token,
                session_type,
                version,
                language_code,
                ..
            } => format!(
                "{}?deviceLinkType={}&sessionToken={}&sessionType={}&version={}&lang={}",
                device_link_base,
                device_link_type,
                session_token,
                session_type,
                version,
                language_code
            )
            .to_string(),
            DeviceLink::CrossDeviceLink {
                device_link_base,
                device_link_type,
                session_token,
                session_type,
                session_start_time,
                version,
                language_code,
                ..
            } => format!(
                "{}?deviceLinkType={}&elapsedSeconds={}&sessionToken={}&sessionType={}&version={}&lang={}",
                device_link_base,
                device_link_type,
                self.elapsed_seconds(session_start_time),
                session_token,
                session_type,
                version,
                language_code
            )
            .to_string(),
        }
    }

    /// Generate auth code payload for the device link.
    /// As described here https://sk-eid.github.io/smart-id-documentation/rp-api/authcode.html
    pub(crate) fn generate_auth_code_payload(&self) -> String {
        match self {
            DeviceLink::SameDeviceLink {
                scheme_name,
                signature_protocol,
                rp_challenge_or_digest,
                relying_party_name,
                brokered_rp_name,
                interactions,
                initial_callback_url,
                ..
            } => {
                let separator: &str = "|";
                let relying_party_name_base64: String = BASE64_URL_SAFE.encode(relying_party_name);
                let brokered_rp_name_base64: &str = &BASE64_URL_SAFE.encode(brokered_rp_name);
                let unprotected_device_link: String = self.generate_unprotected_device_link();
                let signature_protocol: String = signature_protocol
                    .as_ref()
                    .map(|s| s.as_ref().to_string())
                    .unwrap_or_else(|| SignatureProtocol::default().as_ref().to_string());

                let auth_code_payload_parts: [&str; 8] = [
                    scheme_name.as_ref(),
                    &signature_protocol,
                    rp_challenge_or_digest,
                    &relying_party_name_base64,
                    brokered_rp_name_base64,
                    interactions,
                    &initial_callback_url.clone().unwrap_or("".to_string()),
                    &unprotected_device_link,
                ];

                auth_code_payload_parts.join(separator)
            }
            DeviceLink::CrossDeviceLink {
                scheme_name,
                relying_party_name,
                brokered_rp_name,
                initial_callback_url,
                signature_protocol,
                rp_challenge_or_digest,
                interactions,
                ..
            } => {
                let separator: &str = "|";

                let signature_protocol: &str = signature_protocol
                    .as_ref()
                    .map(|s| s.as_ref())
                    .unwrap_or("");

                let relying_party_name_base64: &str = &BASE64_URL_SAFE.encode(relying_party_name);
                let brokered_rp_name_base64: &str = &BASE64_URL_SAFE.encode(brokered_rp_name);
                let unprotected_device_link: String = self.generate_unprotected_device_link();

                let auth_code_payload_parts: [&str; 8] = [
                    scheme_name.as_ref(),
                    signature_protocol,
                    rp_challenge_or_digest,
                    relying_party_name_base64,
                    brokered_rp_name_base64,
                    interactions,
                    &initial_callback_url.clone().unwrap_or("".to_string()),
                    &unprotected_device_link,
                ];

                auth_code_payload_parts.join(separator)
            }
        }
    }

    /// Generate auth code for the device link.
    /// As described here https://sk-eid.github.io/smart-id-documentation/rp-api/authcode.html
    /// Generate a HMAC SHA256 code for the session
    /// As described here https://sk-eid.github.io/smart-id-documentation/rp-api/device_link_flows.html
    pub(crate) fn generate_auth_code(&self) -> String {
        let session_secret: &[u8] = &general_purpose::STANDARD
            .decode(self.session_secret())
            .unwrap();
        let auth_code_payload: String = self.generate_auth_code_payload();

        let mut mac =
            Hmac::<Sha256>::new_from_slice(session_secret).expect("HMAC can take key of any size");
        mac.update(auth_code_payload.as_bytes());

        let auth_code_bytes = mac.finalize().into_bytes();

        const CUSTOM_ENGINE: engine::GeneralPurpose =
            engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);
        let auth_code: String = CUSTOM_ENGINE.encode(auth_code_bytes);

        auth_code
    }

    fn elapsed_seconds(&self, from: &DateTime<Utc>) -> i64 {
        let now = Utc::now();
        let duration = now.signed_duration_since(from);
        duration.num_seconds()
    }

    fn session_secret(&self) -> &str {
        match self {
            DeviceLink::SameDeviceLink { session_secret, .. } => session_secret,
            DeviceLink::CrossDeviceLink { session_secret, .. } => session_secret,
        }
    }
}

// region: Device Link Tests
#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::device_link::DeviceLink::{CrossDeviceLink, SameDeviceLink};
    use crate::models::signature::SignatureProtocol::ACSP_V2;
    use tracing_test::traced_test;

    // Created using outputs from the web link generator https://sk-eid.github.io/smart-id-documentation/rp-api/authcode.html
    #[traced_test]
    #[tokio::test]
    async fn authentication_qr_device_link_auth_code_generation() {
        let device_link = SameDeviceLink {
            device_link_base: "https://smart-id.com".to_string(),
            version: "1.0".to_string(),
            session_token: "sessionToken".to_string(),
            session_secret: "rG/kLmfR4j4SEO+TTNUEDB7z".to_string(),
            scheme_name: SchemeName::smart_id_demo,
            relying_party_name: "RELYING_PARTY_NAME".to_string(),
            brokered_rp_name: "".to_string(),
            device_link_type: DeviceLinkType::QR,
            session_type: SessionType::auth,
            language_code: "eng".to_string(),
            initial_callback_url: Some("https://example.com/smart-id/callback".to_string()),
            signature_protocol: Some(ACSP_V2),
            rp_challenge_or_digest: "zv++eYQ9JGnEwd3TLpzw/5pJqQQ+zhjp0kFaJfk0f39TW89wOPRUj9PX7rITfKUWQq367RGo/91Q46WNrGRLrg==".to_string(),
            interactions: "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IlRFU1QgMSJ9XQ==".to_string(),
        };

        let unprotected_link = device_link.generate_unprotected_device_link();
        assert_eq!(unprotected_link, "https://smart-id.com?deviceLinkType=QR&sessionToken=sessionToken&sessionType=auth&version=1.0&lang=eng");

        let auth_code_payload = device_link.generate_auth_code_payload();
        assert_eq!(auth_code_payload, "smart-id-demo|ACSP_V2|zv++eYQ9JGnEwd3TLpzw/5pJqQQ+zhjp0kFaJfk0f39TW89wOPRUj9PX7rITfKUWQq367RGo/91Q46WNrGRLrg==|REVNTyBUcnVzdDE=||W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IlRFU1QgMSJ9XQ==|https://example.com/smart-id/callback|https://smart-id.com?deviceLinkType=QR&sessionToken=sessionToken&sessionType=auth&version=1.0&lang=eng");

        let auth_code = device_link.generate_auth_code();
        assert_eq!(auth_code, "yEbrTnbQ1AmnwnwGT1BGTNjvX2er1Hvun-zsWR9UwS4");
    }

    #[traced_test]
    #[tokio::test]
    async fn authentication_qr_device_link_auth_code_generation_with_real_params() {
        use crate::models::common::SchemeName;

        let device_link = CrossDeviceLink {
            device_link_base: "https://sid.demo.sk.ee/device-link".to_string(),
            version: "1.0".to_string(),
            session_token: "UhZj7BX4XWp6ZPQwI29ZoT6o".to_string(),
            session_secret: "qCej5K5F+ADc+U665zkP0bi9".to_string(),
            scheme_name: SchemeName::smart_id_demo,
            relying_party_name: "RELYING_PARTY_NAME".to_string(),
            brokered_rp_name: "".to_string(),
            device_link_type: DeviceLinkType::QR,
            session_type: SessionType::auth,
            language_code: "eng".to_string(),
            initial_callback_url: None,
            signature_protocol: Some(ACSP_V2),
            rp_challenge_or_digest: "FtKbl73BUkdTFvBvoz+Xg4thbS71WHBYIM7ukj8mykEns4hMWPaXeFN8nfEYwgexuJw9YIOYlqSLFyZBYAnEqw==".to_string(),
            interactions: "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IlRFU1QgMSJ9XQ==".to_string(),
            session_start_time: Utc::now(),
        };

        let unprotected_link = device_link.generate_unprotected_device_link();
        assert_eq!(
            unprotected_link,
            "https://sid.demo.sk.ee/device-link?deviceLinkType=QR&elapsedSeconds=0&sessionToken=UhZj7BX4XWp6ZPQwI29ZoT6o&sessionType=auth&version=1.0&lang=eng"
        );

        let auth_code_payload = device_link.generate_auth_code_payload();
        assert_eq!(
            auth_code_payload,
            "smart-id-demo|ACSP_V2|FtKbl73BUkdTFvBvoz+Xg4thbS71WHBYIM7ukj8mykEns4hMWPaXeFN8nfEYwgexuJw9YIOYlqSLFyZBYAnEqw==|REVNTyBUcnVzdDE=||W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IlRFU1QgMSJ9XQ==||https://sid.demo.sk.ee/device-link?deviceLinkType=QR&elapsedSeconds=0&sessionToken=UhZj7BX4XWp6ZPQwI29ZoT6o&sessionType=auth&version=1.0&lang=eng"
        );

        let auth_code = device_link.generate_auth_code();
        assert_eq!(auth_code, "Ecjsq9F38hNxP3diXalFtFFXcEklMKQUQpI7nMLre2M");
    }

    #[traced_test]
    #[tokio::test]
    async fn authentication_qr_device_link_link_generation() {
        let device_link = CrossDeviceLink {
            device_link_base: "https://smart-id.com/device-link".to_string(),
            version: "1.0".to_string(),
            session_token: "tw1hOWNAcw0wd-e9OalXV-Sr".to_string(),
            session_secret: "rG/kLmfR4j4SEO+TTNUEDB7z".to_string(),
            scheme_name: SchemeName::smart_id_demo,
            signature_protocol: Some(ACSP_V2),
            rp_challenge_or_digest: "zv++eYQ9JGnEwd3TLpzw/5pJqQQ+zhjp0kFaJfk0f39TW89wOPRUj9PX7rITfKUWQq367RGo/91Q46WNrGRLrg==".to_string(),
            relying_party_name: "RELYING_PARTY_NAME".to_string(),
            brokered_rp_name: "".to_string(),
            device_link_type: DeviceLinkType::QR,
            session_type: SessionType::auth,
            language_code: "eng".to_string(),
            initial_callback_url: Some("https://example.com/smart-id/callback".to_string()),
            session_start_time: Utc::now(),
            interactions: "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IlRFU1QgMSJ9XQ==".to_string(),
        };

        let link = device_link.generate_device_link();

        assert_eq!(link.split_at(143).0, "https://smart-id.com/device-link?deviceLinkType=QR&elapsedSeconds=0&sessionToken=tw1hOWNAcw0wd-e9OalXV-Sr&sessionType=auth&version=1.0&lang=eng");
    }

    #[traced_test]
    #[tokio::test]
    async fn unprotected_link_qr_auth() {
        let device_link = CrossDeviceLink {
            device_link_base: "https://smart-id.com/device-link".to_string(),
            version: "1.0".to_string(),
            session_token: "tw1hOWNAcw0wd-e9OalXV-Sr".to_string(),
            session_secret: "qKzzHX6SG0ovfEdMuDEzCgTu".to_string(),
            scheme_name: SchemeName::smart_id,
            signature_protocol: Some(ACSP_V2),
            rp_challenge_or_digest: "zv++eYQ9JGnEwd3TLpzw/5pJqQQ+zhjp0kFaJfk0f39TW89wOPRUj9PX7rITfKUWQq367RGo/91Q46WNrGRLrg==".to_string(),
            relying_party_name: "DEMO 1".to_string(),
            brokered_rp_name: "".to_string(),
            device_link_type: DeviceLinkType::QR,
            session_type: SessionType::auth,
            session_start_time: Utc::now(),
            language_code: "eng".to_string(),
            initial_callback_url: Some("https://example.com".to_string()),
            interactions: "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IlRFU1QgMSJ9XQ==".to_string(),
        };

        let unprotected_link = device_link.generate_unprotected_device_link();

        assert_eq!(unprotected_link, "https://smart-id.com/device-link?deviceLinkType=QR&elapsedSeconds=0&sessionToken=tw1hOWNAcw0wd-e9OalXV-Sr&sessionType=auth&version=1.0&lang=eng");
    }

    #[traced_test]
    #[tokio::test]
    async fn unprotected_link_qr_signature() {
        let device_link = CrossDeviceLink {
            device_link_base: "https://smart-id.com/device-link".to_string(),
            version: "1.0".to_string(),
            session_token: "tw1hOWNAcw0wd-e9OalXV-Sr".to_string(),
            session_secret: "qKzzHX6SG0ovfEdMuDEzCgTu".to_string(),
            scheme_name: SchemeName::smart_id,
            signature_protocol: Some(ACSP_V2),
            rp_challenge_or_digest: "zv++eYQ9JGnEwd3TLpzw/5pJqQQ+zhjp0kFaJfk0f39TW89wOPRUj9PX7rITfKUWQq367RGo/91Q46WNrGRLrg==".to_string(),
            relying_party_name: "DEMO 1".to_string(),
            brokered_rp_name: "".to_string(),
            device_link_type: DeviceLinkType::QR,
            session_type: SessionType::sign,
            session_start_time: Utc::now(),
            language_code: "eng".to_string(),
            initial_callback_url: Some("https://example.com".to_string()),
            interactions: "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IlRFU1QgMSJ9XQ==".to_string(),
        };

        let unprotected_link = device_link.generate_unprotected_device_link();

        assert_eq!(unprotected_link, "https://smart-id.com/device-link?deviceLinkType=QR&elapsedSeconds=0&sessionToken=tw1hOWNAcw0wd-e9OalXV-Sr&sessionType=sign&version=1.0&lang=eng");
    }

    #[traced_test]
    #[tokio::test]
    async fn unprotected_link_qr_cert() {
        let device_link = CrossDeviceLink {
            device_link_base: "https://smart-id.com/device-link".to_string(),
            version: "1.0".to_string(),
            session_token: "tw1hOWNAcw0wd-e9OalXV-Sr".to_string(),
            session_secret: "qKzzHX6SG0ovfEdMuDEzCgTu".to_string(),
            scheme_name: SchemeName::smart_id,
            signature_protocol: Some(ACSP_V2),
            rp_challenge_or_digest: "zv++eYQ9JGnEwd3TLpzw/5pJqQQ+zhjp0kFaJfk0f39TW89wOPRUj9PX7rITfKUWQq367RGo/91Q46WNrGRLrg==".to_string(),
            relying_party_name: "DEMO 1".to_string(),
            brokered_rp_name: "".to_string(),
            device_link_type: DeviceLinkType::QR,
            session_type: SessionType::cert,
            session_start_time: Utc::now(),
            language_code: "eng".to_string(),
            initial_callback_url: Some("https://example.com".to_string()),
            interactions: "W3sidHlwZSI6ImNvbmZpcm1hdGlvbk1lc3NhZ2UiLCJkaXNwbGF5VGV4dDIwMCI6IlRFU1QgMSJ9XQ==".to_string(),
        };

        let unprotected_link = device_link.generate_unprotected_device_link();

        assert_eq!(unprotected_link, "https://smart-id.com/device-link?deviceLinkType=QR&elapsedSeconds=0&sessionToken=tw1hOWNAcw0wd-e9OalXV-Sr&sessionType=cert&version=1.0&lang=eng");
    }
}

// endregion: Device Link Tests
