use serde::{Deserialize, Serialize};
use x509_parser::prelude::{FromDer};
use base64::{Engine as _};
use anyhow::Result;
use crate::models::requests::InteractionFlow;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum Capability {
    QUALIFIED,
    ADVANCED,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum CertificateLevel {
    QUALIFIED,
    ADVANCED,
    QSCD
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum ResultState {
    OK,
    USER_REFUSED,
    TIMEOUT,
    DOCUMENT_UNUSABLE,
    WRONG_VC,
    REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP,
    USER_REFUSED_CERT_CHOICE,
    USER_REFUSED_DISPLAYTEXTANDPIN,
    USER_REFUSED_VC_CHOICE,
    USER_REFUSED_CONFIRMATIONMESSAGE,
    USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE,
    UNKNOWN,
}

impl From<String> for ResultState {
    fn from(value: String) -> Self {
        match value.to_uppercase().as_str() {
            "OK" => ResultState::OK,
            "USER_REFUSED" => ResultState::USER_REFUSED,
            "TIMEOUT" => ResultState::TIMEOUT,
            "DOCUMENT_UNUSABLE" => ResultState::DOCUMENT_UNUSABLE,
            "WRONG_VC" => ResultState::WRONG_VC,
            "REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP" => ResultState::REQUIRED_INTERACTION_NOT_SUPPORTED_BY_APP,
            "USER_REFUSED_CERT_CHOICE" => ResultState::USER_REFUSED_CERT_CHOICE,
            "USER_REFUSED_DISPLAYTEXTANDPIN" => ResultState::USER_REFUSED_DISPLAYTEXTANDPIN,
            "USER_REFUSED_VC_CHOICE" => ResultState::USER_REFUSED_VC_CHOICE,
            "USER_REFUSED_CONFIRMATIONMESSAGE" => ResultState::USER_REFUSED_CONFIRMATIONMESSAGE,
            "USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE" => ResultState::USER_REFUSED_CONFIRMATIONMESSAGE_WITH_VC_CHOICE,
            _ => ResultState::UNKNOWN,
        }
    }
}


#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum HashType {
    SHA256,
    SHA384,
    SHA512
}

impl From<String> for CertificateLevel {
    fn from(value: String) -> Self {
        match value.to_uppercase().as_str() {
            "QUALIFIED" => CertificateLevel::QUALIFIED,
            "ADVANCED" => CertificateLevel::ADVANCED,
            "QSCD" => CertificateLevel::QSCD,
            _ => CertificateLevel::QUALIFIED
        }
    }
}

impl From<CertificateLevel> for String {
    fn from(value: CertificateLevel) -> Self {
        format!("{:?}", value).to_uppercase()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum IdentityType {
    PAS,
    IDC,
    PNO
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum CountryCode {
    EE, LT, LV, BE
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticsIdentifier {
    pub identifier: String,
}

impl SemanticsIdentifier {
    pub fn new_from_string(identity_type: impl Into<String>, country_code: impl Into<String>, identity_number: impl Into<String>) -> Self {
        SemanticsIdentifier { identifier: format!("{}{}-{}", identity_type.into(), country_code.into(), identity_number.into()) }
    }

    pub fn new_from_enum(identity_type: IdentityType, country_code: CountryCode, identity_number: impl Into<String>) -> Self {
        SemanticsIdentifier { identifier: format!("{:?}{:?}-{}", identity_type, country_code, identity_number.into()) }
    }

    pub fn new_from_string_mock(identity_type: impl Into<String>, country_code: impl Into<String>) -> Self {
        SemanticsIdentifier { identifier: format!("{}{}-{}-MOCK-Q", identity_type.into(), country_code.into(), "00010299944") }
    }

    pub fn new_from_enum_mock(identity_type: IdentityType, country_code: CountryCode) -> Self {
        SemanticsIdentifier { identifier: format!("{:?}{:?}-{}-MOCK-Q", identity_type, country_code, "00010299944") }
    }
}


#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Interaction {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "type")]
    pub interaction_flow: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "displayText60")]
    pub display_text_60: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "displayText200")]
    pub display_text_200: Option<String>,
}

impl Interaction {
    pub fn new(interaction_flow: Option<InteractionFlow>, display_text_60: Option<String>, display_text_200: Option<String>) -> Self {
        Interaction {
            interaction_flow: interaction_flow.map(|x| x.into()),
            display_text_60,
            display_text_200,
        }
    }

    pub fn diplay_text_and_pin(display_text_60: impl Into<String>) -> Self {
        Interaction {
            interaction_flow: Some(InteractionFlow::DISPLAY_TEXT_AND_PIN.into()),
            display_text_60: Some(display_text_60.into()),
            display_text_200: None,
        }
    }

    pub fn verification_code_choice(display_text_60: impl Into<String>) -> Self {
        Interaction {
            interaction_flow: Some(InteractionFlow::VERIFICATION_CODE_CHOICE.into()),
            display_text_60: Some(display_text_60.into()),
            display_text_200: None,
        }
    }

    pub fn confirmation_message(display_text_200: impl Into<String>) -> Self {
        Interaction {
            interaction_flow: Some(InteractionFlow::CONFIRMATION_MESSAGE.into()),
            display_text_60: None,
            display_text_200: Some(display_text_200.into()),
        }
    }

    pub fn confirmation_message_and_verification_code_choice(display_text_200: impl Into<String>) -> Self {
        Interaction {
            interaction_flow: Some(InteractionFlow::CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE.into()),
            display_text_60: None,
            display_text_200: Some(display_text_200.into()),
        }
    }

    pub fn validate_display_text60(&self) -> Result<()> {

        match &self.interaction_flow {
            None => Ok(()),
            Some(inter_f) => {
                let inter_f_typed = InteractionFlow::from(inter_f.clone());
                if inter_f_typed.eq(&InteractionFlow::VERIFICATION_CODE_CHOICE) || inter_f_typed.eq(&InteractionFlow::DISPLAY_TEXT_AND_PIN) {
                    let display_text_60 = self.display_text_60.clone();
                    let display_text_200 = self.display_text_200.clone();
                    if display_text_60.is_none() {
                        return Err(anyhow::anyhow!(format!("displayText60 cannot be null for AllowedInteractionOrder of type {:?}", inter_f_typed.clone())));
                    };
                    if display_text_60.is_some() && display_text_60.unwrap().clone().len() > 60 {
                        return Err(anyhow::anyhow!("displayText60 must not be longer than 60 characters"));
                    };
                    if display_text_200.is_some() {
                        return Err(anyhow::anyhow!(format!("displayText200 must be null for AllowedInteractionOrder of type {:?}", inter_f_typed.clone())));
                    };
                }
                Ok(())
            }
        }
    }

    pub fn validate_display_text200(&self) -> Result<()> {
        match &self.interaction_flow {
            None => Ok(()),
            Some(inter_f) => {
                let inter_f_typed = InteractionFlow::from(inter_f.clone());
                if inter_f_typed.eq(&InteractionFlow::CONFIRMATION_MESSAGE) || inter_f_typed.eq(&InteractionFlow::CONFIRMATION_MESSAGE_AND_VERIFICATION_CODE_CHOICE) {
                    let display_text_60 = self.display_text_60.clone();
                    let display_text_200 = self.display_text_200.clone();
                    if display_text_200.is_none() {
                        return Err(anyhow::anyhow!(format!("displayText200 cannot be null for AllowedInteractionOrder of type {:?}", inter_f_typed.clone())));
                    };
                    if display_text_200.is_some() && display_text_200.unwrap().clone().len() > 200 {
                        return Err(anyhow::anyhow!("displayText200 must not be longer than 200 characters"));
                    };
                    if display_text_60.is_some() {
                        return Err(anyhow::anyhow!(format!("displayText60 must be null for AllowedInteractionOrder of type {:?}", inter_f_typed.clone())));
                    };
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing::{error, info};
    use tracing_test::traced_test;
    use crate::models::requests::InteractionFlow;

    #[traced_test]
    #[tokio::test]
    async fn test_semantics_id_construct_by_string() {
        let sem_id = SemanticsIdentifier::new_from_string("PNO", "BE", "123456789");
        assert_eq!(sem_id.identifier, "PNOBE-123456789");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_semantics_id_construct_by_enum() {
        let sem_id = SemanticsIdentifier::new_from_enum(IdentityType::PNO, CountryCode::BE, "123456789");
        assert_eq!(sem_id.identifier, "PNOBE-123456789");
    }

    #[traced_test]
    #[tokio::test]
    async fn test_resolve_certificate_level_string_value() {
        let cert_level: CertificateLevel = CertificateLevel::QUALIFIED;
        assert_eq!(String::from(cert_level), "QUALIFIED");
    }
}
