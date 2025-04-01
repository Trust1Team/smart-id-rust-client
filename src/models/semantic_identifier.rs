use crate::error::Result;
use crate::error::SmartIdClientError;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::str::FromStr;
use strum_macros::{Display, EnumString};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SemanticsIdentifier {
    pub identity_type: IdentityType,
    pub country_code: CountryCode,
    pub identity_number: String,
}

impl SemanticsIdentifier {
    pub fn new(
        identity_type: IdentityType,
        country_code: CountryCode,
        identity_number: String,
    ) -> Self {
        SemanticsIdentifier {
            identity_type,
            country_code,
            identity_number,
        }
    }

    pub fn new_from_string(
        identity_type: String,
        country_code: String,
        identity_number: String,
    ) -> Result<Self> {
        Ok(SemanticsIdentifier {
            identity_type: IdentityType::from_str(identity_type.to_uppercase().as_str()).map_err(
                |e| SmartIdClientError::InvalidSemanticIdentifierException(e.to_string()),
            )?,
            country_code: CountryCode::from_str(country_code.to_uppercase().as_str()).map_err(
                |e| SmartIdClientError::InvalidSemanticIdentifierException(e.to_string()),
            )?,
            identity_number,
        })
    }

    pub fn identifier(&self) -> String {
        format!(
            "{}{}-{}",
            self.identity_type.clone(),
            self.country_code.clone(),
            self.identity_number.clone(),
        )
    }
}

impl Display for SemanticsIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.identifier())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[strum(serialize_all = "UPPERCASE")]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum IdentityType {
    PAS,
    IDC,
    PNO,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, EnumString, Display)]
#[strum(serialize_all = "UPPERCASE")]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum CountryCode {
    EE,
    LT,
    LV,
    BE,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let identifier =
            SemanticsIdentifier::new(IdentityType::PAS, CountryCode::EE, "1234567890".to_string());
        assert_eq!(identifier.identifier(), "PASEE-1234567890");
    }

    #[test]
    fn test_new_from_string() {
        let identifier = SemanticsIdentifier::new_from_string(
            "PAS".to_string(),
            "EE".to_string(),
            "1234567890".to_string(),
        )
        .unwrap();
        assert_eq!(identifier.identifier(), "PASEE-1234567890");
    }

    #[test]
    fn test_new_from_string_mixed_case() {
        let identifier = SemanticsIdentifier::new_from_string(
            "Pas".to_string(),
            "Ee".to_string(),
            "1234567890".to_string(),
        )
        .unwrap();
        assert_eq!(identifier.identifier(), "PASEE-1234567890");
    }
}
