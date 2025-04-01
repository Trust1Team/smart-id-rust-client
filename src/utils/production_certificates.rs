// Production certificates
const EID_SK: &str = include_str!("../../certs/production/intermediate/EID-SK.pem.crt");
const EID_SK_2007: &str = include_str!("../../certs/production/intermediate/EID-SK_2007.pem.crt");
const EID_SK_2011: &str = include_str!("../../certs/production/intermediate/EID-SK_2011.pem.crt");
const EID_SK_2016: &str = include_str!("../../certs/production/intermediate/EID-SK_2016.pem.crt");
const EID_NQ_2021E: &str = include_str!("../../certs/production/intermediate/EID_NQ_2021E.pem.crt");
const EID_NQ_2021R: &str = include_str!("../../certs/production/intermediate/EID_NQ_2021R.pem.crt");
const EID_Q_2021E: &str = include_str!("../../certs/production/intermediate/EID_Q_2021E.pem.crt");
const EID_Q_2021R: &str = include_str!("../../certs/production/intermediate/EID_Q_2021R.pem.crt");
const EID_Q_2024E: &str = include_str!("../../certs/production/intermediate/EID_Q_2024E.pem.crt");
const EID_Q_2024R: &str = include_str!("../../certs/production/intermediate/EID_Q_2024R.pem.crt");
const ESTEID2018: &str = include_str!("../../certs/production/intermediate/esteid2018.pem.crt");
const ESTEID_SK: &str = include_str!("../../certs/production/intermediate/ESTEID-SK.pem.crt");
const ESTEID_SK_2007: &str =
    include_str!("../../certs/production/intermediate/ESTEID-SK_2007.pem.crt");
const ESTEID_SK_2011: &str =
    include_str!("../../certs/production/intermediate/ESTEID-SK_2011.pem.crt");
const ESTEID_SK_2015: &str =
    include_str!("../../certs/production/intermediate/ESTEID-SK_2015.pem.crt");
const KLASS3_SK: &str = include_str!("../../certs/production/intermediate/KLASS3-SK.pem.crt");
const KLASS3_SK_2010: &str =
    include_str!("../../certs/production/intermediate/KLASS3-SK_2010.pem.crt");
const KLASS3_SK_2010_EECCRCA: &str =
    include_str!("../../certs/production/intermediate/KLASS3-SK_2010_EECCRCA.pem.crt");
const KLASS3_SK_2010_EECCRCA_SHA384: &str =
    include_str!("../../certs/production/intermediate/KLASS3-SK_2010_EECCRCA_SHA384.pem.crt");
const KLASS3_SK_2016_EECCRCA_SHA384: &str =
    include_str!("../../certs/production/intermediate/KLASS3-SK_2016_EECCRCA_SHA384.pem.crt");
const NQ_SK_2016: &str = include_str!("../../certs/production/intermediate/NQ-SK_2016.pem.crt");
const ORG_2021E: &str = include_str!("../../certs/production/intermediate/ORG_2021E.pem.crt");
const ORG_2021R: &str = include_str!("../../certs/production/intermediate/ORG_2021R.pem.crt");

const EE_GOVCA2018: &str = include_str!("../../certs/production/root/EE-GovCA2018.pem.crt");
const EE_CERTIFICATION_CENTRE_ROOT_CA: &str =
    include_str!("../../certs/production/root/EE_Certification_Centre_Root_CA.pem.crt");
const JUUR_SK: &str = include_str!("../../certs/production/root/Juur-SK.pem.crt");
const SK_ID_SOLUTIONS_ROOT_G1E: &str =
    include_str!("../../certs/production/root/SK_ID_Solutions_ROOT_G1E.pem.crt");
const SK_ID_SOLUTIONS_ROOT_G1R: &str =
    include_str!("../../certs/production/root/SK_ID_Solutions_ROOT_G1R.pem.crt");

pub(crate) fn production_intermediate_certificates() -> Vec<String> {
    vec![
        EID_SK.to_string(),
        EID_SK_2007.to_string(),
        EID_SK_2011.to_string(),
        EID_SK_2016.to_string(),
        EID_NQ_2021E.to_string(),
        EID_NQ_2021R.to_string(),
        EID_Q_2021E.to_string(),
        EID_Q_2021R.to_string(),
        EID_Q_2024E.to_string(),
        EID_Q_2024R.to_string(),
        ESTEID2018.to_string(),
        ESTEID_SK.to_string(),
        ESTEID_SK_2007.to_string(),
        ESTEID_SK_2011.to_string(),
        ESTEID_SK_2015.to_string(),
        KLASS3_SK.to_string(),
        KLASS3_SK_2010.to_string(),
        KLASS3_SK_2010_EECCRCA.to_string(),
        KLASS3_SK_2010_EECCRCA_SHA384.to_string(),
        KLASS3_SK_2016_EECCRCA_SHA384.to_string(),
        NQ_SK_2016.to_string(),
        ORG_2021E.to_string(),
        ORG_2021R.to_string(),
    ]
}

pub(crate) fn production_root_certificates() -> Vec<String> {
    vec![
        EE_GOVCA2018.to_string(),
        EE_CERTIFICATION_CENTRE_ROOT_CA.to_string(),
        JUUR_SK.to_string(),
        SK_ID_SOLUTIONS_ROOT_G1E.to_string(),
        SK_ID_SOLUTIONS_ROOT_G1R.to_string(),
    ]
}
