// Test certificates
const EID_SK: &str = include_str!("../../certs/demo/intermediate/EID-SK.pem.crt");
const EID_SK_2007: &str = include_str!("../../certs/demo/intermediate/EID-SK_2007.pem.crt");
const EID_SK_2011: &str = include_str!("../../certs/demo/intermediate/EID-SK_2011.pem.crt");
const EID_SK_2016: &str = include_str!("../../certs/demo/intermediate/EID-SK_2016.pem.crt");
const EID_NQ_2021E: &str = include_str!("../../certs/demo/intermediate/EID_NQ_2021E.pem.crt");
const EID_NQ_2021R: &str = include_str!("../../certs/demo/intermediate/EID_NQ_2021R.pem.crt");
const EID_Q_2021E: &str = include_str!("../../certs/demo/intermediate/EID_Q_2021E.pem.crt");
const EID_Q_2021R: &str = include_str!("../../certs/demo/intermediate/EID_Q_2021R.pem.crt");
const EID_Q_2024E: &str = include_str!("../../certs/demo/intermediate/EID_Q_2024E.pem.crt");
const EID_Q_2024R: &str = include_str!("../../certs/demo/intermediate/EID_Q_2024R.pem.crt");
const ESTEID2018: &str = include_str!("../../certs/demo/intermediate/esteid2018.pem.crt");
const ESTEID_SK: &str = include_str!("../../certs/demo/intermediate/ESTEID-SK.pem.crt");
const ESTEID_SK_2007: &str = include_str!("../../certs/demo/intermediate/ESTEID-SK_2007.pem.crt");
const ESTEID_SK_2011: &str = include_str!("../../certs/demo/intermediate/ESTEID-SK_2011.pem.crt");
const ESTEID_SK_2015: &str = include_str!("../../certs/demo/intermediate/ESTEID-SK_2015.pem.crt");
const KLASS3_SK: &str = include_str!("../../certs/demo/intermediate/KLASS3-SK.pem.crt");
const KLASS3_SK_2010: &str = include_str!("../../certs/demo/intermediate/KLASS3-SK_2010.pem.crt");
const KLASS3_SK_2010_EECCRCA: &str =
    include_str!("../../certs/demo/intermediate/KLASS3-SK_2010_EECCRCA.pem.crt");
const KLASS3_SK_2010_EECCRCA_SHA384: &str =
    include_str!("../../certs/demo/intermediate/KLASS3-SK_2010_EECCRCA_SHA384.pem.crt");
const KLASS3_SK_2016_EECCRCA_SHA384: &str =
    include_str!("../../certs/demo/intermediate/KLASS3-SK_2016_EECCRCA_SHA384.pem.crt");
const NQ_SK_2016: &str = include_str!("../../certs/demo/intermediate/NQ-SK_2016.pem.crt");
const ORG_2021E: &str = include_str!("../../certs/demo/intermediate/ORG_2021E.pem.crt");
const ORG_2021R: &str = include_str!("../../certs/demo/intermediate/ORG_2021R.pem.crt");

const DEMO_SK_TIMESTAMPING_AUTHORITY_2020: &str =
    include_str!("../../certs/demo/root/DEMO_SK_TIMESTAMPING_AUTHORITY_2020.pem.cer");
const DEMO_SK_TIMESTAMPING_UNIT_2025E: &str =
    include_str!("../../certs/demo/root/DEMO_SK_TIMESTAMPING_UNIT_2025E.pem.crt");
const DEMO_SK_TIMESTAMPING_UNIT_2025R: &str =
    include_str!("../../certs/demo/root/DEMO_SK_TIMESTAMPING_UNIT_2025R.pem.crt");
const DEMO_TSU_ECC_2023: &str = include_str!("../../certs/demo/root/demo_tsu_ecc_2023.pem.crt");
const DEMO_TSU_RSA_2023: &str = include_str!("../../certs/demo/root/demo_tsu_rsa_2023.pem.crt");
const SID_DEMO_SK_EE: &str = include_str!("../../certs/demo/root/sid_demo_sk_ee.pem");
const SID_DEMO_SK_EE_PEM: &str = include_str!("../../certs/demo/root/sid_demo_sk_ee.pem.crt");
const SID_DEMO_SK_EE_2022_PEM: &str =
    include_str!("../../certs/demo/root/sid_demo_sk_ee_2022_PEM.crt");
const TEST_OF_EID_SK_2016_REISSUED: &str =
    include_str!("../../certs/demo/root/TEST of EID-SK 2016_reissued.pem");
const TEST_OF_NQ_SK_2016_REISSUED: &str =
    include_str!("../../certs/demo/root/TEST of NQ-SK 2016_reissued.pem");
const TEST_EID_NQ_2021E: &str = include_str!("../../certs/demo/root/TEST_EID-NQ_2021E.pem.crt");
const TEST_EID_NQ_2021R: &str = include_str!("../../certs/demo/root/TEST_EID-NQ_2021R.pem.crt");
const TEST_EID_Q_2021E: &str = include_str!("../../certs/demo/root/TEST_EID-Q_2021E.pem.crt");
const TEST_EID_Q_2021R: &str = include_str!("../../certs/demo/root/TEST_EID-Q_2021R.pem.crt");
const TEST_OF_EE_GOVCA2018: &str =
    include_str!("../../certs/demo/root/TEST_of_EE-GovCA2018.pem.crt");
const TEST_OF_EE_CERTIFICATION_CENTRE_ROOT_CA: &str =
    include_str!("../../certs/demo/root/TEST_of_EE_Certification_Centre_Root_CA.pem.crt");
const TEST_OF_ESTEID2018: &str = include_str!("../../certs/demo/root/TEST_of_ESTEID2018.pem.crt");
const TEST_OF_ESTEID_SK_2015: &str =
    include_str!("../../certs/demo/root/TEST_of_ESTEID-SK_2015.pem.crt");
const TEST_OF_KLASS3_SK_2016: &str =
    include_str!("../../certs/demo/root/TEST_of_KLASS3-SK_2016.pem.crt");
const TEST_OF_SK_ID_SOLUTIONS_EID_Q_2024E: &str =
    include_str!("../../certs/demo/root/TEST_of_SK_ID_Solutions_EID-Q_2024E.pem.crt");
const TEST_OF_SK_ID_SOLUTIONS_EID_Q_2024R: &str =
    include_str!("../../certs/demo/root/TEST_of_SK_ID_Solutions_EID-Q_2024R.pem.crt");
const TEST_OF_SK_OCSP_RESPONDER_2020: &str =
    include_str!("../../certs/demo/root/TEST_of_SK_OCSP_RESPONDER_2020.pem.cer");
const TEST_OF_SK_TSA_CA_2023E: &str =
    include_str!("../../certs/demo/root/TEST_of_SK_TSA_CA_2023E.pem.crt");
const TEST_OF_SK_TSA_CA_2023R: &str =
    include_str!("../../certs/demo/root/TEST_of_SK_TSA_CA_2023R.pem.crt");
const TEST_ORG_2021E: &str = include_str!("../../certs/demo/root/TEST_ORG_2021E.pem.crt");
const TEST_ORG_2021R: &str = include_str!("../../certs/demo/root/TEST_ORG_2021R.pem.crt");
const TEST_SK_ROOT_G1_2021E: &str =
    include_str!("../../certs/demo/root/TEST_SK_ROOT_G1_2021E.pem.crt");
const TEST_SK_ROOT_G1_2021R: &str =
    include_str!("../../certs/demo/root/TEST_SK_ROOT_G1_2021R.pem.crt");
const TSP_DEMO_SK_EE_2024: &str = include_str!("../../certs/demo/root/tsp.demo.sk.ee_2024.pem.cer");
const TSP_DEMO_SK_EE_2023: &str = include_str!("../../certs/demo/root/tsp_demo_sk_ee_2023.pem.cer");
const TSP_DEMO_SK_EE_2025: &str = include_str!("../../certs/demo/root/tsp_demo_sk_ee_2025.pem.cer");

pub(crate) fn demo_intermediate_certificates() -> Vec<String> {
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

pub(crate) fn demo_root_certificates() -> Vec<String> {
    vec![
        DEMO_SK_TIMESTAMPING_AUTHORITY_2020.to_string(),
        DEMO_SK_TIMESTAMPING_UNIT_2025E.to_string(),
        DEMO_SK_TIMESTAMPING_UNIT_2025R.to_string(),
        DEMO_TSU_ECC_2023.to_string(),
        DEMO_TSU_RSA_2023.to_string(),
        SID_DEMO_SK_EE.to_string(),
        SID_DEMO_SK_EE_PEM.to_string(),
        SID_DEMO_SK_EE_2022_PEM.to_string(),
        TEST_OF_EID_SK_2016_REISSUED.to_string(),
        TEST_OF_NQ_SK_2016_REISSUED.to_string(),
        TEST_EID_NQ_2021E.to_string(),
        TEST_EID_NQ_2021R.to_string(),
        TEST_EID_Q_2021E.to_string(),
        TEST_EID_Q_2021R.to_string(),
        TEST_OF_EE_GOVCA2018.to_string(),
        TEST_OF_EE_CERTIFICATION_CENTRE_ROOT_CA.to_string(),
        TEST_OF_ESTEID2018.to_string(),
        TEST_OF_ESTEID_SK_2015.to_string(),
        TEST_OF_KLASS3_SK_2016.to_string(),
        TEST_OF_SK_ID_SOLUTIONS_EID_Q_2024E.to_string(),
        TEST_OF_SK_ID_SOLUTIONS_EID_Q_2024R.to_string(),
        TEST_OF_SK_OCSP_RESPONDER_2020.to_string(),
        TEST_OF_SK_TSA_CA_2023E.to_string(),
        TEST_OF_SK_TSA_CA_2023R.to_string(),
        TEST_ORG_2021E.to_string(),
        TEST_ORG_2021R.to_string(),
        TEST_SK_ROOT_G1_2021E.to_string(),
        TEST_SK_ROOT_G1_2021R.to_string(),
        TSP_DEMO_SK_EE_2024.to_string(),
        TSP_DEMO_SK_EE_2023.to_string(),
        TSP_DEMO_SK_EE_2025.to_string(),
    ]
}
