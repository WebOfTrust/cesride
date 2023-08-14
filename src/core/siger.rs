use crate::core::indexer::{tables as indexer, Indexer};
use crate::core::verfer::Verfer;
use crate::error::{err, Error, Result};

#[derive(Debug, Clone, PartialEq)]
pub struct Siger {
    raw: Vec<u8>,
    code: String,
    index: u32,
    ondex: u32,
    verfer: Verfer,
}

impl Default for Siger {
    fn default() -> Self {
        Siger {
            raw: vec![],
            code: indexer::Codex::Ed25519.to_string(),
            index: 0,
            ondex: 0,
            verfer: Verfer::default(),
        }
    }
}

fn validate_code(code: &str) -> Result<()> {
    const CODES: &[&str] = &[
        indexer::Codex::Ed25519,
        indexer::Codex::Ed25519_Crt,
        indexer::Codex::ECDSA_256k1,
        indexer::Codex::ECDSA_256k1_Crt,
        indexer::Codex::ECDSA_256r1,
        indexer::Codex::ECDSA_256r1_Crt,
        indexer::Codex::CRYSTALS_Dilithium3,
        indexer::Codex::CRYSTALS_Dilithium3_Crt,
        indexer::Codex::CRYSTALS_Dilithium5,
        indexer::Codex::CRYSTALS_Dilithium5_Crt,
        // indexer::Codex::Ed448,
        // indexer::Codex::Ed448_Crt,
        indexer::Codex::Ed25519_Big,
        indexer::Codex::Ed25519_Big_Crt,
        indexer::Codex::ECDSA_256k1_Big,
        indexer::Codex::ECDSA_256k1_Big_Crt,
        indexer::Codex::ECDSA_256r1_Big,
        indexer::Codex::ECDSA_256r1_Big_Crt,
        indexer::Codex::CRYSTALS_Dilithium3_Big,
        indexer::Codex::CRYSTALS_Dilithium3_Big_Crt,
        indexer::Codex::CRYSTALS_Dilithium5_Big,
        indexer::Codex::CRYSTALS_Dilithium5_Big_Crt,
        // indexer::Codex::Ed448_Big,
        // indexer::Codex::Ed448_Big_Crt,
    ];

    if !CODES.contains(&code) {
        return err!(Error::UnexpectedCode(code.to_string()));
    }

    Ok(())
}

impl Siger {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        verfer: Option<&Verfer>,
        index: Option<u32>,
        ondex: Option<u32>,
        code: Option<&str>,
        raw: Option<&[u8]>,
        qb64b: Option<&[u8]>,
        qb64: Option<&str>,
        qb2: Option<&[u8]>,
    ) -> Result<Self> {
        let mut siger: Self = Indexer::new(index, ondex, code, raw, qb64b, qb64, qb2)?;
        if let Some(verfer) = verfer {
            siger.set_verfer(verfer);
        }
        validate_code(&siger.code())?;
        Ok(siger)
    }

    pub fn new_with_raw(
        raw: &[u8],
        verfer: Option<&Verfer>,
        index: Option<u32>,
        ondex: Option<u32>,
        code: Option<&str>,
    ) -> Result<Self> {
        Self::new(verfer, index, ondex, code, Some(raw), None, None, None)
    }

    pub fn new_with_qb64b(qb64b: &[u8], verfer: Option<&Verfer>) -> Result<Self> {
        Self::new(verfer, None, None, None, None, Some(qb64b), None, None)
    }

    pub fn new_with_qb64(qb64: &str, verfer: Option<&Verfer>) -> Result<Self> {
        Self::new(verfer, None, None, None, None, None, Some(qb64), None)
    }

    pub fn new_with_qb2(qb2: &[u8], verfer: Option<&Verfer>) -> Result<Self> {
        Self::new(verfer, None, None, None, None, None, None, Some(qb2))
    }

    pub fn verfer(&self) -> Verfer {
        self.verfer.clone()
    }

    fn set_verfer(&mut self, verfer: &Verfer) {
        self.verfer = verfer.clone();
    }
}

impl Indexer for Siger {
    fn code(&self) -> String {
        self.code.clone()
    }

    fn raw(&self) -> Vec<u8> {
        self.raw.clone()
    }

    fn index(&self) -> u32 {
        self.index
    }

    fn ondex(&self) -> u32 {
        self.ondex
    }

    fn set_code(&mut self, code: &str) {
        self.code = code.to_string();
    }

    fn set_raw(&mut self, raw: &[u8]) {
        self.raw = raw.to_vec();
    }

    fn set_index(&mut self, size: u32) {
        self.index = size;
    }

    fn set_ondex(&mut self, size: u32) {
        self.ondex = size;
    }
}

#[cfg(test)]
mod test {
    use super::{indexer, Indexer, Siger, Verfer};
    use crate::core::matter::tables as matter;
    use base64::{engine::general_purpose as b64_engine, Engine};
    use hex_literal::hex;

    #[test]
    fn convenience() {
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();
        let code = indexer::Codex::Ed25519;
        let raw = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]";

        let siger =
            Siger::new(Some(&verfer), None, None, Some(code), Some(raw), None, None, None).unwrap();

        assert!(Siger::new_with_raw(&siger.raw(), Some(&verfer), None, None, Some(&siger.code()))
            .is_ok());
        assert!(Siger::new_with_qb64b(&siger.qb64b().unwrap(), Some(&verfer)).is_ok());
        assert!(Siger::new_with_qb64(&siger.qb64().unwrap(), Some(&verfer)).is_ok());
        assert!(Siger::new_with_qb2(&siger.qb2().unwrap(), Some(&verfer)).is_ok());
    }

    #[test]
    fn new() {
        let vcode = matter::Codex::Ed25519;
        let vraw = b"abcdefghijklmnopqrstuvwxyz012345";
        let verfer = Verfer::new(Some(vcode), Some(vraw), None, None, None).unwrap();
        let code = indexer::Codex::Ed25519;
        let raw = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ[]";

        assert!(
            Siger::new(Some(&verfer), None, None, Some(code), Some(raw), None, None, None).is_ok()
        );
        assert!(Siger::new(None, None, None, Some(code), Some(raw), None, None, None).is_ok());
    }

    #[test]
    fn python_interop() {
        assert!(Siger::new(None, None, None, Some(""), Some(b""), None, None, None).is_err());

        let qsig64 = "AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let qsig64b = qsig64.as_bytes();

        let siger = Siger::new(None, None, None, None, None, Some(qsig64b), None, None).unwrap();
        assert_eq!(siger.code(), indexer::Codex::Ed25519);
        assert_eq!(siger.index(), 0);
        assert_eq!(siger.ondex(), 0);
        assert_eq!(siger.qb64().unwrap(), qsig64);
        // this behaviour differs from KERIpy
        assert_eq!(siger.verfer(), Verfer::default());

        let mut siger = Siger::new(None, None, None, None, None, None, Some(qsig64), None).unwrap();
        assert_eq!(siger.code(), indexer::Codex::Ed25519);
        assert_eq!(siger.index(), 0);
        assert_eq!(siger.ondex(), 0);
        assert_eq!(siger.qb64().unwrap(), qsig64);
        // this behaviour differs from KERIpy
        assert_eq!(siger.verfer(), Verfer::default());

        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new(Some(verfer_code), Some(&verfer_raw), None, None, None).unwrap();

        siger.set_verfer(&verfer);
        assert_eq!(siger.verfer(), verfer);

        let siger =
            Siger::new(Some(&verfer), None, None, None, None, None, Some(qsig64), None).unwrap();
        assert_eq!(siger.verfer(), verfer);

        // we don't support ed448 yet

        // let raw = b"abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdef";
        // let siger = Siger::new(
        //     None,
        //     Some(4),
        //     None,
        //     Some(indexer::Codex::Ed448),
        //     Some(raw),
        //     None,
        //     None,
        //     None,
        // )
        // .unwrap();
        // assert_eq!(siger.qb64().unwrap(), "0AEEYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5YWJjZGVm");
    }

    #[test]
    fn new_with_code_and_raw() {
        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new(Some(verfer_code), Some(&verfer_raw), None, None, None).unwrap();

        let siger_code = indexer::Codex::Ed25519;
        let siger_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa"
                                       "0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        assert!(Siger::new(
            Some(&verfer),
            None,
            None,
            Some(siger_code),
            Some(&siger_raw),
            None,
            None,
            None
        )
        .is_ok());
        assert!(Siger::new(None, None, None, Some(siger_code), Some(&siger_raw), None, None, None)
            .is_ok());
    }

    #[test]
    fn new_with_qb64() {
        let qsig64 = "5AAAAKEWfy8izZF5MNOHRA5jj0WdWR4LnasWt97UTwEgku7o5xd_L7Oftt8oHAS4qO4gUpbj7rZntpI4wB-vHSvTXDBXSsEc3NOJ4Vb1MWfxiYHsJSSHSh5g-_S-6LmBeC5v66eMh8RUsAuP-SqfXwH3O2Vim3e44wTY7tf5XCxuGHdXLpvksZ3ut5W-TtT_yz5zCzO88M4SwNKg6VACGXwXyASLzlsHSaxx3Y4FQa8o3AImkfoIJmMQYHYo--EhIJkWl5zLOmljGenQUC7mie2wqe0_JtA0PS-2lsFRFhHT4xvoHDNH-T9t72mZY_fHqeuQx2sqf6f-tjqAzSly1DHxPc_q6evDLSev_90GGWmaY2ZcionQZZr8pM741vy7u_pdSRc_rvrEcSf9ofE_4eXFezNHfHBVlsLaX3BsztwXvAxT_FmCRrrTGzR_uYffYnAdvaLCDdnuflaEC8stAsuOEnZbpgHIeeYWJK8xkwq-pwDQ-khGFVM0aJnMUIyNJpHzwBQS-OcTjU3HLObOOy5L3tuTkoRdvlxv0nNUre9ZY5S7rDW8vSQgCEXJOw0RkKr5uOjwQwM-yARGu-Ta44RddAKDvijDI0OAyT5Lv2U2U1ip9y9bMCOOr4dRK3elOQ6M0RReAfLb6UFniSqbfevFyJ0WbfNfDaqhhbo2J2V0Ck53kb1G6pY7yV9BNlBrlvXQARedf-wLgby3jU0Y06yoCWdavycH9-vvAKzBF6ggnfxJCeJNnAIATy3dfvsBaYRv4uOa6gODaSJuOdKAInErMcGUi279jTUy1LtPk9v1LMdWoTm_zT-K3kwvEu1uU0kcszzVjJUOAl7rDbXeux1CyooyN0MfH4dtUgUiSWGDq3JoNsDSEuQ2XfztoNQcS82hsRzgQsyvTeXsSqp92MpO4jCfGv3pvhyAUdv0TKh1wkxXvj9P1Hv9WmeSFpYCx1aZlqekYcKedPEZ2jDAVJSFsJUVGvyl8_meOZvOCUSTAEbjoL52tdQu8wUmreRBRyrfXkh5C9a3Jl39YHSkhStc1dgwHOJmLFK3oGMRRlwnqlazQ77JjIFJYjt2i4q-KfKDiIURL6ai66fTHXbndvBMq548NVcQYrfIOI_xRnKEXsDwEGMJhc47Fmk3sznpJ76yIzCXchqepmLXbBqM6sA3Gwd9dJZGzaJwpSeugEBZmjckU7rwzyDXim1sphs2ywFKGMyQGxvUOv7HgriPpbR5kvuSNN_HXDZaAzatWM-bbcfvv-3WxAmY398SSaQpe0sWaa9IxAhbCUB1jgPxslJLNNLfWF8J8vp90SxMRhlwZUGZGclSvlM0plFYrpmeqvNlhr3iViCquSQDDQmD4gqE2lViKA4PU7TxYPb1Ywiov0-bjlQylTckf8dkI3ZafQgNNpOCdquj-8AkGoUzlGHx1sg-hxSe9XphO8a5Gqd204ydiNzHLr1CLBDdkHSwcDA6j2UHlrfRV8mtM1Tfcutl05ise_BQgv5C2EiYw-r_Zz0itQPngCH_LdVT1NBTlPyPy8DxjGnMjwthaOhBBc8mSoA4Xe9vz4cWhjJ-UJaCtESUz7zybMJ2toafTrtBptE0TjZFWC1oZBCEn1codNMQ1fIzddCPJpce8NvvdZrEkqP0UT1RuxR35-o7aVOtWzf6WtpvKre2doKliwgNnMXOJHUZdAWYLsolPW5wbkCElkvQ0vS0nep_jFJuDt3AvQdkLOhf-wRNSiswCz8-LNWRNVZV2bdJ90CiF4jr-L9jb4Tzt38oJM1xXSgBsn0XErcui0GZPm1R80pM3kbErebrXn5XFR6CoKqgHgCf_X2kQ5nQHtir5ipskq35kEG7pZ9vRaSw6YBqz28_eUHITN0PfNHIGSAo8shsqCuV8DdN59iBLPKr9JvZK3FmzOPsLGNKcmYS0UMVSbkCSfRMb-s2jKOqFbSe4xsFCky90CcNsxUIqBIRhNu5f2Ebqv7jZOVR8wb22j3eNBz1Mp1Jpe-asxD3o6O0gbIGa081eiMoKUvG60ZRfVwroKd0OP-LVKPP2HRB6UHGyMZ-MxYBHhLbc_3un5uvTIgQ-2i2fzLP2Az5vMY12hTbYqzIwWVHa0O2nzdTBAzM7fSkupSazxG_24Th5HF5RTCJAl11KsPPzKbimFdE1yT7S9lGIDGk446fYdhdGhUs_ujiowlNZkDlaxk_L5zymDOwRUfYYwfpIiRVWhT6OgkS8KaqufHIBowAN7WQIeQ4RTYsJCF5wYUGRwB_dvLyJehXZlilBIXVLeL5kMbYTMMuF0QZbKDVymAAXI6m_0LLEsCWbLoOjWvz8L9QvNWjFiEZzGOMZa1g7BTQ17GFJ5aOWJ0tvaAbIS079zSOj0JFF889AxuRF2UizQCvXeh_geSQ3ccgWBwpSv6Un85GdTiQUQKcZRSOtNT2-pc6mCj6z1vKFr0zwktY4B5JYMw-mbHlq8KUz_rBwVU09MhuCRG-eqv78PCZI0Lg6jHXpgjTBR8Z3ylH_eU4lQxH_8Qm8_4S2IoHHnMa-EXiNaxoxPT3GJOCjNvXVKAbVKfnmau32R2J3nBYwShSfGh32adA70JbO69D_zHIAkJPdmr_ZTUh8RYzVtetHLNO6wHGhat-Kft6k4rSmN-epMzU80pgp_e22AfXS8YhyuE3JOT2C6H5VC1eO6jO1ra3njqHGtQpTcaXRELCHZBS97bykJP3Vpg93VY1kFZEgVY1uGiXrCLI-PTPOJUEWv9GR7x4yesfyOboQPrDsCoLJgXd6DMPa_L2xbCyz-fuqzsJm_6sjzjXGx_MJXlOLAI9mw4JEUUu1xM5rqkxHiQ8_RzTBxfmA2kNYSsPRJDuzdWcI7aLXS1w6JC7Rfmb5iYN15Sh2ykgCZdU9o_fYc49bnS-Eyqlt5-C_ZY3vx2ipspVjBnZZB3fnenAfpw9JJvHVhpCFIdIU1W_QiZD5RrFAK8sw8MXIBlSTc6yfkRx6FiZ64ih17g7_VeYmZDjEndl7MZNxq5o3fbLiqIAFrV_KIqQqpUu-wSYtqKSXTaaVAb8QsVjh4ab9vUYkiW9hoU11O0SvVGajD4fzejELhEFBZsXfz9DYrBGGukeEEU-BIawpv-CCZAl5e4xbHaVPg8OvyIHf9uF4OlEodY487Bji8oP9qpd5YoYbbbUfiCIrxWfcR9DnXZAnJmj5Cjr9shkIsqXjF5ra3qWjMfcZh7eS0vRWpioL9EHsHvncodGFO-sXCiRo70SOmQPtKc4R5HHFw1c9Sm4etqAHqMHXMcZYbnrhaFQuJSnL4fe5wVJLEmvcPFueA1Ymz4tOlxjgzC8VxsWnFRCBYdLnxTvHeMp18h5r8kWz3Y0auhxzLHSR4cOirgKWNCBSSZvgvzWYHGLtDkiPoIfOJYZ8pqbKzFyRIqvkZvBQwBXHmyRyz0_pxkoeGIP0FaWGu0YBLy-y6ZEzNs0igbisX8-DtJ6ORrnsFGVaYEwVnPFlPydJ5n6r7geEQR9ZxdXXzG2VBaY4OJwHr5_WP4YmiPxdQWaJPrC6xZHthq5el4j82exKwXU6VXduhPY7n0n1TkIY9-i7jxRdkMI_RIlXylrNYTl_L5THA4NIgmoBJFHyDeV7tHwQPTvoz-AQe5TznzS4oMEfYY6HBBjlqXkSI0sySPC3p0QZU7oMQ18gGQDpqagGJYRr4OpJFvjcvEa2KEUmqkz-cfo2WFq-jjxO6nyvR0BQrqXE_L8Du63qj19yYEF4jX2HRvAQSSw20GqjaG7Ua0WM4fRGU0MIZ996j38iJdSAlsA9vRkoZNj_V-SQb2sGkN1qUyZK9YuhQ8BRdLs-ksxnJjLTAur4UpyWncYUeegj7PmSSv2MPe1B-6IKhlqr3vzo8S3K8xteGXR6LMhsh_mU0Bbo_HLlIll_xNcCh-HgGkLb-sqKcC09HwBEGBB1A3xO_rNkIjMcgwClA-l-3klQCohmkk2fd39m_ZYq5MabS9ge2jV8jg_9jBJVwO3kd9KhCRBoYjnGucN2eiheo2BsFFrFo7lexE7z90Pf4zhLBu-RKqV4X0Y7SVUWZgJBNK_GAmyAWmqYMmviO0fP5UZ29KoDdIpgnCqWme6FNTyew7wFvL7pbeEr7OcGzH6zDMHQdNFPns3MNCw6OMUIq2CDSHpccaj2vZkA0gM8z8Tg1MdreU12UkyzVjFFFkdCROSX32hBndzQa14977XP1JBom_vlzFdDxOeZ03-cVTpzH_Y8ha5D9J_gKA9locHSdbvUA7hAzjfrVVpBAAHpc9prqqO3bLgt08dCLa9Hf08l9wzyBQCW3_2ETRq0114g6Ws2uouS1S77_MNb8AOD1NVWGBoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAgPFRgf";

        Siger::new(None, None, None, None, None, None, Some(qsig64), None).unwrap();
        assert!(Siger::new(None, None, None, None, None, None, Some(qsig64), None).is_ok());
    }

    #[test]
    fn new_with_qb64b() {
        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new(Some(verfer_code), Some(&verfer_raw), None, None, None).unwrap();

        let qsig64 = "AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ";
        let qsig64b = qsig64.as_bytes();

        assert!(
            Siger::new(Some(&verfer), None, None, None, None, Some(qsig64b), None, None).is_ok()
        );
        assert!(Siger::new(None, None, None, None, None, Some(qsig64b), None, None).is_ok());
    }

    #[test]
    fn new_with_qb2() {
        let verfer_raw = hex!("0123456789abcdef00001111222233334444555566667777888899990000aaaa");

        let verfer_code = matter::Codex::Ed25519;
        let verfer = Verfer::new(Some(verfer_code), Some(&verfer_raw), None, None, None).unwrap();

        let qsig2 = b64_engine::URL_SAFE.decode("AACdI8OSQkMJ9r-xigjEByEjIua7LHH3AOJ22PQKqljMhuhcgh9nGRcKnsz5KvKd7K_H9-1298F4Id1DxvIoEmCQ").unwrap();

        assert!(Siger::new(Some(&verfer), None, None, None, None, None, None, Some(&qsig2)).is_ok());
        assert!(Siger::new(None, None, None, None, None, None, None, Some(&qsig2)).is_ok());
    }

    #[test]
    fn unhappy_paths() {
        // invalid code
        assert!(Siger::new(None, None, None, Some("CESR"), Some(&[]), None, None, None).is_err());
    }
}
