use cesride_core::indexer::Codex as IndexerCodex;
use cesride_core::matter::Codex as MatterCodex;
use wasm_bindgen::prelude::*;

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[wasm_bindgen(js_name = MatterCodex)]
pub enum CesrideMatterCodex {
    Ed25519Seed,
    Ed25519N,
    X25519,
    Ed25519,
    Blake3_256,
    Blake2b_256,
    Blake2s_256,
    SHA3_256,
    SHA2_256,
    ECDSA_256k1_Seed,
    Ed448_Seed,
    X448,
    Short,
    Big,
    X25519_Private,
    X25519_Cipher_Seed,
    Salt_128,
    Ed25519_Sig,
    ECDSA_256k1_Sig,
    Blake3_512,
    Blake2b_512,
    SHA3_512,
    SHA2_512,
    Long,
    ECDSA_256k1N,
    ECDSA_256k1,
    Ed448N,
    Ed448,
    Ed448_Sig,
    Tern,
    DateTime,
    X25519_Cipher_Salt,
    TBD1,
    TBD2,
    StrB64_L0,
    StrB64_L1,
    StrB64_L2,
    StrB64_Big_L0,
    StrB64_Big_L1,
    StrB64_Big_L2,
    Bytes_L0,
    Bytes_L1,
    Bytes_L2,
    Bytes_Big_L0,
    Bytes_Big_L1,
    Bytes_Big_L2,
}

impl CesrideMatterCodex {
    pub fn code(&self) -> &str {
        match self {
            CesrideMatterCodex::Ed25519Seed => MatterCodex::Ed25519_Seed,
            CesrideMatterCodex::Ed25519N => MatterCodex::Ed25519N,
            CesrideMatterCodex::X25519 => MatterCodex::X25519,
            CesrideMatterCodex::Ed25519 => MatterCodex::Ed25519,
            CesrideMatterCodex::Blake3_256 => MatterCodex::Blake3_256,
            CesrideMatterCodex::Blake2b_256 => MatterCodex::Blake2b_256,
            CesrideMatterCodex::Blake2s_256 => MatterCodex::Blake2s_256,
            CesrideMatterCodex::SHA3_256 => MatterCodex::SHA3_256,
            CesrideMatterCodex::SHA2_256 => MatterCodex::SHA2_256,
            CesrideMatterCodex::ECDSA_256k1_Seed => MatterCodex::ECDSA_256k1_Seed,
            CesrideMatterCodex::Ed448_Seed => MatterCodex::Ed448_Seed,
            CesrideMatterCodex::X448 => MatterCodex::X448,
            CesrideMatterCodex::Short => MatterCodex::Short,
            CesrideMatterCodex::Big => MatterCodex::Big,
            CesrideMatterCodex::X25519_Private => MatterCodex::X25519_Private,
            CesrideMatterCodex::X25519_Cipher_Seed => MatterCodex::X25519_Cipher_Seed,
            CesrideMatterCodex::Salt_128 => MatterCodex::Salt_128,
            CesrideMatterCodex::Ed25519_Sig => MatterCodex::Ed25519_Sig,
            CesrideMatterCodex::ECDSA_256k1_Sig => MatterCodex::ECDSA_256k1_Sig,
            CesrideMatterCodex::Blake3_512 => MatterCodex::Blake3_512,
            CesrideMatterCodex::Blake2b_512 => MatterCodex::Blake2b_512,
            CesrideMatterCodex::SHA3_512 => MatterCodex::SHA3_512,
            CesrideMatterCodex::SHA2_512 => MatterCodex::SHA2_512,
            CesrideMatterCodex::Long => MatterCodex::Long,
            CesrideMatterCodex::ECDSA_256k1N => MatterCodex::ECDSA_256k1N,
            CesrideMatterCodex::ECDSA_256k1 => MatterCodex::ECDSA_256k1,
            CesrideMatterCodex::Ed448N => MatterCodex::Ed448N,
            CesrideMatterCodex::Ed448 => MatterCodex::Ed448,
            CesrideMatterCodex::Ed448_Sig => MatterCodex::Ed448_Sig,
            CesrideMatterCodex::Tern => MatterCodex::Tern,
            CesrideMatterCodex::DateTime => MatterCodex::DateTime,
            CesrideMatterCodex::X25519_Cipher_Salt => MatterCodex::X25519_Cipher_Salt,
            CesrideMatterCodex::TBD1 => MatterCodex::TBD1,
            CesrideMatterCodex::TBD2 => MatterCodex::TBD2,
            CesrideMatterCodex::StrB64_L0 => MatterCodex::StrB64_L0,
            CesrideMatterCodex::StrB64_L1 => MatterCodex::StrB64_L1,
            CesrideMatterCodex::StrB64_L2 => MatterCodex::StrB64_L2,
            CesrideMatterCodex::StrB64_Big_L0 => MatterCodex::StrB64_Big_L0,
            CesrideMatterCodex::StrB64_Big_L1 => MatterCodex::StrB64_Big_L1,
            CesrideMatterCodex::StrB64_Big_L2 => MatterCodex::StrB64_Big_L2,
            CesrideMatterCodex::Bytes_L0 => MatterCodex::Bytes_L0,
            CesrideMatterCodex::Bytes_L1 => MatterCodex::Bytes_L1,
            CesrideMatterCodex::Bytes_L2 => MatterCodex::Bytes_L2,
            CesrideMatterCodex::Bytes_Big_L0 => MatterCodex::Bytes_Big_L0,
            CesrideMatterCodex::Bytes_Big_L1 => MatterCodex::Bytes_Big_L1,
            CesrideMatterCodex::Bytes_Big_L2 => MatterCodex::Bytes_Big_L2,
        }
    }
}

#[wasm_bindgen]
pub fn matter_codex_code(codex: CesrideMatterCodex) -> String {
    codex.code().to_string()
}

#[allow(non_camel_case_types)]
#[derive(Debug)]
#[wasm_bindgen(js_name = IndexerCodex)]
pub enum CesrideIndexerCodex {
    Ed25519,
    Ed25519_Crt,
    ECDSA_256k1,
    ECDSA_256k1_Crt,
    Ed448,
    Ed448_Crt,
    Ed25519_Big,
    Ed25519_Big_Crt,
    ECDSA_256k1_Big,
    ECDSA_256k1_Big_Crt,
    Ed448_Big,
    Ed448_Big_Crt,
    TBD0,
    TBD1,
    TBD4,
}

impl CesrideIndexerCodex {
    pub fn code(&self) -> &str {
        match self {
            CesrideIndexerCodex::Ed25519 => IndexerCodex::Ed25519,
            CesrideIndexerCodex::Ed25519_Crt => IndexerCodex::Ed25519_Crt,
            CesrideIndexerCodex::ECDSA_256k1 => IndexerCodex::ECDSA_256k1,
            CesrideIndexerCodex::ECDSA_256k1_Crt => IndexerCodex::ECDSA_256k1_Crt,
            CesrideIndexerCodex::Ed448 => IndexerCodex::Ed448,
            CesrideIndexerCodex::Ed448_Crt => IndexerCodex::Ed448_Crt,
            CesrideIndexerCodex::Ed25519_Big => IndexerCodex::Ed25519_Big,
            CesrideIndexerCodex::Ed25519_Big_Crt => IndexerCodex::Ed25519_Big_Crt,
            CesrideIndexerCodex::ECDSA_256k1_Big => IndexerCodex::ECDSA_256k1_Big,
            CesrideIndexerCodex::ECDSA_256k1_Big_Crt => IndexerCodex::ECDSA_256k1_Big_Crt,
            CesrideIndexerCodex::Ed448_Big => IndexerCodex::Ed448_Big,
            CesrideIndexerCodex::Ed448_Big_Crt => IndexerCodex::Ed448_Big_Crt,
            CesrideIndexerCodex::TBD0 => IndexerCodex::TBD0,
            CesrideIndexerCodex::TBD1 => IndexerCodex::TBD1,
            CesrideIndexerCodex::TBD4 => IndexerCodex::TBD4,
        }
    }
}

#[wasm_bindgen]
pub fn indexer_codex_code(codex: CesrideIndexerCodex) -> String {
    codex.code().to_string()
}
