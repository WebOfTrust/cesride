pub type BoxedError = Box<dyn std::error::Error>;
pub type Result<T> = core::result::Result<T, BoxedError>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("matter error: {0}")]
    Matter(String),
    #[error("empty material: {0}")]
    EmptyMaterial(String),
    #[error("decode error: {0}")]
    Decode(String),
    #[error("unexpected code error: {0}")]
    UnexpectedCode(String),
    #[error("unexpected count code error: {0}")]
    UnexpectedCountCode(String),
    #[error("unexpected op code error: {0}")]
    UnexpectedOpCode(String),
    #[error("invalid variable size: {0}")]
    InvalidVarSize(String),
    #[error("invalid variable raw size: {0}")]
    InvalidVarRawSize(String),
    #[error("invalid code size: {0}")]
    InvalidCodeSize(String),
    #[error("shortage: {0}")]
    Shortage(String),
    #[error("empty qb64")]
    EmptyQb64(),
    #[error("unknown sizage: {0}")]
    UnknownSizage(String),
    #[error("unknown hardage: {0}")]
    UnknownHardage(String),
    #[error("variable size codes not supported")]
    UnsupportedSize(),
    #[error("need {0} more characters")]
    TooSmall(usize),
    #[error("prepad error")]
    Prepad(),
    #[error("non-zeroed prepad bits")]
    NonZeroedPrepad(),
    #[error("non-zeroed lead byte")]
    NonZeroedLeadByte(),
    #[error("non-zeroed lead bytes")]
    NonZeroedLeadBytes(),
    #[error("non-zeroed pad bits")]
    NonZeroedPadBits(),
    #[error("error parsing qb64: {0}")]
    ParseQb64(String),
    #[error("error parsing qb2: {0}")]
    ParseQb2(String),
    #[error("conversion error: {0}")]
    Conversion(String),
    #[error("{0}")]
    InvalidVarIndex(String),
}
