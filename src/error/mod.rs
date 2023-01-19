use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("matter error: {0}")]
    MatterError(String),
    #[error("empty material")]
    EmptyMaterialError(),
    #[error("decode error: {0}")]
    DecodeError(String),
    #[error("unexpected code error: {0}")]
    UnexpectedCodeError(String),
    #[error("shortage")]
    ShortageError(),
    #[error("empty qb64")]
    EmptyQb64Error(),
    #[error("unknown sizage {0}")]
    UnknownSizage(String),
    #[error("unknown hardage {0}")]
    UnknownHardage(String),
    #[error("variable size codes not supported")]
    UnsupportedSizeError(),
    #[error("need {0} more characters")]
    TooSmallError(usize),
    #[error("prepad error")]
    PrepadError(),
    #[error("Non zeroed prepad bits")]
    NonZeroedPrepad(),
    #[error("Non zeroed lead byte")]
    NonZeroedLeadByte(),
    #[error("Non zeroed lead bytes")]
    NonZeroedLeadBytes(),
    #[error("error parsing qb64b {0}")]
    ParseQb64Error(String),
}
