use thiserror::Error;

#[derive(Error, Debug)]
pub enum TpmError {
    #[error("TPM2 error: {0}")]
    Tpm2Error(#[from] tss_esapi::Error),
    #[error("TPM2 not found")]
    NotFound,
}
