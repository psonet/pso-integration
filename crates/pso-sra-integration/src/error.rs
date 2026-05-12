//! Error types for FFI operations.
//!
//! Error messages must never contain key material or intermediate crypto values.

use thiserror::Error;

#[derive(Error, Debug, uniffi::Error)]
#[uniffi(flat_error)]
pub enum OwnershipError {
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),
}

impl From<pso_integrations_shared::CryptoError> for OwnershipError {
    fn from(e: pso_integrations_shared::CryptoError) -> Self {
        match e {
            pso_integrations_shared::CryptoError::InvalidSecretKey(s) => {
                OwnershipError::InvalidSecretKey(s)
            }
            pso_integrations_shared::CryptoError::InvalidPublicKey(s) => {
                OwnershipError::InvalidPublicKey(s)
            }
            pso_integrations_shared::CryptoError::CryptoOperation(s) => {
                OwnershipError::CryptoError(s)
            }
        }
    }
}
