use thiserror::Error;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

use crate::pok_sig::PoKOfSignatureProofStatus;

/// The kinds of errors that can be generated
#[derive(Debug, Error, Clone)]
pub enum BBSErrorKind {
    /// Error during key generation
    #[error("Key generation error")]
    KeyGenError,
    /// When there are more messages than public key generators
    #[error("Public key to message mismatch. Expected {0}, found {1}")]
    PublicKeyGeneratorMessageCountMismatch(usize, usize),
    /// When the signature is the incorrect size when calling from_bytes
    #[error("Signature incorrect size. Expected 193, found {0}")]
    SignatureIncorrectSize(usize),
    /// When the signature bytes are not a valid curve point
    #[error("Signature cannot be loaded due to a bad value")]
    SignatureValueIncorrectSize,
    /// When a signature contains a zero or a point at infinity
    #[error("Malformed signature")]
    MalformedSignature,
    /// When a secret key is all zeros
    #[error("Malformed secret key")]
    MalformedSecretKey,
    /// When the public key bytes are not valid curve points
    #[error("Malformed public key")]
    MalformedPublicKey,
    /// Signature proof-of-knowledge error
    #[error("Signature proof-of-knowledge error: {msg}")]
    SignaturePoKError {
        /// The error message
        msg: String,
    },
    /// Incorrect number of bytes passed to from_bytes methods
    #[error("Invalid number of bytes. Expected {0}, found {1}")]
    InvalidNumberOfBytes(usize, usize),
    /// Failed signature poof of knowledge
    #[error("The proof failed due to {status}")]
    InvalidProof {
        /// The status of the invalid proof
        status: PoKOfSignatureProofStatus,
    },
    /// A Generic error
    #[error("{msg}")]
    GeneralError {
        /// The error message
        msg: String,
    },
}

/// Wrapper to hold the kind of error and a backtrace
#[derive(Debug, Error, Clone)]
#[error(transparent)]
pub struct BBSError {
    #[from]
    inner: BBSErrorKind,
}

impl BBSError {
    /// Get the inner error kind
    pub fn from_kind(kind: BBSErrorKind) -> Self {
        BBSError { inner: kind }
    }

    /// Get the inner error kind
    pub fn kind(&self) -> &BBSErrorKind {
        &self.inner
    }
}

impl From<String> for BBSError {
    fn from(msg: String) -> BBSError {
        BBSError::from_kind(BBSErrorKind::GeneralError { msg })
    }
}

impl From<std::io::Error> for BBSError {
    fn from(err: std::io::Error) -> BBSError {
        BBSError::from(format!("{:?}", err))
    }
}

#[cfg(feature = "wasm")]
impl From<BBSError> for JsValue {
    fn from(error: BBSError) -> Self {
        JsValue::from_str(&format!("{}", error))
    }
}

#[cfg(feature = "wasm")]
impl From<JsValue> for BBSError {
    fn from(js: JsValue) -> Self {
        if js.is_string() {
            BBSError::from(BBSErrorKind::GeneralError {
                msg: js.as_string().unwrap(),
            })
        } else {
            BBSError::from(BBSErrorKind::GeneralError {
                msg: "".to_string(),
            })
        }
    }
}

#[cfg(feature = "wasm")]
impl From<serde_wasm_bindgen::Error> for BBSError {
    fn from(err: serde_wasm_bindgen::Error) -> Self {
        BBSError::from(BBSErrorKind::GeneralError {
            msg: format!("{:?}", err),
        })
    }
}

#[cfg(feature = "wasm")]
impl From<BBSError> for serde_wasm_bindgen::Error {
    fn from(err: BBSError) -> Self {
        serde_wasm_bindgen::Error::new(err)
    }
}
