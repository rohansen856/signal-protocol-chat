use thiserror::Error;

#[derive(Error, Debug)]
pub enum SignalError {
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    #[error("Protocol error: {0}")]
    Protocol(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid key format")]
    InvalidKey,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Key not found: {0}")]
    KeyNotFound(String),

    #[error("Contact not found: {0}")]
    ContactNotFound(String),

    #[error("Session not established")]
    NoSession,

    #[error("Message decryption failed")]
    DecryptionFailed,

    #[error("Invalid message format")]
    InvalidMessage,
}

pub type Result<T> = std::result::Result<T, SignalError>;
