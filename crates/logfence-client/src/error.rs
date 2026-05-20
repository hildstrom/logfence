//! Error types for the logfence client library.

use thiserror::Error;

// ── BuildError ────────────────────────────────────────────────────────────────

/// Errors that occur while constructing a [`crate::MessageBuilder`].
#[derive(Debug, Error)]
pub enum BuildError {
    /// A `kv` field key was the empty string.
    #[error("field key must not be empty")]
    EmptyKey,

    /// A `kv` field value could not be serialized to JSON.
    #[error("value serialization failed: {0}")]
    Serialize(#[from] serde_json::Error),
}

// ── ClientError ───────────────────────────────────────────────────────────────

/// Errors that occur while sending a syslog message.
#[derive(Debug, Error)]
pub enum ClientError {
    /// The message construction step failed.
    #[error("build error: {0}")]
    Build(#[from] BuildError),

    /// The rendered message exceeds the transport's size limit.
    #[error("message size {got} bytes exceeds maximum of {max} bytes")]
    MessageTooLarge { max: usize, got: usize },

    /// An underlying I/O error (connection failure, broken pipe, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
