//! The crate error type, one `thiserror` enum spanning config loading,
//! validation, and routing.

use thiserror::Error;

/// Errors surfaced by config loading, validation, and the routing brain.
#[derive(Debug, Error)]
pub enum Error {
    /// The config file could not be read from disk.
    #[error("reading config {path}: {source}")]
    Io {
        /// The path that failed to read.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The YAML did not parse into the config model.
    #[error("parsing config: {0}")]
    Yaml(#[from] serde_yaml::Error),

    /// A point-code string in the config was malformed for its variant.
    #[error("invalid point code: {0}")]
    PointCode(#[from] mtp3::PointCodeError),

    /// The config is structurally valid YAML but semantically inconsistent:
    /// a dangling reference, a duplicate name, an empty required set, and so on.
    #[error("invalid config: {0}")]
    Validation(String),
}

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Build a [`Error::Validation`] from any displayable message.
    pub(crate) fn validation(msg: impl Into<String>) -> Self {
        Error::Validation(msg.into())
    }
}
