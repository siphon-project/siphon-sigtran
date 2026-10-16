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
    #[error("parsing config: {}{source}", key_path_prefix(path))]
    Yaml {
        /// The key path the error happened at (`sccp.gtt[0].to.dpc`); empty
        /// when it is the document itself, or the YAML did not parse at all.
        path: String,
        /// The parser's error, with the line, column and a source snippet.
        /// Boxed: it is large, and every `Result` in the crate carries it.
        source: Box<serde_saphyr::Error>,
    },

    /// A point-code string in the config was malformed for its variant.
    #[error("invalid point code: {0}")]
    PointCode(#[from] mtp3::PointCodeError),

    /// The config is structurally valid YAML but semantically inconsistent:
    /// a dangling reference, a duplicate name, an empty required set, and so on.
    #[error("invalid config: {0}")]
    Validation(String),
}

/// `path: ` ahead of the parser's message, or nothing at the document root.
fn key_path_prefix(path: &str) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!("{path}: ")
    }
}

/// Convenience alias for results in this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// Build a [`Error::Validation`] from any displayable message.
    pub(crate) fn validation(msg: impl Into<String>) -> Self {
        Error::Validation(msg.into())
    }
}
