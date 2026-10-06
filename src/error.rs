//! Error type for the whole crate.

use std::path::PathBuf;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("standard stream: {0}")]
    Stream(#[source] std::io::Error),

    #[error("{path}: not valid YAML or JSON: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: serde_yaml_ng::Error,
    },

    #[error(
        "{path}: expected a threat mapping, a sequence of threat mappings, \
         or a mapping with a `threats` sequence"
    )]
    Shape { path: PathBuf },

    #[error("{path}: threat {index}: {source}")]
    Threat {
        path: PathBuf,
        index: usize,
        #[source]
        source: Box<Error>,
    },

    #[error("{path}: contains no threats")]
    Empty { path: PathBuf },

    #[error("factor `{key}`: score {value} is out of range, expected 0 to {max}")]
    ScoreOutOfRange { key: String, value: i64, max: u8 },

    #[error("unknown factor `{key}`{}", suggestion.as_ref().map(|s| format!(", did you mean `{s}`?")).unwrap_or_default())]
    UnknownFactor {
        key: String,
        suggestion: Option<String>,
    },

    #[error(
        "missing {} factor{}: {}. Score them, or pass --allow-missing to treat them as 0",
        keys.len(),
        if keys.len() == 1 { "" } else { "s" },
        keys.join(", ")
    )]
    MissingFactors { keys: Vec<String> },

    #[error("a threat needs a non-empty `title`")]
    MissingTitle,

    #[error("format `{format}` writes a binary database and needs --output")]
    NeedsOutput { format: String },

    #[error(
        "--output is a single file but {count} formats were requested; \
         pass a directory instead"
    )]
    OutputNotADirectory { count: usize },

    #[error("{path}: parent directory does not exist. Create it, or pass --mkdir")]
    MissingParent { path: PathBuf },

    #[error(
        "unknown format `{0}`, expected one of: text, json, csv, html, md, sarif, sqlite, sql, all"
    )]
    UnknownFormat(String),

    #[error("no input: stdin is not a terminal, so pass --input or per-factor flags")]
    NoInput,

    #[error("interactive input ended before every factor was scored")]
    InputEnded,

    #[error("serializing JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("writing CSV: {0}")]
    Csv(#[from] csv::Error),

    #[error("{path}: SQLite: {source}")]
    Sqlite {
        path: PathBuf,
        #[source]
        source: rusqlite::Error,
    },
}

impl Error {
    /// Wrap an IO error with the path it happened on.
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Error::Io {
            path: path.into(),
            source,
        }
    }
}
