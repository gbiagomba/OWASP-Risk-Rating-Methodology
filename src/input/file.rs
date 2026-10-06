//! YAML and JSON input. YAML is a superset of JSON, so one parser reads both.

use crate::error::{Error, Result};
use crate::model::assessment::Assessment;
use serde::Deserialize;
use serde_yaml_ng::Value;
use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};

/// One threat as written in an input file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawThreat {
    title: String,
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    notes: Option<String>,
    #[serde(default)]
    location: Option<String>,
    /// Factor keys to scores. Scores are read as `i64` so that an
    /// out-of-range number reaches catalog validation and is reported
    /// against its factor.
    #[serde(default)]
    factors: BTreeMap<String, i64>,
}

/// Read every threat from a file, or from standard input when `path` is `-`.
pub fn load(path: &Path, allow_missing: bool) -> Result<Vec<Assessment>> {
    let (text, display) = read_source(path)?;
    parse(&text, &display, allow_missing)
}

fn read_source(path: &Path) -> Result<(String, PathBuf)> {
    if path.as_os_str() == "-" {
        let mut text = String::new();
        std::io::stdin()
            .read_to_string(&mut text)
            .map_err(Error::Stream)?;
        Ok((text, PathBuf::from("<stdin>")))
    } else {
        let text = std::fs::read_to_string(path).map_err(|source| Error::io(path, source))?;
        Ok((text, path.to_path_buf()))
    }
}

/// Parse input text into assessments.
///
/// Three shapes are accepted: a single threat mapping, a sequence of threat
/// mappings, or a mapping with a `threats` sequence. The shape is decided
/// before deserializing so that a malformed threat produces an error naming
/// its field, rather than a generic "no variant matched".
pub fn parse(text: &str, display: &Path, allow_missing: bool) -> Result<Vec<Assessment>> {
    let value: Value = serde_yaml_ng::from_str(text).map_err(|source| Error::Parse {
        path: display.to_path_buf(),
        source,
    })?;

    let raw_threats = match &value {
        Value::Sequence(items) => items.clone(),
        Value::Mapping(mapping) => match mapping.get(Value::from("threats")) {
            Some(Value::Sequence(items)) => items.clone(),
            Some(_) => {
                return Err(Error::Shape {
                    path: display.to_path_buf(),
                })
            }
            None => vec![value.clone()],
        },
        _ => {
            return Err(Error::Shape {
                path: display.to_path_buf(),
            })
        }
    };

    if raw_threats.is_empty() {
        return Err(Error::Empty {
            path: display.to_path_buf(),
        });
    }

    let mut assessments = Vec::with_capacity(raw_threats.len());

    for (index, raw_value) in raw_threats.into_iter().enumerate() {
        let threat: RawThreat =
            serde_yaml_ng::from_value(raw_value).map_err(|source| Error::Threat {
                path: display.to_path_buf(),
                index: index + 1,
                source: Box::new(Error::Parse {
                    path: display.to_path_buf(),
                    source,
                }),
            })?;

        let assessment = Assessment::build(
            threat.title,
            threat.id,
            threat.notes,
            threat.location,
            &threat.factors,
            allow_missing,
        )
        .map_err(|source| Error::Threat {
            path: display.to_path_buf(),
            index: index + 1,
            source: Box::new(source),
        })?;

        assessments.push(assessment);
    }

    Ok(assessments)
}
