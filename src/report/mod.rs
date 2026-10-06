//! Reports: the derivation of one threat's severity, and the renderers that
//! write it out.

pub mod csv_out;
pub mod html;
pub mod json;
pub mod markdown;
pub mod sarif;
pub mod sql;
pub mod sqlite;
pub mod text;

use crate::error::Result;
use crate::model::assessment::Assessment;
use crate::model::matrix::{self, Profile, Severity};
use crate::model::score::{Average, Band, ImpactBasis};
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use std::fmt;

/// Version of the tool that produced a report.
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const TOOL_NAME: &str = env!("CARGO_PKG_NAME");

/// One threat's scores together with every number derived from them.
#[derive(Debug, Clone)]
pub struct Report {
    pub assessment: Assessment,
    pub profile: Profile,
    pub likelihood: Average,
    pub technical_impact: Average,
    pub business_impact: Average,
    pub overall_impact: Average,
    /// The basis actually applied, which can differ from the one requested
    /// when `business` falls back to `technical`.
    pub impact_basis: ImpactBasis,
    /// The impact average carried into the matrix.
    pub impact_used: Average,
    pub severity: Severity,
    pub generated_at: DateTime<Utc>,
}

impl Report {
    pub fn new(assessment: Assessment, profile: Profile, requested: ImpactBasis) -> Self {
        let likelihood = assessment.likelihood();
        let (impact_basis, impact_used) = assessment.impact_for(requested);
        let severity = matrix::lookup(profile, likelihood.band(), impact_used.band());

        Report {
            likelihood,
            technical_impact: assessment.technical_impact(),
            business_impact: assessment.business_impact(),
            overall_impact: assessment.overall_impact(),
            impact_basis,
            impact_used,
            severity,
            profile,
            generated_at: Utc::now(),
            assessment,
        }
    }

    pub fn likelihood_band(&self) -> Band {
        self.likelihood.band()
    }

    pub fn impact_band(&self) -> Band {
        self.impact_used.band()
    }

    /// Stable identifier: the supplied id, else a slug of the title.
    pub fn id(&self) -> String {
        self.assessment
            .id
            .clone()
            .unwrap_or_else(|| slug(&self.assessment.title))
    }

    /// One line stating how the severity was reached.
    pub fn derivation(&self) -> String {
        format!(
            "likelihood {} ({}) x impact {} ({}, {} basis) = {} under the {} profile",
            self.likelihood,
            self.likelihood_band(),
            self.impact_used,
            self.impact_band(),
            self.impact_basis,
            self.severity,
            self.profile
        )
    }
}

/// Lowercase, hyphen-separated slug of a title.
pub fn slug(title: &str) -> String {
    let mut out = String::with_capacity(title.len());
    let mut pending_separator = false;

    for character in title.chars() {
        if character.is_ascii_alphanumeric() {
            if pending_separator && !out.is_empty() {
                out.push('-');
            }
            pending_separator = false;
            out.push(character.to_ascii_lowercase());
        } else {
            pending_separator = true;
        }
    }

    if out.is_empty() {
        "threat".to_string()
    } else {
        out
    }
}

/// An output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
#[value(rename_all = "lower")]
pub enum Format {
    /// Human-readable report on the terminal.
    Text,
    Json,
    Csv,
    Html,
    /// Markdown, including a threat-table row ready to paste.
    Md,
    /// SARIF 2.1.0, for tools that consume static-analysis results.
    Sarif,
    /// A SQLite database file. Requires `--output`.
    Sqlite,
    /// Portable SQL statements carrying the same schema as `sqlite`.
    Sql,
}

impl Format {
    /// Every format, which is what `--format all` expands to.
    pub const ALL: [Format; 8] = [
        Format::Text,
        Format::Json,
        Format::Csv,
        Format::Html,
        Format::Md,
        Format::Sarif,
        Format::Sqlite,
        Format::Sql,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Format::Text => "text",
            Format::Json => "json",
            Format::Csv => "csv",
            Format::Html => "html",
            Format::Md => "md",
            Format::Sarif => "sarif",
            Format::Sqlite => "sqlite",
            Format::Sql => "sql",
        }
    }

    /// File extension used when `--output` names a directory.
    pub fn extension(self) -> &'static str {
        match self {
            Format::Text => "txt",
            Format::Json => "json",
            Format::Csv => "csv",
            Format::Html => "html",
            Format::Md => "md",
            Format::Sarif => "sarif",
            Format::Sqlite => "db",
            Format::Sql => "sql",
        }
    }

    /// True when the format writes a binary file directly and so cannot be
    /// streamed to standard output.
    pub fn is_binary(self) -> bool {
        matches!(self, Format::Sqlite)
    }

    /// Render to bytes. Binary formats return an error here and are written
    /// through their own path instead.
    pub fn render(self, reports: &[Report]) -> Result<Vec<u8>> {
        match self {
            Format::Text => text::render(reports),
            Format::Json => json::render(reports),
            Format::Csv => csv_out::render(reports),
            Format::Html => html::render(reports),
            Format::Md => markdown::render(reports),
            Format::Sarif => sarif::render(reports),
            Format::Sql => sql::render(reports),
            Format::Sqlite => Err(crate::error::Error::NeedsOutput {
                format: self.as_str().to_string(),
            }),
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
