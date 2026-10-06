//! Severity matrices: `Risk = Likelihood x Impact`.

use crate::model::score::Band;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Which severity matrix to apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    /// Three-band output with no Critical tier, for programs whose threat
    /// tables top out at High. A Low-by-Low pair rates Low rather than Note,
    /// and a High-by-High pair rates High rather than Critical.
    #[default]
    Capped,
    /// The matrix as published with the methodology, including the Note and
    /// Critical tiers.
    Owasp,
}

impl Profile {
    pub fn as_str(self) -> &'static str {
        match self {
            Profile::Capped => "capped",
            Profile::Owasp => "owasp",
        }
    }

    pub fn description(self) -> &'static str {
        match self {
            Profile::Capped => "three-band output, no Critical tier, ceiling of High",
            Profile::Owasp => "as published, includes the Note and Critical tiers",
        }
    }

    /// The severity levels this profile can produce, ascending.
    pub fn levels(self) -> &'static [Severity] {
        match self {
            Profile::Capped => &[Severity::Low, Severity::Medium, Severity::High],
            Profile::Owasp => &[
                Severity::Note,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ],
        }
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// An overall risk severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    Note,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Note => "Note",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }

    /// SARIF result level for this severity.
    pub fn sarif_level(self) -> &'static str {
        match self {
            Severity::Critical | Severity::High => "error",
            Severity::Medium => "warning",
            Severity::Low | Severity::Note => "note",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Look up a severity. The matrix is symmetric in both profiles, so the
/// argument order carries meaning only for the caller's report.
pub fn lookup(profile: Profile, likelihood: Band, impact: Band) -> Severity {
    use Band::{High, Low, Medium};

    match profile {
        Profile::Capped => match (impact, likelihood) {
            (High, Low) => Severity::Medium,
            (High, Medium) => Severity::High,
            (High, High) => Severity::High,
            (Medium, Low) => Severity::Low,
            (Medium, Medium) => Severity::Medium,
            (Medium, High) => Severity::High,
            (Low, Low) => Severity::Low,
            (Low, Medium) => Severity::Low,
            (Low, High) => Severity::Medium,
        },
        Profile::Owasp => match (impact, likelihood) {
            (High, Low) => Severity::Medium,
            (High, Medium) => Severity::High,
            (High, High) => Severity::Critical,
            (Medium, Low) => Severity::Low,
            (Medium, Medium) => Severity::Medium,
            (Medium, High) => Severity::High,
            (Low, Low) => Severity::Note,
            (Low, Medium) => Severity::Low,
            (Low, High) => Severity::Medium,
        },
    }
}

/// The matrix rendered as rows of `(impact band, [severity per likelihood
/// band])`, impact descending, likelihood ascending. Used by the `matrix`
/// subcommand and the report renderers.
pub fn grid(profile: Profile) -> Vec<(Band, [Severity; 3])> {
    [Band::High, Band::Medium, Band::Low]
        .into_iter()
        .map(|impact| {
            (
                impact,
                [
                    lookup(profile, Band::Low, impact),
                    lookup(profile, Band::Medium, impact),
                    lookup(profile, Band::High, impact),
                ],
            )
        })
        .collect()
}
