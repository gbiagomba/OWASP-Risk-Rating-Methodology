//! Averaging and band mapping.
//!
//! Band boundaries are compared on integer sums rather than on the floating
//! point average, so a value sitting exactly on a boundary can never land in
//! the wrong band through rounding. For `count` factors, `average < 3` holds
//! exactly when `sum < 3 * count`, and `average < 6` when `sum < 6 * count`.
//! Floating point appears only in `Average::value`, used for display.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A likelihood or impact level, per the spreadsheet thresholds
/// `0 to <3 = LOW`, `3 to <6 = MEDIUM`, `6 to 9 = HIGH`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Band {
    Low,
    Medium,
    High,
}

impl Band {
    pub fn as_str(self) -> &'static str {
        match self {
            Band::Low => "LOW",
            Band::Medium => "MEDIUM",
            Band::High => "HIGH",
        }
    }
}

impl fmt::Display for Band {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The mean of a set of factor scores, retained as an exact sum and count.
///
/// A score of `0` is a real score and not an absence of one, so `count` is
/// always the full number of factors in the set and never shrinks. The
/// reference spreadsheet depends on this: its technical impact is
/// `(2 + 0 + 0 + 9) / 4 = 2.75`, not `(2 + 9) / 2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Average {
    pub sum: u32,
    pub count: u32,
}

impl Average {
    /// Average a set of factor scores.
    ///
    /// # Panics
    /// Panics when `scores` is empty. Every call site draws its scores from
    /// a non-empty group of the factor catalog, so an empty set is a
    /// programming error rather than a possible input.
    pub fn of(scores: &[u8]) -> Self {
        assert!(
            !scores.is_empty(),
            "an average needs at least one factor score"
        );
        Average {
            sum: scores.iter().map(|score| u32::from(*score)).sum(),
            count: scores.len() as u32,
        }
    }

    /// The mean, for display only. Never used to decide a band.
    pub fn value(&self) -> f64 {
        f64::from(self.sum) / f64::from(self.count)
    }

    /// The mean rounded to three decimal places, matching the precision the
    /// reference spreadsheet displays (for example `3.375`).
    pub fn rounded(&self) -> f64 {
        (self.value() * 1000.0).round() / 1000.0
    }

    /// The band this average falls in, decided by integer comparison.
    pub fn band(&self) -> Band {
        if self.sum < 3 * self.count {
            Band::Low
        } else if self.sum < 6 * self.count {
            Band::Medium
        } else {
            Band::High
        }
    }
}

impl fmt::Display for Average {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:.3}", self.rounded())
    }
}

/// Which impact average is carried into the severity matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactBasis {
    /// All eight impact factors averaged together. Matches the reference
    /// spreadsheet, whose overall impact cell averages both groups.
    #[default]
    Overall,
    /// The four technical impact factors only.
    Technical,
    /// The four business impact factors, which the methodology treats as
    /// governing when they are known. Falls back to the technical average
    /// when every business factor is unscored.
    Business,
}

impl ImpactBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            ImpactBasis::Overall => "overall",
            ImpactBasis::Technical => "technical",
            ImpactBasis::Business => "business",
        }
    }
}

impl fmt::Display for ImpactBasis {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}
