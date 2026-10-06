//! A scored threat, validated against the factor catalog.

use crate::error::{Error, Result};
use crate::model::catalog::{self, Factor, Group, FACTORS, MAX_SCORE};
use crate::model::score::{Average, ImpactBasis};
use std::collections::BTreeMap;

/// One factor's score within an assessment.
#[derive(Debug, Clone, Copy)]
pub struct FactorScore {
    pub factor: &'static Factor,
    pub score: u8,
    /// True when the input omitted this factor and `--allow-missing` scored
    /// it 0. Reports mark these so an assumed 0 is never mistaken for a
    /// deliberate one.
    pub assumed: bool,
}

/// A threat with all 16 factors scored.
#[derive(Debug, Clone)]
pub struct Assessment {
    pub id: Option<String>,
    pub title: String,
    pub notes: Option<String>,
    /// Optional artifact or code location, carried into SARIF output.
    pub location: Option<String>,
    /// One entry per catalog factor, in catalog order.
    pub scores: Vec<FactorScore>,
}

impl Assessment {
    /// Build an assessment from raw `key -> score` pairs.
    ///
    /// Scores arrive as `i64` so that an out-of-range number reaches this
    /// validation and is reported against its factor, rather than failing
    /// earlier as an opaque integer conversion.
    pub fn build(
        title: String,
        id: Option<String>,
        notes: Option<String>,
        location: Option<String>,
        raw: &BTreeMap<String, i64>,
        allow_missing: bool,
    ) -> Result<Self> {
        if title.trim().is_empty() {
            return Err(Error::MissingTitle);
        }

        // Reject unknown keys rather than ignoring them. A typo must fail
        // loudly instead of silently scoring its factor 0.
        for key in raw.keys() {
            if catalog::factor_by_key(key).is_none() {
                return Err(Error::UnknownFactor {
                    key: key.clone(),
                    suggestion: nearest_key(key),
                });
            }
        }

        let mut missing = Vec::new();
        let mut scores = Vec::with_capacity(FACTORS.len());

        for factor in FACTORS {
            match raw.get(factor.key) {
                Some(&value) => {
                    let score = u8::try_from(value)
                        .ok()
                        .filter(|score| *score <= MAX_SCORE)
                        .ok_or_else(|| Error::ScoreOutOfRange {
                            key: factor.key.to_string(),
                            value,
                            max: MAX_SCORE,
                        })?;
                    scores.push(FactorScore {
                        factor,
                        score,
                        assumed: false,
                    });
                }
                None => {
                    missing.push(factor.key.to_string());
                    scores.push(FactorScore {
                        factor,
                        score: 0,
                        assumed: true,
                    });
                }
            }
        }

        if !missing.is_empty() && !allow_missing {
            return Err(Error::MissingFactors { keys: missing });
        }

        Ok(Assessment {
            id,
            title,
            notes,
            location,
            scores,
        })
    }

    fn scores_in(&self, group: Group) -> Vec<u8> {
        self.scores
            .iter()
            .filter(|entry| entry.factor.group == group)
            .map(|entry| entry.score)
            .collect()
    }

    fn scores_where(&self, predicate: impl Fn(Group) -> bool) -> Vec<u8> {
        self.scores
            .iter()
            .filter(|entry| predicate(entry.factor.group))
            .map(|entry| entry.score)
            .collect()
    }

    /// Average of the eight likelihood factors.
    pub fn likelihood(&self) -> Average {
        Average::of(&self.scores_where(Group::is_likelihood))
    }

    /// Average of the four technical impact factors.
    pub fn technical_impact(&self) -> Average {
        Average::of(&self.scores_in(Group::TechnicalImpact))
    }

    /// Average of the four business impact factors.
    pub fn business_impact(&self) -> Average {
        Average::of(&self.scores_in(Group::BusinessImpact))
    }

    /// Average of all eight impact factors, matching the overall impact
    /// cell of the reference spreadsheet.
    pub fn overall_impact(&self) -> Average {
        Average::of(&self.scores_where(Group::is_impact))
    }

    /// The impact average that the chosen basis carries into the matrix.
    ///
    /// Under `Business`, an all-zero business group is read as unscored and
    /// the technical average is used instead, following the methodology's
    /// guidance that business impact governs only when it is known.
    pub fn impact_for(&self, basis: ImpactBasis) -> (ImpactBasis, Average) {
        match basis {
            ImpactBasis::Overall => (ImpactBasis::Overall, self.overall_impact()),
            ImpactBasis::Technical => (ImpactBasis::Technical, self.technical_impact()),
            ImpactBasis::Business => {
                let business = self.business_impact();
                if business.sum == 0 {
                    (ImpactBasis::Technical, self.technical_impact())
                } else {
                    (ImpactBasis::Business, business)
                }
            }
        }
    }

    /// Factor keys whose scores were assumed rather than supplied.
    pub fn assumed_keys(&self) -> Vec<&'static str> {
        self.scores
            .iter()
            .filter(|entry| entry.assumed)
            .map(|entry| entry.factor.key)
            .collect()
    }
}

/// Closest catalog key to a misspelled one, for a did-you-mean hint.
fn nearest_key(key: &str) -> Option<String> {
    FACTORS
        .iter()
        .map(|factor| (edit_distance(key, factor.key), factor.key))
        .filter(|(distance, _)| *distance <= 3)
        .min_by_key(|(distance, _)| *distance)
        .map(|(_, candidate)| candidate.to_string())
}

/// Levenshtein distance, two rows at a time.
fn edit_distance(left: &str, right: &str) -> usize {
    let right: Vec<char> = right.chars().collect();
    let mut previous: Vec<usize> = (0..=right.len()).collect();
    let mut current = vec![0usize; right.len() + 1];

    for (i, left_char) in left.chars().enumerate() {
        current[0] = i + 1;
        for (j, right_char) in right.iter().enumerate() {
            let substitution = previous[j] + usize::from(left_char != *right_char);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[right.len()]
}
