//! Score threat-model risk with the OWASP Risk Rating Methodology.
//!
//! Sixteen factors are scored 0 to 9. The eight likelihood factors average
//! into a likelihood score and the eight impact factors into an impact
//! score; each average maps to a LOW, MEDIUM or HIGH band, and the two bands
//! meet in a severity matrix: `Risk = Likelihood x Impact`.

pub mod cli;
pub mod error;
pub mod input;
pub mod model;
pub mod report;
