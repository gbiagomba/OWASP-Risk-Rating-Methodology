//! SQLite output. Values are bound as parameters, never interpolated.

use crate::error::{Error, Result};
use crate::report::{sql, Report, TOOL_VERSION};
use rusqlite::{params, Connection};
use std::path::Path;

pub fn write(reports: &[Report], path: &Path) -> Result<()> {
    let wrap = |source: rusqlite::Error| Error::Sqlite {
        path: path.to_path_buf(),
        source,
    };

    let mut connection = Connection::open(path).map_err(wrap)?;
    connection.execute_batch(sql::SCHEMA).map_err(wrap)?;

    let transaction = connection.transaction().map_err(wrap)?;

    for report in reports {
        let id = report.id();
        let generated_at = report.generated_at.to_rfc3339();

        transaction
            .execute(
                "INSERT INTO assessment VALUES \
                 (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                  ?15, ?16, ?17, ?18, ?19, ?20, ?21)",
                params![
                    id,
                    report.assessment.title,
                    report.assessment.notes,
                    report.assessment.location,
                    report.profile.as_str(),
                    report.likelihood.sum,
                    report.likelihood.rounded(),
                    report.likelihood_band().as_str(),
                    report.technical_impact.rounded(),
                    report.technical_impact.band().as_str(),
                    report.business_impact.rounded(),
                    report.business_impact.band().as_str(),
                    report.overall_impact.rounded(),
                    report.overall_impact.band().as_str(),
                    report.impact_basis.as_str(),
                    report.impact_used.rounded(),
                    report.impact_band().as_str(),
                    report.severity.as_str(),
                    report.derivation(),
                    TOOL_VERSION,
                    generated_at,
                ],
            )
            .map_err(wrap)?;

        for entry in &report.assessment.scores {
            transaction
                .execute(
                    "INSERT INTO factor_score VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        id,
                        generated_at,
                        entry.factor.key,
                        entry.factor.name,
                        format!("{:?}", entry.factor.group).to_lowercase(),
                        entry.score,
                        entry.factor.anchor(entry.score),
                        entry.assumed,
                    ],
                )
                .map_err(wrap)?;
        }
    }

    transaction.commit().map_err(wrap)?;
    Ok(())
}
