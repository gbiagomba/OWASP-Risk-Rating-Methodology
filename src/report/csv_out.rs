//! Flat CSV output, one row per threat.

use crate::error::Result;
use crate::model::catalog::FACTORS;
use crate::report::Report;

pub fn render(reports: &[Report]) -> Result<Vec<u8>> {
    let mut writer = csv::Writer::from_writer(Vec::new());

    let mut header: Vec<String> = vec!["id".into(), "title".into()];
    header.extend(FACTORS.iter().map(|factor| factor.key.to_string()));
    header.extend(
        [
            "likelihood_average",
            "likelihood_band",
            "technical_impact_average",
            "technical_impact_band",
            "business_impact_average",
            "business_impact_band",
            "overall_impact_average",
            "overall_impact_band",
            "impact_basis",
            "impact_used_average",
            "impact_used_band",
            "profile",
            "severity",
        ]
        .iter()
        .map(|column| column.to_string()),
    );
    writer.write_record(&header)?;

    for report in reports {
        let mut row: Vec<String> = vec![report.id(), report.assessment.title.clone()];
        row.extend(
            report
                .assessment
                .scores
                .iter()
                .map(|entry| entry.score.to_string()),
        );
        row.extend([
            report.likelihood.rounded().to_string(),
            report.likelihood_band().to_string(),
            report.technical_impact.rounded().to_string(),
            report.technical_impact.band().to_string(),
            report.business_impact.rounded().to_string(),
            report.business_impact.band().to_string(),
            report.overall_impact.rounded().to_string(),
            report.overall_impact.band().to_string(),
            report.impact_basis.to_string(),
            report.impact_used.rounded().to_string(),
            report.impact_band().to_string(),
            report.profile.to_string(),
            report.severity.to_string(),
        ]);
        writer.write_record(&row)?;
    }

    writer.flush().map_err(crate::error::Error::Stream)?;
    writer
        .into_inner()
        .map_err(|err| crate::error::Error::Stream(std::io::Error::other(err.to_string())))
}
