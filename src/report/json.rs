//! JSON output, and the shared value shape that SARIF properties reuse.

use crate::error::Result;
use crate::model::score::Average;
use crate::report::{Report, TOOL_NAME, TOOL_VERSION};
use serde_json::{json, Map, Value};

/// An average rendered with its exact sum, its display value and its band.
pub fn average_value(average: Average) -> Value {
    json!({
        "sum": average.sum,
        "count": average.count,
        "average": average.rounded(),
        "band": average.band(),
    })
}

/// Every factor of one report, keyed by catalog key.
pub fn factors_value(report: &Report) -> Value {
    let mut factors = Map::new();

    for entry in &report.assessment.scores {
        factors.insert(
            entry.factor.key.to_string(),
            json!({
                "name": entry.factor.name,
                "group": entry.factor.group,
                "score": entry.score,
                "anchor": entry.factor.anchor(entry.score),
                "assumed": entry.assumed,
            }),
        );
    }

    Value::Object(factors)
}

/// One report as a JSON value.
pub fn report_value(report: &Report) -> Value {
    json!({
        "id": report.id(),
        "title": report.assessment.title,
        "notes": report.assessment.notes,
        "location": report.assessment.location,
        "profile": report.profile.as_str(),
        "factors": factors_value(report),
        "likelihood": average_value(report.likelihood),
        "impact": {
            "technical": average_value(report.technical_impact),
            "business": average_value(report.business_impact),
            "overall": average_value(report.overall_impact),
            "basis": report.impact_basis.as_str(),
            "used": average_value(report.impact_used),
        },
        "severity": report.severity.as_str(),
        "derivation": report.derivation(),
        "assumed_factors": report.assessment.assumed_keys(),
    })
}

pub fn render(reports: &[Report]) -> Result<Vec<u8>> {
    let generated_at = reports
        .first()
        .map(|report| report.generated_at.to_rfc3339())
        .unwrap_or_default();

    let document = json!({
        "tool": { "name": TOOL_NAME, "version": TOOL_VERSION },
        "methodology": "OWASP Risk Rating Methodology",
        "generated_at": generated_at,
        "threats": reports.iter().map(report_value).collect::<Vec<_>>(),
    });

    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');
    Ok(bytes)
}
