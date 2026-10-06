//! SARIF 2.1.0 output, so threat ratings can be consumed by tooling that
//! already reads static-analysis results.

use crate::error::Result;
use crate::report::{json, Report, TOOL_NAME, TOOL_VERSION};
use serde_json::{json, Value};
use std::collections::BTreeMap;

const SCHEMA: &str =
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json";

pub fn render(reports: &[Report]) -> Result<Vec<u8>> {
    // One rule per distinct threat identifier, so a batch of threats
    // produces a stable rule set rather than one rule per occurrence.
    let mut rules: BTreeMap<String, Value> = BTreeMap::new();
    let mut results = Vec::with_capacity(reports.len());

    for report in reports {
        let rule_id = report.id();

        rules.entry(rule_id.clone()).or_insert_with(|| {
            json!({
                "id": rule_id,
                "name": report.assessment.title,
                "shortDescription": { "text": report.assessment.title },
                "fullDescription": { "text": report.derivation() },
                "defaultConfiguration": { "level": report.severity.sarif_level() },
                "properties": {
                    "methodology": "OWASP Risk Rating Methodology",
                    "profile": report.profile.as_str(),
                    "severity": report.severity.as_str(),
                },
            })
        });

        results.push(result_value(report, &rule_id));
    }

    let document = json!({
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "informationUri": "https://github.com/gbiagomba/OWASP-Risk-Rating-Methodology",
                    "rules": rules.into_values().collect::<Vec<_>>(),
                }
            },
            "results": results,
        }],
    });

    let mut bytes = serde_json::to_vec_pretty(&document)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn result_value(report: &Report, rule_id: &str) -> Value {
    let mut result = json!({
        "ruleId": rule_id,
        "level": report.severity.sarif_level(),
        "message": { "text": report.derivation() },
        "properties": {
            "severity": report.severity.as_str(),
            "profile": report.profile.as_str(),
            "likelihood": json::average_value(report.likelihood),
            "impact": {
                "technical": json::average_value(report.technical_impact),
                "business": json::average_value(report.business_impact),
                "overall": json::average_value(report.overall_impact),
                "basis": report.impact_basis.as_str(),
                "used": json::average_value(report.impact_used),
            },
            "factors": json::factors_value(report),
        },
        // A rating is not tied to a source line, so the identifier carries
        // the result's identity across runs. SARIF 2.1.0 allows a result
        // with no location.
        "partialFingerprints": { "riskforge/v1": rule_id },
    });

    if let Some(location) = &report.assessment.location {
        result["locations"] = json!([{
            "physicalLocation": {
                "artifactLocation": { "uri": location }
            }
        }]);
    }

    result
}
