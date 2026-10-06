//! Markdown output, including a threat-table row ready to paste.

use crate::error::Result;
use crate::model::catalog::{factors_in, GROUPS};
use crate::model::matrix::grid;
use crate::report::{Report, TOOL_NAME, TOOL_VERSION};
use std::fmt::Write as _;

pub fn render(reports: &[Report]) -> Result<Vec<u8>> {
    let mut out = String::new();

    let _ = writeln!(out, "# OWASP risk rating\n");
    let _ = writeln!(
        out,
        "Produced by `{TOOL_NAME}` {TOOL_VERSION} using the OWASP Risk Rating \
         Methodology, `Risk = Likelihood x Impact`.\n"
    );

    render_threat_table(&mut out, reports);

    for report in reports {
        render_one(&mut out, report);
    }

    Ok(out.into_bytes())
}

/// The paste-ready threat table, one row per threat.
fn render_threat_table(out: &mut String, reports: &[Report]) {
    let _ = writeln!(out, "## Threat table\n");
    let _ = writeln!(out, "| Threat | Likelihood | Impact | Overall severity |");
    let _ = writeln!(out, "|---|---|---|---|");
    for report in reports {
        let _ = writeln!(
            out,
            "| {} | {} ({}) | {} ({}) | {} |",
            escape(&report.assessment.title),
            report.likelihood_band(),
            report.likelihood,
            report.impact_band(),
            report.impact_used,
            report.severity
        );
    }
    out.push('\n');
}

fn render_one(out: &mut String, report: &Report) {
    let _ = writeln!(out, "## {}\n", escape(&report.assessment.title));
    let _ = writeln!(out, "- **Identifier:** `{}`", report.id());
    let _ = writeln!(out, "- **Severity:** {}", report.severity);
    let _ = writeln!(
        out,
        "- **Profile:** `{}` ({})",
        report.profile,
        report.profile.description()
    );
    if let Some(notes) = &report.assessment.notes {
        let _ = writeln!(out, "- **Notes:** {}", escape(notes));
    }
    if let Some(location) = &report.assessment.location {
        let _ = writeln!(out, "- **Location:** `{location}`");
    }
    out.push('\n');

    let _ = writeln!(out, "### Factors\n");
    let _ = writeln!(out, "| Group | Factor | Score | Option |");
    let _ = writeln!(out, "|---|---|---|---|");
    for group in GROUPS {
        for factor in factors_in(group) {
            let entry = report
                .assessment
                .scores
                .iter()
                .find(|entry| entry.factor.key == factor.key)
                .expect("every catalog factor is scored");
            let label = factor
                .anchor(entry.score)
                .unwrap_or("between anchors, interpolated");
            let assumed = if entry.assumed { " (assumed)" } else { "" };
            let _ = writeln!(
                out,
                "| {} | {} | {} | {}{} |",
                group.title(),
                factor.name,
                entry.score,
                escape(label),
                assumed
            );
        }
    }
    out.push('\n');

    let _ = writeln!(out, "### Derivation\n");
    let _ = writeln!(out, "| Measure | Sum | Count | Average | Band |");
    let _ = writeln!(out, "|---|---|---|---|---|");
    for (name, average) in [
        ("Likelihood", report.likelihood),
        ("Technical impact", report.technical_impact),
        ("Business impact", report.business_impact),
        ("Overall impact", report.overall_impact),
    ] {
        let _ = writeln!(
            out,
            "| {} | {} | {} | {} | {} |",
            name,
            average.sum,
            average.count,
            average,
            average.band()
        );
    }
    out.push('\n');
    let _ = writeln!(
        out,
        "Impact basis `{}` carries {} ({}) into the matrix.\n",
        report.impact_basis,
        report.impact_used,
        report.impact_band()
    );
    let _ = writeln!(
        out,
        "`{} x {} = {}` under the `{}` profile.\n",
        report.likelihood_band(),
        report.impact_band(),
        report.severity,
        report.profile
    );

    let assumed = report.assessment.assumed_keys();
    if !assumed.is_empty() {
        let _ = writeln!(
            out,
            "Scored 0 by assumption rather than by assessment: {}.\n",
            assumed
                .iter()
                .map(|key| format!("`{key}`"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let _ = writeln!(out, "### Matrix applied\n");
    let _ = writeln!(out, "| Impact | Likelihood LOW | MEDIUM | HIGH |");
    let _ = writeln!(out, "|---|---|---|---|");
    for (impact, row) in grid(report.profile) {
        let _ = writeln!(out, "| {} | {} | {} | {} |", impact, row[0], row[1], row[2]);
    }
    out.push('\n');
}

/// Escape the pipe and backslash characters that would break a table cell.
fn escape(text: &str) -> String {
    text.replace('\\', "\\\\").replace('|', "\\|")
}
