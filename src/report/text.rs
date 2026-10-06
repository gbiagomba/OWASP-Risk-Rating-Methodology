//! Human-readable report for the terminal.

use crate::error::Result;
use crate::model::catalog::{factors_in, GROUPS};
use crate::report::Report;
use std::fmt::Write as _;

pub fn render(reports: &[Report]) -> Result<Vec<u8>> {
    let mut out = String::new();

    for (index, report) in reports.iter().enumerate() {
        if index > 0 {
            out.push('\n');
        }
        render_one(&mut out, report);
    }

    if reports.len() > 1 {
        render_summary(&mut out, reports);
    }

    Ok(out.into_bytes())
}

fn render_one(out: &mut String, report: &Report) {
    let _ = writeln!(out, "{}", report.assessment.title);
    let _ = writeln!(out, "{}", "=".repeat(report.assessment.title.len()));
    let _ = writeln!(out, "id: {}", report.id());
    if let Some(notes) = &report.assessment.notes {
        let _ = writeln!(out, "notes: {notes}");
    }
    if let Some(location) = &report.assessment.location {
        let _ = writeln!(out, "location: {location}");
    }
    out.push('\n');

    for group in GROUPS {
        let _ = writeln!(out, "{}", group.title());
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
            let assumed = if entry.assumed { "  [assumed]" } else { "" };
            let _ = writeln!(
                out,
                "  {:<24} {}  {}{}",
                factor.name, entry.score, label, assumed
            );
        }
        out.push('\n');
    }

    let _ = writeln!(
        out,
        "Overall likelihood:       {} ({})",
        report.likelihood,
        report.likelihood_band()
    );
    let _ = writeln!(
        out,
        "Overall technical impact: {} ({})",
        report.technical_impact,
        report.technical_impact.band()
    );
    let _ = writeln!(
        out,
        "Overall business impact:  {} ({})",
        report.business_impact,
        report.business_impact.band()
    );
    let _ = writeln!(
        out,
        "Overall impact:           {} ({})",
        report.overall_impact,
        report.overall_impact.band()
    );
    out.push('\n');
    let _ = writeln!(
        out,
        "Risk = Likelihood x Impact = {} x {} = {}",
        report.likelihood_band(),
        report.impact_band(),
        report.severity
    );
    let _ = writeln!(out, "Derivation: {}", report.derivation());

    let assumed = report.assessment.assumed_keys();
    if !assumed.is_empty() {
        let _ = writeln!(
            out,
            "\nScored 0 by assumption, not by assessment: {}",
            assumed.join(", ")
        );
    }
}

fn render_summary(out: &mut String, reports: &[Report]) {
    let _ = writeln!(out, "\nSummary of {} threats", reports.len());
    let _ = writeln!(
        out,
        "{:<10} {:<8} {:<8} THREAT",
        "SEVERITY", "LIKELY", "IMPACT"
    );
    for report in reports {
        let _ = writeln!(
            out,
            "{:<10} {:<8} {:<8} {}",
            report.severity.as_str(),
            report.likelihood_band().as_str(),
            report.impact_band().as_str(),
            report.assessment.title
        );
    }
}
