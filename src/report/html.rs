//! Self-contained HTML output. Inline styles only, no network fetches.

use crate::error::Result;
use crate::model::catalog::{factors_in, GROUPS};
use crate::model::matrix::grid;
use crate::report::{Report, TOOL_NAME, TOOL_VERSION};
use std::fmt::Write as _;

const STYLE: &str = r#"
:root { color-scheme: light dark; --fg:#1b1b1f; --bg:#ffffff; --muted:#5c5f66;
  --line:#d8dae0; --head:#f4f5f7; --note:#6b7280; --low:#2f7d32; --med:#b26a00;
  --high:#c62828; --crit:#7b1fa2; }
@media (prefers-color-scheme: dark) { :root { --fg:#e6e6e9; --bg:#15161a;
  --muted:#a0a3ab; --line:#2e3038; --head:#1e2026; --note:#9aa0ab;
  --low:#6cc06f; --med:#e0a33c; --high:#ef6c6c; --crit:#c085e0; } }
* { box-sizing:border-box; }
body { margin:0; padding:2rem 1rem; background:var(--bg); color:var(--fg);
  font:16px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif; }
main { max-width:60rem; margin:0 auto; }
h1 { font-size:1.6rem; margin:0 0 .25rem; }
h2 { font-size:1.25rem; margin:2.5rem 0 .75rem; border-bottom:1px solid var(--line);
  padding-bottom:.35rem; }
h3 { font-size:1rem; margin:1.75rem 0 .5rem; color:var(--muted);
  text-transform:uppercase; letter-spacing:.06em; }
p.lede { color:var(--muted); margin:0 0 2rem; }
table { border-collapse:collapse; width:100%; margin:0 0 1rem; font-size:.93rem; }
caption { text-align:left; color:var(--muted); padding-bottom:.4rem; font-size:.85rem; }
th,td { border:1px solid var(--line); padding:.45rem .6rem; text-align:left;
  vertical-align:top; }
th { background:var(--head); font-weight:600; }
td.num,th.num { text-align:right; font-variant-numeric:tabular-nums; }
dl.meta { display:grid; grid-template-columns:max-content 1fr; gap:.3rem 1rem;
  margin:0 0 1rem; }
dt { color:var(--muted); }
dd { margin:0; }
code { font:.9em ui-monospace,SFMono-Regular,Menlo,monospace;
  background:var(--head); padding:.1em .35em; border-radius:3px; }
.sev { font-weight:700; }
.sev-Note{color:var(--note)} .sev-Low{color:var(--low)} .sev-Medium{color:var(--med)}
.sev-High{color:var(--high)} .sev-Critical{color:var(--crit)}
.assumed { color:var(--muted); font-style:italic; }
.derivation { background:var(--head); border-left:3px solid var(--line);
  padding:.7rem .9rem; margin:0 0 1rem; }
@media (max-width:40rem) { body{padding:1.25rem .75rem} table{font-size:.85rem} }
"#;

pub fn render(reports: &[Report]) -> Result<Vec<u8>> {
    let mut out = String::new();

    let _ = writeln!(
        out,
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n\
         <title>OWASP risk rating</title>\n<style>{STYLE}</style>\n</head>\n<body>\n<main>"
    );
    let _ = writeln!(out, "<h1>OWASP risk rating</h1>");
    let _ = writeln!(
        out,
        "<p class=\"lede\">Produced by <code>{}</code> {} using the OWASP Risk \
         Rating Methodology, <code>Risk = Likelihood x Impact</code>.</p>",
        esc(TOOL_NAME),
        esc(TOOL_VERSION)
    );

    render_summary(&mut out, reports);

    for report in reports {
        render_one(&mut out, report);
    }

    let _ = writeln!(out, "</main>\n</body>\n</html>");
    Ok(out.into_bytes())
}

fn render_summary(out: &mut String, reports: &[Report]) {
    let _ = writeln!(out, "<h2>Threat table</h2>");
    let _ = writeln!(
        out,
        "<table><thead><tr><th>Threat</th><th>Likelihood</th><th>Impact</th>\
         <th>Overall severity</th></tr></thead><tbody>"
    );
    for report in reports {
        let _ = writeln!(
            out,
            "<tr><td>{}</td><td>{} ({})</td><td>{} ({})</td>\
             <td class=\"sev sev-{}\">{}</td></tr>",
            esc(&report.assessment.title),
            report.likelihood_band(),
            report.likelihood,
            report.impact_band(),
            report.impact_used,
            report.severity.as_str(),
            report.severity
        );
    }
    let _ = writeln!(out, "</tbody></table>");
}

fn render_one(out: &mut String, report: &Report) {
    let _ = writeln!(out, "<h2>{}</h2>", esc(&report.assessment.title));

    let _ = writeln!(out, "<dl class=\"meta\">");
    let _ = writeln!(
        out,
        "<dt>Identifier</dt><dd><code>{}</code></dd>",
        esc(&report.id())
    );
    let _ = writeln!(
        out,
        "<dt>Severity</dt><dd class=\"sev sev-{}\">{}</dd>",
        report.severity.as_str(),
        report.severity
    );
    let _ = writeln!(
        out,
        "<dt>Profile</dt><dd><code>{}</code> ({})</dd>",
        report.profile,
        esc(report.profile.description())
    );
    if let Some(notes) = &report.assessment.notes {
        let _ = writeln!(out, "<dt>Notes</dt><dd>{}</dd>", esc(notes));
    }
    if let Some(location) = &report.assessment.location {
        let _ = writeln!(
            out,
            "<dt>Location</dt><dd><code>{}</code></dd>",
            esc(location)
        );
    }
    let _ = writeln!(out, "</dl>");

    let _ = writeln!(out, "<h3>Factors</h3>");
    let _ = writeln!(
        out,
        "<table><thead><tr><th>Group</th><th>Factor</th><th class=\"num\">Score</th>\
         <th>Option</th></tr></thead><tbody>"
    );
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
            let assumed = if entry.assumed {
                " <span class=\"assumed\">(assumed)</span>"
            } else {
                ""
            };
            let _ = writeln!(
                out,
                "<tr><td>{}</td><td>{}</td><td class=\"num\">{}</td><td>{}{}</td></tr>",
                esc(group.title()),
                esc(factor.name),
                entry.score,
                esc(label),
                assumed
            );
        }
    }
    let _ = writeln!(out, "</tbody></table>");

    let _ = writeln!(out, "<h3>Derivation</h3>");
    let _ = writeln!(
        out,
        "<table><thead><tr><th>Measure</th><th class=\"num\">Sum</th>\
         <th class=\"num\">Count</th><th class=\"num\">Average</th><th>Band</th>\
         </tr></thead><tbody>"
    );
    for (name, average) in [
        ("Likelihood", report.likelihood),
        ("Technical impact", report.technical_impact),
        ("Business impact", report.business_impact),
        ("Overall impact", report.overall_impact),
    ] {
        let _ = writeln!(
            out,
            "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td>\
             <td class=\"num\">{}</td><td>{}</td></tr>",
            name,
            average.sum,
            average.count,
            average,
            average.band()
        );
    }
    let _ = writeln!(out, "</tbody></table>");

    let _ = writeln!(
        out,
        "<p class=\"derivation\">{}</p>",
        esc(&report.derivation())
    );

    let assumed = report.assessment.assumed_keys();
    if !assumed.is_empty() {
        let _ = writeln!(
            out,
            "<p class=\"assumed\">Scored 0 by assumption rather than by \
             assessment: {}.</p>",
            esc(&assumed.join(", "))
        );
    }

    let _ = writeln!(out, "<h3>Matrix applied</h3>");
    let _ = writeln!(
        out,
        "<table><caption>Rows are impact, columns are likelihood.</caption>\
         <thead><tr><th>Impact</th><th>LOW</th><th>MEDIUM</th><th>HIGH</th>\
         </tr></thead><tbody>"
    );
    for (impact, row) in grid(report.profile) {
        let _ = write!(out, "<tr><th>{impact}</th>");
        for severity in row {
            let _ = write!(
                out,
                "<td class=\"sev sev-{}\">{}</td>",
                severity.as_str(),
                severity
            );
        }
        let _ = writeln!(out, "</tr>");
    }
    let _ = writeln!(out, "</tbody></table>");
}

/// Escape text for an HTML text node or a double-quoted attribute.
fn esc(text: &str) -> String {
    html_escape::encode_quoted_attribute(text).into_owned()
}
