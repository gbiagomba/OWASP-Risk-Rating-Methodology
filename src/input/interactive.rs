//! Interactive scoring: one prompt per factor, driven by the catalog.

use crate::error::{Error, Result};
use crate::model::assessment::Assessment;
use crate::model::catalog::{FACTORS, MAX_SCORE};
use std::collections::BTreeMap;
use std::io::{BufRead, Write};

/// Walk the operator through every factor and build one assessment.
pub fn prompt(
    input: &mut impl BufRead,
    output: &mut impl Write,
    title: Option<String>,
    id: Option<String>,
    notes: Option<String>,
    location: Option<String>,
) -> Result<Assessment> {
    writeln!(
        output,
        "OWASP Risk Rating Methodology. Score each factor 0 to {MAX_SCORE}.\n\
         Listed options are the anchored scores; a value between two anchors \
         is accepted as interpolation.\n"
    )
    .map_err(Error::Stream)?;

    let title = match title {
        Some(title) => title,
        None => {
            let answer = ask(input, output, "Threat title")?;
            if answer.trim().is_empty() {
                return Err(Error::MissingTitle);
            }
            answer
        }
    };

    let mut scores: BTreeMap<String, i64> = BTreeMap::new();
    let mut current_group = None;

    for factor in FACTORS {
        if current_group != Some(factor.group) {
            writeln!(output, "\n{}", factor.group.title()).map_err(Error::Stream)?;
            current_group = Some(factor.group);
        }

        writeln!(output, "\n  {}", factor.name).map_err(Error::Stream)?;
        for (score, label) in factor.anchors {
            writeln!(output, "    {score}  {label}").map_err(Error::Stream)?;
        }

        let score = loop {
            let answer = ask(input, output, &format!("  {} [0-{MAX_SCORE}]", factor.name))?;
            match answer.trim().parse::<i64>() {
                Ok(value) if (0..=i64::from(MAX_SCORE)).contains(&value) => break value,
                _ => {
                    writeln!(output, "    Enter a whole number from 0 to {MAX_SCORE}.")
                        .map_err(Error::Stream)?;
                }
            }
        };

        scores.insert(factor.key.to_string(), score);
    }

    writeln!(output).map_err(Error::Stream)?;

    // Every factor was prompted, so nothing can be missing here.
    Assessment::build(title, id, notes, location, &scores, false)
}

fn ask(input: &mut impl BufRead, output: &mut impl Write, question: &str) -> Result<String> {
    write!(output, "{question}: ").map_err(Error::Stream)?;
    output.flush().map_err(Error::Stream)?;

    let mut line = String::new();
    let read = input.read_line(&mut line).map_err(Error::Stream)?;
    if read == 0 {
        return Err(Error::InputEnded);
    }

    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}
