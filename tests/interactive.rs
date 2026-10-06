//! The interactive prompt loop, driven over a scripted reader.

use riskforge::error::Error;
use riskforge::input::interactive::prompt;
use riskforge::model::catalog::FACTORS;
use std::io::{BufReader, Cursor};

/// Answer every factor prompt with `score`, after an optional title line.
fn script(title: Option<&str>, scores: &[i64]) -> String {
    let mut lines: Vec<String> = Vec::new();
    if let Some(title) = title {
        lines.push(title.to_string());
    }
    lines.extend(scores.iter().map(|score| score.to_string()));
    format!("{}\n", lines.join("\n"))
}

fn run(
    input: &str,
    title: Option<String>,
) -> Result<riskforge::model::assessment::Assessment, Error> {
    let mut reader = BufReader::new(input.as_bytes());
    let mut output: Vec<u8> = Vec::new();
    prompt(&mut reader, &mut output, title, None, None, None)
}

#[test]
fn every_factor_is_prompted_in_catalog_order() {
    let mut reader = BufReader::new(Cursor::new(script(Some("Scripted threat"), &[5; 16])));
    let mut output: Vec<u8> = Vec::new();
    let assessment = prompt(&mut reader, &mut output, None, None, None, None).expect("completes");

    assert_eq!(assessment.title, "Scripted threat");
    assert_eq!(assessment.scores.len(), 16);
    assert!(assessment.assumed_keys().is_empty());

    let transcript = String::from_utf8(output).expect("utf-8 transcript");
    for factor in FACTORS {
        assert!(
            transcript.contains(factor.name),
            "{} should be prompted",
            factor.name
        );
    }
    for group in ["Threat agent factors", "Business impact"] {
        assert!(transcript.contains(group), "{group} header should print");
    }
    // The anchored options are shown as a guide.
    assert!(transcript.contains("Security penetration skills"));
}

#[test]
fn a_title_supplied_up_front_is_not_prompted_for() {
    let assessment = run(&script(None, &[3; 16]), Some("Given title".into()))
        .expect("completes without a title prompt");
    assert_eq!(assessment.title, "Given title");
}

#[test]
fn the_reference_example_can_be_typed_in() {
    let scores = [4, 1, 4, 5, 3, 3, 4, 3, 2, 0, 0, 9, 1, 1, 0, 5];
    let assessment = run(
        &script(Some("Full database theft from datacenter"), &scores),
        None,
    )
    .expect("completes");

    assert_eq!(assessment.likelihood().rounded(), 3.375);
    assert_eq!(assessment.technical_impact().rounded(), 2.75);
    assert_eq!(assessment.business_impact().rounded(), 1.75);
    assert_eq!(assessment.overall_impact().rounded(), 2.25);
}

#[test]
fn an_out_of_range_answer_is_re_prompted_rather_than_accepted() {
    // 10, then a word, then a valid 7 for the first factor.
    let mut lines = vec![
        "A threat".to_string(),
        "10".into(),
        "nine".into(),
        "7".into(),
    ];
    lines.extend((1..16).map(|_| "1".to_string()));
    let input = format!("{}\n", lines.join("\n"));

    let mut reader = BufReader::new(Cursor::new(input));
    let mut output: Vec<u8> = Vec::new();
    let assessment = prompt(&mut reader, &mut output, None, None, None, None).expect("completes");

    assert_eq!(assessment.scores[0].score, 7, "the valid answer wins");
    let transcript = String::from_utf8(output).expect("utf-8");
    assert_eq!(
        transcript.matches("Enter a whole number").count(),
        2,
        "both bad answers should be refused"
    );
}

#[test]
fn zero_is_accepted_as_a_real_score() {
    let assessment = run(&script(Some("All zeros"), &[0; 16]), None).expect("completes");
    assert_eq!(assessment.overall_impact().sum, 0);
    assert_eq!(assessment.overall_impact().count, 8);
    assert!(
        assessment.assumed_keys().is_empty(),
        "a typed 0 is scored, not assumed"
    );
}

#[test]
fn an_empty_title_is_refused() {
    let input = script(Some(""), &[1; 16]);
    assert!(matches!(run(&input, None), Err(Error::MissingTitle)));
}

#[test]
fn input_ending_early_is_an_error_rather_than_a_partial_rating() {
    // A title and three answers, then end of input.
    let input = script(Some("Truncated"), &[1, 2, 3]);
    assert!(matches!(run(&input, None), Err(Error::InputEnded)));
}
