//! Input validation at the trust boundary. Bad input must fail loudly and
//! name the factor at fault, never score it silently.

use riskforge::error::Error;
use riskforge::input::file;
use riskforge::model::assessment::Assessment;
use riskforge::model::catalog::FACTORS;
use std::collections::BTreeMap;
use std::path::Path;

fn complete_scores() -> BTreeMap<String, i64> {
    FACTORS
        .iter()
        .map(|factor| (factor.key.to_string(), 5))
        .collect()
}

fn build(scores: &BTreeMap<String, i64>, allow_missing: bool) -> Result<Assessment, Error> {
    Assessment::build("A threat".into(), None, None, None, scores, allow_missing)
}

#[test]
fn a_complete_set_of_scores_builds() {
    let assessment = build(&complete_scores(), false).expect("builds");
    assert_eq!(assessment.scores.len(), 16);
    assert!(assessment.assumed_keys().is_empty());
}

#[test]
fn a_score_above_nine_is_rejected_by_name() {
    let mut scores = complete_scores();
    scores.insert("skill_level".into(), 10);

    match build(&scores, false) {
        Err(Error::ScoreOutOfRange { key, value, max }) => {
            assert_eq!(key, "skill_level");
            assert_eq!(value, 10);
            assert_eq!(max, 9);
        }
        other => panic!("expected an out-of-range error, got {other:?}"),
    }
}

#[test]
fn a_negative_score_is_rejected_by_name() {
    let mut scores = complete_scores();
    scores.insert("privacy_violation".into(), -1);

    match build(&scores, false) {
        Err(Error::ScoreOutOfRange { key, value, .. }) => {
            assert_eq!(key, "privacy_violation");
            assert_eq!(value, -1);
        }
        other => panic!("expected an out-of-range error, got {other:?}"),
    }
}

#[test]
fn the_full_range_is_accepted() {
    for score in 0..=9 {
        let scores: BTreeMap<String, i64> = FACTORS
            .iter()
            .map(|factor| (factor.key.to_string(), score))
            .collect();
        assert!(build(&scores, false).is_ok(), "score {score} should build");
    }
}

#[test]
fn an_unknown_factor_is_rejected_rather_than_ignored() {
    let mut scores = complete_scores();
    scores.insert("skill_lvl".into(), 4);

    match build(&scores, false) {
        Err(Error::UnknownFactor { key, suggestion }) => {
            assert_eq!(key, "skill_lvl");
            assert_eq!(
                suggestion.as_deref(),
                Some("skill_level"),
                "a near miss should be suggested"
            );
        }
        other => panic!("expected an unknown-factor error, got {other:?}"),
    }
}

#[test]
fn a_wild_key_is_rejected_without_a_suggestion() {
    let mut scores = complete_scores();
    scores.insert("completely_unrelated_thing".into(), 4);

    match build(&scores, false) {
        Err(Error::UnknownFactor { suggestion, .. }) => assert!(suggestion.is_none()),
        other => panic!("expected an unknown-factor error, got {other:?}"),
    }
}

#[test]
fn missing_factors_fail_and_are_all_listed() {
    let mut scores = complete_scores();
    scores.remove("motive");
    scores.remove("awareness");

    match build(&scores, false) {
        Err(Error::MissingFactors { keys }) => {
            assert_eq!(keys.len(), 2);
            assert!(keys.contains(&"motive".to_string()));
            assert!(keys.contains(&"awareness".to_string()));
        }
        other => panic!("expected a missing-factors error, got {other:?}"),
    }
}

#[test]
fn allow_missing_scores_zero_and_marks_the_assumption() {
    let mut scores = complete_scores();
    scores.remove("motive");

    let assessment = build(&scores, true).expect("builds with --allow-missing");
    assert_eq!(assessment.assumed_keys(), vec!["motive"]);

    let motive = assessment
        .scores
        .iter()
        .find(|entry| entry.factor.key == "motive")
        .expect("present in the score list");
    assert_eq!(motive.score, 0);
    assert!(motive.assumed);
}

#[test]
fn an_empty_title_is_rejected() {
    let scores = complete_scores();
    assert!(matches!(
        Assessment::build("   ".into(), None, None, None, &scores, false),
        Err(Error::MissingTitle)
    ));
}

// Input-file shapes.

fn yaml_factors() -> String {
    FACTORS
        .iter()
        .map(|factor| format!("    {}: 5", factor.key))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn a_single_threat_mapping_parses() {
    let text = format!("title: One threat\nfactors:\n{}\n", yaml_factors());
    let threats = file::parse(&text, Path::new("test.yaml"), false).expect("parses");
    assert_eq!(threats.len(), 1);
    assert_eq!(threats[0].title, "One threat");
}

#[test]
fn a_sequence_of_threats_parses() {
    let factors = yaml_factors();
    let text = format!(
        "- title: First\n  factors:\n{}\n- title: Second\n  factors:\n{}\n",
        factors.replace("    ", "      "),
        factors.replace("    ", "      ")
    );
    let threats = file::parse(&text, Path::new("test.yaml"), false).expect("parses");
    assert_eq!(threats.len(), 2);
    assert_eq!(threats[1].title, "Second");
}

#[test]
fn a_threats_wrapper_parses() {
    let factors = yaml_factors().replace("    ", "      ");
    let text = format!("threats:\n  - title: Wrapped\n    factors:\n{factors}\n");
    let threats = file::parse(&text, Path::new("test.yaml"), false).expect("parses");
    assert_eq!(threats.len(), 1);
    assert_eq!(threats[0].title, "Wrapped");
}

#[test]
fn json_input_parses_through_the_same_path() {
    let factors = FACTORS
        .iter()
        .map(|factor| format!("\"{}\": 5", factor.key))
        .collect::<Vec<_>>()
        .join(", ");
    let text = format!("{{\"title\": \"From JSON\", \"factors\": {{{factors}}}}}");
    let threats = file::parse(&text, Path::new("test.json"), false).expect("parses");
    assert_eq!(threats[0].title, "From JSON");
}

#[test]
fn an_unknown_top_level_field_is_rejected() {
    let text = format!("title: Typo\nsevrity: High\nfactors:\n{}\n", yaml_factors());
    let error = file::parse(&text, Path::new("test.yaml"), false).expect_err("rejected");
    assert!(
        matches!(error, Error::Threat { .. }),
        "expected a per-threat error, got {error:?}"
    );
}

#[test]
fn a_bad_score_inside_a_batch_names_its_threat() {
    let factors = yaml_factors().replace("    ", "      ");
    let text = format!(
        "- title: Fine\n  factors:\n{factors}\n- title: Broken\n  factors:\n{}\n",
        factors.replace("motive: 5", "motive: 42")
    );

    match file::parse(&text, Path::new("test.yaml"), false) {
        Err(Error::Threat { index, source, .. }) => {
            assert_eq!(index, 2, "the second threat is the broken one");
            assert!(matches!(*source, Error::ScoreOutOfRange { .. }));
        }
        other => panic!("expected a per-threat error, got {other:?}"),
    }
}

#[test]
fn an_empty_sequence_is_rejected() {
    let error = file::parse("[]", Path::new("test.yaml"), false).expect_err("rejected");
    assert!(matches!(error, Error::Empty { .. }));
}

#[test]
fn a_scalar_document_is_rejected() {
    let error = file::parse("just a string", Path::new("test.yaml"), false).expect_err("rejected");
    assert!(matches!(error, Error::Shape { .. }));
}
