//! The factor catalog must match the OWASP Risk Rating template spreadsheet.

use riskforge::model::catalog::{factor_by_key, factors_in, Group, FACTORS, GROUPS, MAX_SCORE};
use std::collections::BTreeSet;

#[test]
fn has_sixteen_factors() {
    assert_eq!(FACTORS.len(), 16);
}

#[test]
fn every_group_holds_four_factors() {
    for group in GROUPS {
        assert_eq!(
            factors_in(group).count(),
            4,
            "{group} should hold four factors"
        );
    }
}

#[test]
fn eight_factors_average_into_each_side() {
    let likelihood = FACTORS
        .iter()
        .filter(|factor| factor.group.is_likelihood())
        .count();
    let impact = FACTORS
        .iter()
        .filter(|factor| factor.group.is_impact())
        .count();

    assert_eq!(likelihood, 8);
    assert_eq!(impact, 8);
}

#[test]
fn keys_flags_and_names_are_unique() {
    for (label, values) in [
        ("key", FACTORS.iter().map(|f| f.key).collect::<Vec<_>>()),
        ("flag", FACTORS.iter().map(|f| f.flag).collect::<Vec<_>>()),
        ("name", FACTORS.iter().map(|f| f.name).collect::<Vec<_>>()),
    ] {
        let unique: BTreeSet<_> = values.iter().collect();
        assert_eq!(unique.len(), values.len(), "duplicate factor {label}");
    }
}

#[test]
fn keys_are_snake_case_and_flags_are_kebab_case() {
    for factor in FACTORS {
        assert!(
            factor
                .key
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '_'),
            "{} is not snake_case",
            factor.key
        );
        assert!(
            factor
                .flag
                .chars()
                .all(|c| c.is_ascii_lowercase() || c == '-'),
            "{} is not kebab-case",
            factor.flag
        );
        assert_eq!(factor.key.replace('_', "-"), factor.flag);
    }
}

#[test]
fn anchors_ascend_and_stay_in_range() {
    for factor in FACTORS {
        assert!(
            !factor.anchors.is_empty(),
            "{} has no anchored options",
            factor.key
        );

        let mut previous: Option<u8> = None;
        for (score, label) in factor.anchors {
            assert!(
                *score <= MAX_SCORE,
                "{} anchors {score} above the maximum",
                factor.key
            );
            assert!(
                !label.trim().is_empty(),
                "{} has an empty option label at {score}",
                factor.key
            );
            if let Some(previous) = previous {
                assert!(
                    *score > previous,
                    "{} anchors are not ascending at {score}",
                    factor.key
                );
            }
            previous = Some(*score);
        }
    }
}

#[test]
fn lookup_by_key_round_trips() {
    for factor in FACTORS {
        let found = factor_by_key(factor.key).expect("catalog key resolves");
        assert_eq!(found.name, factor.name);
    }
    assert!(factor_by_key("no_such_factor").is_none());
}

#[test]
fn anchor_text_matches_the_spreadsheet() {
    // Spot checks transcribed from the `Rating` sheet of the template.
    let expected: &[(&str, u8, &str)] = &[
        ("skill_level", 1, "No technical skills"),
        ("skill_level", 9, "Security penetration skills"),
        ("motive", 4, "Possible reward"),
        (
            "opportunity",
            0,
            "Full access or expensive resources required",
        ),
        ("opportunity", 9, "No access or resources required"),
        ("size", 2, "Developers, system administrators"),
        ("size", 9, "Anonymous Internet users"),
        ("ease_of_discovery", 1, "Practically impossible"),
        ("ease_of_exploit", 5, "Easy"),
        ("awareness", 6, "Obvious"),
        ("intrusion_detection", 8, "Logged without review"),
        ("intrusion_detection", 9, "Not logged"),
        (
            "loss_of_confidentiality",
            2,
            "Minimal non-sensitive data disclosed",
        ),
        (
            "loss_of_confidentiality",
            5,
            "Extensive critical data disclosed",
        ),
        ("loss_of_integrity", 9, "All data totally corrupt"),
        (
            "loss_of_availability",
            7,
            "Extensive primary services interrupted",
        ),
        ("loss_of_accountability", 9, "Completely anonymous"),
        (
            "financial_damage",
            1,
            "Less than the cost to fix the vulnerability",
        ),
        ("reputation_damage", 5, "Loss of goodwill"),
        ("non_compliance", 7, "High profile violation"),
        ("privacy_violation", 9, "Millions of people"),
    ];

    for (key, score, label) in expected {
        let factor = factor_by_key(key).expect("factor exists");
        assert_eq!(
            factor.anchor(*score),
            Some(*label),
            "{key} at {score} should read {label:?}"
        );
    }
}

#[test]
fn unanchored_scores_have_no_option_text() {
    // Skill level anchors 1, 3, 5, 6 and 9. The gaps are interpolation.
    let factor = factor_by_key("skill_level").expect("factor exists");
    assert!(factor.anchor(2).is_none());
    assert!(factor.anchor(4).is_none());
    assert!(factor.anchor(7).is_none());
}

#[test]
fn groups_split_into_likelihood_and_impact() {
    assert!(Group::ThreatAgent.is_likelihood());
    assert!(Group::Vulnerability.is_likelihood());
    assert!(Group::TechnicalImpact.is_impact());
    assert!(Group::BusinessImpact.is_impact());
    assert!(!Group::TechnicalImpact.is_likelihood());
}
