//! The primary acceptance gate.
//!
//! The OWASP Risk Rating template ships a worked example on its `Assesment`
//! sheet, titled "Full database theft from datacenter". Every number this
//! tool derives for that input must equal the number the spreadsheet shows.
//! If this file fails, the tool disagrees with the methodology it claims to
//! implement.

use riskforge::model::assessment::Assessment;
use riskforge::model::matrix::{Profile, Severity};
use riskforge::model::score::{Band, ImpactBasis};
use riskforge::report::Report;
use std::collections::BTreeMap;

/// The example as the spreadsheet scores it.
fn reference() -> BTreeMap<String, i64> {
    [
        // Threat agent factors
        ("skill_level", 4),
        ("motive", 1),
        ("opportunity", 4),
        ("size", 5),
        // Vulnerability factors
        ("ease_of_discovery", 3),
        ("ease_of_exploit", 3),
        ("awareness", 4),
        ("intrusion_detection", 3),
        // Technical impact
        ("loss_of_confidentiality", 2),
        ("loss_of_integrity", 0),
        ("loss_of_availability", 0),
        ("loss_of_accountability", 9),
        // Business impact
        ("financial_damage", 1),
        ("reputation_damage", 1),
        ("non_compliance", 0),
        ("privacy_violation", 5),
    ]
    .into_iter()
    .map(|(key, score)| (key.to_string(), score))
    .collect()
}

fn assessment() -> Assessment {
    Assessment::build(
        "Full database theft from datacenter".to_string(),
        None,
        None,
        None,
        &reference(),
        false,
    )
    .expect("the reference example scores every factor")
}

#[test]
fn overall_likelihood_matches_cell_f8() {
    let likelihood = assessment().likelihood();
    assert_eq!(likelihood.sum, 27);
    assert_eq!(likelihood.count, 8);
    assert_eq!(likelihood.rounded(), 3.375);
    assert_eq!(likelihood.band(), Band::Medium);
}

#[test]
fn overall_technical_impact_matches_cell_d13() {
    let technical = assessment().technical_impact();
    assert_eq!(technical.sum, 11);
    assert_eq!(technical.count, 4);
    assert_eq!(technical.rounded(), 2.75);
    assert_eq!(technical.band(), Band::Low);
}

#[test]
fn overall_business_impact_matches_cell_i13() {
    let business = assessment().business_impact();
    assert_eq!(business.sum, 7);
    assert_eq!(business.count, 4);
    assert_eq!(business.rounded(), 1.75);
    assert_eq!(business.band(), Band::Low);
}

#[test]
fn overall_impact_matches_cell_f14() {
    let overall = assessment().overall_impact();
    assert_eq!(overall.sum, 18);
    assert_eq!(overall.count, 8);
    assert_eq!(overall.rounded(), 2.25);
    assert_eq!(overall.band(), Band::Low);
}

#[test]
fn severity_is_low_under_both_profiles() {
    // MEDIUM likelihood against LOW impact. The two profiles agree here:
    // they diverge only at the Low-by-Low and High-by-High corners.
    for profile in [Profile::Capped, Profile::Owasp] {
        let report = Report::new(assessment(), profile, ImpactBasis::Overall);
        assert_eq!(report.likelihood_band(), Band::Medium);
        assert_eq!(report.impact_band(), Band::Low);
        assert_eq!(report.severity, Severity::Low, "under {profile}");
    }
}

#[test]
fn the_technical_basis_also_bands_low() {
    let report = Report::new(assessment(), Profile::Capped, ImpactBasis::Technical);
    assert_eq!(report.impact_basis, ImpactBasis::Technical);
    assert_eq!(report.impact_used.rounded(), 2.75);
    assert_eq!(report.severity, Severity::Low);
}

#[test]
fn the_business_basis_is_used_when_it_is_scored() {
    let report = Report::new(assessment(), Profile::Capped, ImpactBasis::Business);
    assert_eq!(report.impact_basis, ImpactBasis::Business);
    assert_eq!(report.impact_used.rounded(), 1.75);
    assert_eq!(report.severity, Severity::Low);
}

#[test]
fn the_business_basis_falls_back_when_unscored() {
    let mut scores = reference();
    for key in [
        "financial_damage",
        "reputation_damage",
        "non_compliance",
        "privacy_violation",
    ] {
        scores.insert(key.to_string(), 0);
    }

    let assessment = Assessment::build(
        "No business impact scored".to_string(),
        None,
        None,
        None,
        &scores,
        false,
    )
    .expect("builds");

    let report = Report::new(assessment, Profile::Capped, ImpactBasis::Business);
    assert_eq!(
        report.impact_basis,
        ImpactBasis::Technical,
        "an all-zero business group should fall back to technical"
    );
    assert_eq!(report.impact_used.rounded(), 2.75);
}

#[test]
fn the_derivation_names_every_number_it_used() {
    let report = Report::new(assessment(), Profile::Capped, ImpactBasis::Overall);
    let derivation = report.derivation();

    for fragment in [
        "3.375", "MEDIUM", "2.250", "LOW", "overall", "Low", "capped",
    ] {
        assert!(
            derivation.contains(fragment),
            "derivation should mention {fragment:?}, got: {derivation}"
        );
    }
}

#[test]
fn the_identifier_slugs_the_title() {
    let report = Report::new(assessment(), Profile::Capped, ImpactBasis::Overall);
    assert_eq!(report.id(), "full-database-theft-from-datacenter");
}

#[test]
fn a_high_by_high_threat_separates_the_profiles() {
    // Every factor at 9 bands both sides HIGH, which is the one corner where
    // the capped ceiling bites.
    let scores: BTreeMap<String, i64> = reference().keys().map(|key| (key.clone(), 9)).collect();

    let worst = || {
        Assessment::build(
            "Everything at maximum".to_string(),
            None,
            None,
            None,
            &scores,
            false,
        )
        .expect("builds")
    };

    let capped = Report::new(worst(), Profile::Capped, ImpactBasis::Overall);
    let owasp = Report::new(worst(), Profile::Owasp, ImpactBasis::Overall);

    assert_eq!(capped.likelihood_band(), Band::High);
    assert_eq!(capped.impact_band(), Band::High);
    assert_eq!(capped.severity, Severity::High, "capped ceiling holds");
    assert_eq!(owasp.severity, Severity::Critical);
}
