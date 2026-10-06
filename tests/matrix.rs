//! Both severity matrices, cell by cell.

use riskforge::model::matrix::{grid, lookup, Profile, Severity};
use riskforge::model::score::Band;

/// Every cell of the capped matrix, as the profile documents it.
const CAPPED: &[(Band, Band, Severity)] = &[
    (Band::Low, Band::Low, Severity::Low),
    (Band::Medium, Band::Low, Severity::Low),
    (Band::High, Band::Low, Severity::Medium),
    (Band::Low, Band::Medium, Severity::Low),
    (Band::Medium, Band::Medium, Severity::Medium),
    (Band::High, Band::Medium, Severity::High),
    (Band::Low, Band::High, Severity::Medium),
    (Band::Medium, Band::High, Severity::High),
    (Band::High, Band::High, Severity::High),
];

/// Every cell of the published matrix.
const OWASP: &[(Band, Band, Severity)] = &[
    (Band::Low, Band::Low, Severity::Note),
    (Band::Medium, Band::Low, Severity::Low),
    (Band::High, Band::Low, Severity::Medium),
    (Band::Low, Band::Medium, Severity::Low),
    (Band::Medium, Band::Medium, Severity::Medium),
    (Band::High, Band::Medium, Severity::High),
    (Band::Low, Band::High, Severity::Medium),
    (Band::Medium, Band::High, Severity::High),
    (Band::High, Band::High, Severity::Critical),
];

#[test]
fn capped_matrix_matches_every_cell() {
    for (likelihood, impact, expected) in CAPPED {
        assert_eq!(
            lookup(Profile::Capped, *likelihood, *impact),
            *expected,
            "capped: likelihood {likelihood} x impact {impact}"
        );
    }
}

#[test]
fn owasp_matrix_matches_every_cell() {
    for (likelihood, impact, expected) in OWASP {
        assert_eq!(
            lookup(Profile::Owasp, *likelihood, *impact),
            *expected,
            "owasp: likelihood {likelihood} x impact {impact}"
        );
    }
}

#[test]
fn capped_profile_never_exceeds_high() {
    for (likelihood, impact, _) in CAPPED {
        let severity = lookup(Profile::Capped, *likelihood, *impact);
        assert!(
            severity <= Severity::High,
            "capped produced {severity} at {likelihood} x {impact}"
        );
        assert_ne!(severity, Severity::Critical);
        assert_ne!(severity, Severity::Note);
    }

    assert!(!Profile::Capped.levels().contains(&Severity::Critical));
    assert!(!Profile::Capped.levels().contains(&Severity::Note));
}

#[test]
fn owasp_profile_reaches_both_outer_tiers() {
    assert_eq!(
        lookup(Profile::Owasp, Band::High, Band::High),
        Severity::Critical
    );
    assert_eq!(lookup(Profile::Owasp, Band::Low, Band::Low), Severity::Note);
    assert!(Profile::Owasp.levels().contains(&Severity::Critical));
    assert!(Profile::Owasp.levels().contains(&Severity::Note));
}

#[test]
fn the_profiles_differ_only_at_the_two_corners() {
    for (likelihood, impact, _) in CAPPED {
        let capped = lookup(Profile::Capped, *likelihood, *impact);
        let owasp = lookup(Profile::Owasp, *likelihood, *impact);
        let is_corner = (*likelihood == Band::Low && *impact == Band::Low)
            || (*likelihood == Band::High && *impact == Band::High);

        if is_corner {
            assert_ne!(capped, owasp, "{likelihood} x {impact} should diverge");
        } else {
            assert_eq!(capped, owasp, "{likelihood} x {impact} should agree");
        }
    }
}

#[test]
fn both_matrices_are_symmetric() {
    for profile in [Profile::Capped, Profile::Owasp] {
        for likelihood in [Band::Low, Band::Medium, Band::High] {
            for impact in [Band::Low, Band::Medium, Band::High] {
                assert_eq!(
                    lookup(profile, likelihood, impact),
                    lookup(profile, impact, likelihood),
                    "{profile} is asymmetric at {likelihood} x {impact}"
                );
            }
        }
    }
}

#[test]
fn grid_rows_run_impact_descending() {
    let rows = grid(Profile::Owasp);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].0, Band::High);
    assert_eq!(rows[1].0, Band::Medium);
    assert_eq!(rows[2].0, Band::Low);

    // Top-left is low likelihood against high impact; bottom-right is the
    // reverse corner.
    assert_eq!(rows[0].1[0], Severity::Medium);
    assert_eq!(rows[0].1[2], Severity::Critical);
    assert_eq!(rows[2].1[0], Severity::Note);
}

#[test]
fn sarif_levels_map_by_severity() {
    assert_eq!(Severity::Critical.sarif_level(), "error");
    assert_eq!(Severity::High.sarif_level(), "error");
    assert_eq!(Severity::Medium.sarif_level(), "warning");
    assert_eq!(Severity::Low.sarif_level(), "note");
    assert_eq!(Severity::Note.sarif_level(), "note");
}

#[test]
fn capped_is_the_default_profile() {
    assert_eq!(Profile::default(), Profile::Capped);
}
