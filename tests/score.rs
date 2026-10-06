//! Band thresholds and averaging. The boundaries are the point of this file:
//! a value sitting exactly on one must not drift through rounding.

use riskforge::model::score::{Average, Band, ImpactBasis};

#[test]
fn reference_average_matches_the_spreadsheet() {
    // The likelihood row of the template's worked example.
    let average = Average::of(&[4, 1, 4, 5, 3, 3, 4, 3]);
    assert_eq!(average.sum, 27);
    assert_eq!(average.count, 8);
    assert_eq!(average.rounded(), 3.375);
    assert_eq!(average.band(), Band::Medium);
}

#[test]
fn band_boundaries_are_exact_over_eight_factors() {
    // 3.0 and 6.0 are the first value of MEDIUM and of HIGH respectively.
    let cases: &[(u32, Band)] = &[
        (0, Band::Low),
        (23, Band::Low),    // 2.875
        (24, Band::Medium), // 3.000 exactly
        (25, Band::Medium),
        (47, Band::Medium), // 5.875
        (48, Band::High),   // 6.000 exactly
        (72, Band::High),   // 9.000, every factor at the maximum
    ];

    for (sum, expected) in cases {
        let average = Average {
            sum: *sum,
            count: 8,
        };
        assert_eq!(
            average.band(),
            *expected,
            "sum {sum} over 8 factors averages {} and should band {expected}",
            average.value()
        );
    }
}

#[test]
fn band_boundaries_are_exact_over_four_factors() {
    let cases: &[(u32, Band)] = &[
        (11, Band::Low),    // 2.75
        (12, Band::Medium), // 3.00 exactly
        (23, Band::Medium), // 5.75
        (24, Band::High),   // 6.00 exactly
    ];

    for (sum, expected) in cases {
        let average = Average {
            sum: *sum,
            count: 4,
        };
        assert_eq!(average.band(), *expected, "sum {sum} over 4 factors");
    }
}

#[test]
fn a_zero_is_a_score_and_never_shrinks_the_divisor() {
    // The template's technical impact: (2 + 0 + 0 + 9) / 4 = 2.75, not
    // (2 + 9) / 2 = 5.5. Treating zero as unscored would band this MEDIUM.
    let average = Average::of(&[2, 0, 0, 9]);
    assert_eq!(average.count, 4);
    assert_eq!(average.rounded(), 2.75);
    assert_eq!(average.band(), Band::Low);

    let all_zero = Average::of(&[0, 0, 0, 0]);
    assert_eq!(all_zero.count, 4);
    assert_eq!(all_zero.rounded(), 0.0);
    assert_eq!(all_zero.band(), Band::Low);
}

#[test]
fn rounding_is_three_decimal_places() {
    // 1/3 of the way up the scale, which does not terminate in decimal.
    let average = Average { sum: 1, count: 3 };
    assert_eq!(average.rounded(), 0.333);
    assert_eq!(format!("{average}"), "0.333");
}

#[test]
fn a_repeating_average_still_bands_by_integer_comparison() {
    // 8 factors summing to 24 averages 3.0 exactly. Were the comparison done
    // on the float, a representation below 3.0 would band it LOW.
    for count in 1u32..=16 {
        let at_boundary = Average {
            sum: 3 * count,
            count,
        };
        assert_eq!(at_boundary.band(), Band::Medium, "3.0 over {count} factors");

        let below = Average {
            sum: 3 * count - 1,
            count,
        };
        assert_eq!(below.band(), Band::Low, "just under 3.0 over {count}");
    }
}

#[test]
#[should_panic(expected = "at least one factor score")]
fn an_empty_set_has_no_average() {
    let _ = Average::of(&[]);
}

#[test]
fn bands_order_low_to_high() {
    assert!(Band::Low < Band::Medium);
    assert!(Band::Medium < Band::High);
}

#[test]
fn impact_basis_defaults_to_overall() {
    assert_eq!(ImpactBasis::default(), ImpactBasis::Overall);
}
