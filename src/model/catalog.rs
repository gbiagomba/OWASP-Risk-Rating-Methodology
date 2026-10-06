//! The 16 OWASP Risk Rating factors and their anchored option text.
//!
//! This module is the single source of truth for the methodology. The
//! interactive prompts, the per-factor CLI flags, the JSON Schema, the CSV
//! header and every report table are derived from `FACTORS`, so adding or
//! editing a factor is a one-file change.
//!
//! Option text is transcribed verbatim from the `Rating` sheet of the OWASP
//! Risk Rating template spreadsheet.
//!
//! Deliberate deviation from the OWASP community wiki: the template anchors
//! "Minimal critical data disclosed, extensive non-sensitive data disclosed"
//! at 4 and "Extensive critical data disclosed" at 5, where the wiki text
//! places the equivalent rungs at 6 and 7. The template is followed here
//! because it is the artifact the manual assessment process uses. See the
//! README section "Deviation from the OWASP wiki".

use serde::{Deserialize, Serialize};
use std::fmt;

/// The four factor groups of the methodology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Group {
    ThreatAgent,
    Vulnerability,
    TechnicalImpact,
    BusinessImpact,
}

impl Group {
    /// Groups whose factors average into the likelihood score.
    pub fn is_likelihood(self) -> bool {
        matches!(self, Group::ThreatAgent | Group::Vulnerability)
    }

    /// Groups whose factors average into an impact score.
    pub fn is_impact(self) -> bool {
        !self.is_likelihood()
    }

    pub fn title(self) -> &'static str {
        match self {
            Group::ThreatAgent => "Threat agent factors",
            Group::Vulnerability => "Vulnerability factors",
            Group::TechnicalImpact => "Technical impact",
            Group::BusinessImpact => "Business impact",
        }
    }
}

impl fmt::Display for Group {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.title())
    }
}

/// One factor of the methodology.
#[derive(Debug, Clone, Copy)]
pub struct Factor {
    /// Key used in input files, JSON output and database rows.
    pub key: &'static str,
    /// Long-form CLI flag, without the leading dashes.
    pub flag: &'static str,
    /// Human-readable name as it appears in the spreadsheet.
    pub name: &'static str,
    pub group: Group,
    /// Scored option text, ascending by score. Unlisted scores in `0..=9`
    /// remain valid and are treated as interpolation between anchors,
    /// exactly as the spreadsheet drop-downs allow.
    pub anchors: &'static [(u8, &'static str)],
}

impl Factor {
    /// Option text for an exact score, or `None` when the score falls
    /// between two anchors.
    pub fn anchor(&self, score: u8) -> Option<&'static str> {
        self.anchors
            .iter()
            .find(|(value, _)| *value == score)
            .map(|(_, label)| *label)
    }
}

/// Highest score any factor accepts. The methodology scores every factor
/// on the same `0..=9` scale.
pub const MAX_SCORE: u8 = 9;

/// Every factor, grouped and ordered as the spreadsheet presents them.
pub const FACTORS: &[Factor] = &[
    Factor {
        key: "skill_level",
        flag: "skill-level",
        name: "Skill level",
        group: Group::ThreatAgent,
        anchors: &[
            (1, "No technical skills"),
            (3, "Some technical skills"),
            (5, "Advanced computer user"),
            (6, "Network and programming skills"),
            (9, "Security penetration skills"),
        ],
    },
    Factor {
        key: "motive",
        flag: "motive",
        name: "Motive",
        group: Group::ThreatAgent,
        anchors: &[
            (1, "Low or no reward"),
            (4, "Possible reward"),
            (9, "High reward"),
        ],
    },
    Factor {
        key: "opportunity",
        flag: "opportunity",
        name: "Opportunity",
        group: Group::ThreatAgent,
        anchors: &[
            (0, "Full access or expensive resources required"),
            (4, "Special access or resources required"),
            (7, "Some access or resources required"),
            (9, "No access or resources required"),
        ],
    },
    Factor {
        key: "size",
        flag: "size",
        name: "Size",
        group: Group::ThreatAgent,
        anchors: &[
            (2, "Developers, system administrators"),
            (4, "Intranet users"),
            (5, "Partners"),
            (6, "Authenticated users"),
            (9, "Anonymous Internet users"),
        ],
    },
    Factor {
        key: "ease_of_discovery",
        flag: "ease-of-discovery",
        name: "Ease of discovery",
        group: Group::Vulnerability,
        anchors: &[
            (1, "Practically impossible"),
            (3, "Difficult"),
            (7, "Easy"),
            (9, "Automated tools available"),
        ],
    },
    Factor {
        key: "ease_of_exploit",
        flag: "ease-of-exploit",
        name: "Ease of exploit",
        group: Group::Vulnerability,
        anchors: &[
            (1, "Theoretical"),
            (3, "Difficult"),
            (5, "Easy"),
            (9, "Automated tools available"),
        ],
    },
    Factor {
        key: "awareness",
        flag: "awareness",
        name: "Awareness",
        group: Group::Vulnerability,
        anchors: &[
            (1, "Unknown"),
            (4, "Hidden"),
            (6, "Obvious"),
            (9, "Public knowledge"),
        ],
    },
    Factor {
        key: "intrusion_detection",
        flag: "intrusion-detection",
        name: "Intrusion detection",
        group: Group::Vulnerability,
        anchors: &[
            (1, "Active detection in application"),
            (3, "Logged and reviewed"),
            (8, "Logged without review"),
            (9, "Not logged"),
        ],
    },
    Factor {
        key: "loss_of_confidentiality",
        flag: "loss-of-confidentiality",
        name: "Loss of confidentiality",
        group: Group::TechnicalImpact,
        anchors: &[
            (2, "Minimal non-sensitive data disclosed"),
            (
                4,
                "Minimal critical data disclosed, extensive non-sensitive data disclosed",
            ),
            (5, "Extensive critical data disclosed"),
            (9, "All data disclosed"),
        ],
    },
    Factor {
        key: "loss_of_integrity",
        flag: "loss-of-integrity",
        name: "Loss of integrity",
        group: Group::TechnicalImpact,
        anchors: &[
            (1, "Minimal slightly corrupt data"),
            (3, "Minimal seriously corrupt data"),
            (5, "Extensive slightly corrupt data"),
            (7, "Extensive seriously corrupt data"),
            (9, "All data totally corrupt"),
        ],
    },
    Factor {
        key: "loss_of_availability",
        flag: "loss-of-availability",
        name: "Loss of availability",
        group: Group::TechnicalImpact,
        anchors: &[
            (1, "Minimal secondary services interrupted"),
            (
                5,
                "Minimal primary services interrupted, extensive secondary services interrupted",
            ),
            (7, "Extensive primary services interrupted"),
            (9, "All services completely lost"),
        ],
    },
    Factor {
        key: "loss_of_accountability",
        flag: "loss-of-accountability",
        name: "Loss of accountability",
        group: Group::TechnicalImpact,
        anchors: &[
            (1, "Fully traceable"),
            (7, "Possibly traceable"),
            (9, "Completely anonymous"),
        ],
    },
    Factor {
        key: "financial_damage",
        flag: "financial-damage",
        name: "Financial damage",
        group: Group::BusinessImpact,
        anchors: &[
            (1, "Less than the cost to fix the vulnerability"),
            (3, "Minor effect on annual profit"),
            (7, "Significant effect on annual profit"),
            (9, "Bankruptcy"),
        ],
    },
    Factor {
        key: "reputation_damage",
        flag: "reputation-damage",
        name: "Reputation damage",
        group: Group::BusinessImpact,
        anchors: &[
            (1, "Minimal damage"),
            (4, "Loss of major accounts"),
            (5, "Loss of goodwill"),
            (9, "Brand damage"),
        ],
    },
    Factor {
        key: "non_compliance",
        flag: "non-compliance",
        name: "Non-compliance",
        group: Group::BusinessImpact,
        anchors: &[
            (2, "Minor violation"),
            (5, "Clear violation"),
            (7, "High profile violation"),
        ],
    },
    Factor {
        key: "privacy_violation",
        flag: "privacy-violation",
        name: "Privacy violation",
        group: Group::BusinessImpact,
        anchors: &[
            (3, "One individual"),
            (5, "Hundreds of people"),
            (7, "Thousands of people"),
            (9, "Millions of people"),
        ],
    },
];

/// Look up a factor by its input-file key.
pub fn factor_by_key(key: &str) -> Option<&'static Factor> {
    FACTORS.iter().find(|factor| factor.key == key)
}

/// Factors belonging to one group, in catalog order.
pub fn factors_in(group: Group) -> impl Iterator<Item = &'static Factor> {
    FACTORS.iter().filter(move |factor| factor.group == group)
}

/// The four groups in presentation order.
pub const GROUPS: [Group; 4] = [
    Group::ThreatAgent,
    Group::Vulnerability,
    Group::TechnicalImpact,
    Group::BusinessImpact,
];
