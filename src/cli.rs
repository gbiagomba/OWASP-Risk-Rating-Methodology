//! Command line surface.
//!
//! The 16 per-factor flags are generated from the factor catalog rather than
//! written out, so the catalog stays the single source of truth and a flag
//! can never drift from the factor it scores.

use crate::model::catalog::{Factor, FACTORS, MAX_SCORE};
use crate::model::matrix::Profile;
use crate::model::score::ImpactBasis;
use crate::report::Format;
use clap::{
    Arg, ArgAction, ArgMatches, Args, Command, FromArgMatches, Parser, Subcommand, ValueEnum,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "riskforge",
    version,
    about = "Score threat-model risk with the OWASP Risk Rating Methodology",
    long_about = "Score threat-model risk with the OWASP Risk Rating Methodology.\n\n\
                  Sixteen factors are scored 0 to 9. The eight likelihood factors \
                  and the eight impact factors are averaged, each average maps to a \
                  LOW, MEDIUM or HIGH band, and the two bands meet in a severity \
                  matrix: Risk = Likelihood x Impact. Every report shows how the \
                  rating was reached.",
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    #[command(flatten)]
    pub assess: AssessArgs,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Score a threat and write its rating. The default when no subcommand
    /// is given.
    Assess(AssessArgs),
    /// Print the factor catalog with every scored option.
    Factors {
        /// Emit the catalog as JSON.
        #[arg(long)]
        json: bool,
    },
    /// Print a severity matrix.
    Matrix {
        /// Which matrix to print.
        #[arg(long, value_enum, default_value_t = ProfileArg::Capped)]
        profile: ProfileArg,
    },
    /// Emit the JSON Schema for an input file.
    Schema,
}

#[derive(Debug, Args)]
pub struct AssessArgs {
    /// Read threats from a YAML or JSON file. Use `-` for standard input.
    #[arg(short, long, value_name = "FILE")]
    pub input: Option<PathBuf>,

    /// Threat title, required when scoring with flags.
    #[arg(short, long, value_name = "TEXT")]
    pub title: Option<String>,

    /// Stable identifier. Defaults to a slug of the title.
    #[arg(long, value_name = "TEXT")]
    pub id: Option<String>,

    /// Free-text note carried into the report.
    #[arg(long, value_name = "TEXT")]
    pub notes: Option<String>,

    /// Artifact or code location, carried into SARIF output.
    #[arg(long, value_name = "URI")]
    pub location: Option<String>,

    /// Output formats. Repeat or comma-separate. `all` selects every format.
    #[arg(
        short,
        long = "format",
        value_enum,
        value_delimiter = ',',
        default_value = "text",
        value_name = "FORMAT"
    )]
    pub formats: Vec<FormatArg>,

    /// Write to this file, or to this directory when more than one format is
    /// requested. Defaults to standard output.
    #[arg(short, long, value_name = "PATH")]
    pub output: Option<PathBuf>,

    /// Create the output directory when it does not exist.
    #[arg(long)]
    pub mkdir: bool,

    /// Severity matrix to apply.
    #[arg(long, value_enum, default_value_t = ProfileArg::Capped)]
    pub profile: ProfileArg,

    /// Which impact average feeds the matrix.
    #[arg(long, value_enum, default_value_t = ImpactBasisArg::Overall)]
    pub impact_basis: ImpactBasisArg,

    /// Score any unscored factor 0 and mark it as assumed in the report.
    #[arg(long)]
    pub allow_missing: bool,

    /// Suppress the progress line written to standard error.
    #[arg(short, long)]
    pub quiet: bool,

    #[command(flatten)]
    pub factors: FactorArgs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum ProfileArg {
    /// Three bands, ceiling of High, no Critical tier.
    Capped,
    /// As published, including the Note and Critical tiers.
    Owasp,
}

impl From<ProfileArg> for Profile {
    fn from(value: ProfileArg) -> Self {
        match value {
            ProfileArg::Capped => Profile::Capped,
            ProfileArg::Owasp => Profile::Owasp,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum ImpactBasisArg {
    /// All eight impact factors averaged together.
    Overall,
    /// The four technical impact factors only.
    Technical,
    /// The four business impact factors, falling back to technical when
    /// every business factor is zero.
    Business,
}

impl From<ImpactBasisArg> for ImpactBasis {
    fn from(value: ImpactBasisArg) -> Self {
        match value {
            ImpactBasisArg::Overall => ImpactBasis::Overall,
            ImpactBasisArg::Technical => ImpactBasis::Technical,
            ImpactBasisArg::Business => ImpactBasis::Business,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum FormatArg {
    Text,
    Json,
    Csv,
    Html,
    Md,
    Sarif,
    Sqlite,
    Sql,
    /// Every format at once. Needs `--output` to name a directory.
    All,
}

impl FormatArg {
    /// Expand a selection into a deduplicated, ordered format set.
    pub fn expand(selected: &[FormatArg]) -> Vec<Format> {
        let mut formats: Vec<Format> = Vec::new();

        for choice in selected {
            match choice {
                FormatArg::All => formats.extend(Format::ALL),
                other => formats.push(other.single()),
            }
        }

        formats.sort_unstable();
        formats.dedup();
        formats
    }

    fn single(self) -> Format {
        match self {
            FormatArg::Text => Format::Text,
            FormatArg::Json => Format::Json,
            FormatArg::Csv => Format::Csv,
            FormatArg::Html => Format::Html,
            FormatArg::Md => Format::Md,
            FormatArg::Sarif => Format::Sarif,
            FormatArg::Sqlite => Format::Sqlite,
            FormatArg::Sql => Format::Sql,
            FormatArg::All => unreachable!("expand handles All"),
        }
    }
}

/// Scores supplied through the generated per-factor flags.
#[derive(Debug, Clone, Default)]
pub struct FactorArgs {
    pub scores: BTreeMap<String, i64>,
}

impl FactorArgs {
    pub fn is_empty(&self) -> bool {
        self.scores.is_empty()
    }

    /// Help text for one factor, listing its anchored options.
    fn help_for(factor: &Factor) -> String {
        let anchors = factor
            .anchors
            .iter()
            .map(|(score, label)| format!("{score}={label}"))
            .collect::<Vec<_>>()
            .join("; ");
        format!("0-{MAX_SCORE}. {anchors}")
    }
}

impl Args for FactorArgs {
    fn augment_args(command: Command) -> Command {
        FACTORS.iter().fold(command, |command, factor| {
            command.arg(
                Arg::new(factor.key)
                    .long(factor.flag)
                    .value_name("0-9")
                    .value_parser(clap::value_parser!(i64))
                    .action(ArgAction::Set)
                    .help(FactorArgs::help_for(factor))
                    .help_heading(factor.group.title()),
            )
        })
    }

    fn augment_args_for_update(command: Command) -> Command {
        Self::augment_args(command)
    }
}

impl FromArgMatches for FactorArgs {
    fn from_arg_matches(matches: &ArgMatches) -> Result<Self, clap::Error> {
        let mut args = FactorArgs::default();
        args.update_from_arg_matches(matches)?;
        Ok(args)
    }

    fn update_from_arg_matches(&mut self, matches: &ArgMatches) -> Result<(), clap::Error> {
        for factor in FACTORS {
            if let Some(score) = matches.get_one::<i64>(factor.key) {
                self.scores.insert(factor.key.to_string(), *score);
            }
        }
        Ok(())
    }
}
