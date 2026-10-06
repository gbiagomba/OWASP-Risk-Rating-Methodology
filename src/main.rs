//! Command line entry point.

use clap::Parser;
use riskforge::cli::{AssessArgs, Cli, Commands, FormatArg};
use riskforge::error::{Error, Result};
use riskforge::input::{file, interactive, schema};
use riskforge::model::assessment::Assessment;
use riskforge::model::catalog::{factors_in, Group, GROUPS};
use riskforge::model::matrix::{grid, Profile};
use riskforge::report::{sqlite, Format, Report};
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::{Path, PathBuf};

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            report_error(&error);
            std::process::ExitCode::FAILURE
        }
    }
}

/// Print an error with its whole source chain, so a nested parse failure
/// still names the file and the threat it came from.
fn report_error(error: &Error) {
    eprintln!("riskforge: {error}");
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        eprintln!("  caused by: {cause}");
        source = cause.source();
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Factors { json }) => print_factors(json),
        Some(Commands::Matrix { profile }) => print_matrix(profile.into()),
        Some(Commands::Schema) => print_schema(),
        Some(Commands::Assess(args)) => assess(args),
        None => assess(cli.assess),
    }
}

fn print_factors(as_json: bool) -> Result<()> {
    let mut out = BufWriter::new(io::stdout().lock());

    if as_json {
        let value = serde_json::to_vec_pretty(&schema::schema())?;
        out.write_all(&value).map_err(Error::Stream)?;
        out.write_all(b"\n").map_err(Error::Stream)?;
        return out.flush().map_err(Error::Stream);
    }

    writeln!(
        out,
        "OWASP Risk Rating Methodology factors. Each is scored 0 to 9; a value \
         between two\nlisted options is accepted as interpolation."
    )
    .map_err(Error::Stream)?;

    for group in GROUPS {
        writeln!(out, "\n{} ({})", group.title(), averaged_into(group)).map_err(Error::Stream)?;
        for factor in factors_in(group) {
            writeln!(out, "\n  {}  --{}", factor.name, factor.flag).map_err(Error::Stream)?;
            writeln!(out, "    key: {}", factor.key).map_err(Error::Stream)?;
            for (score, label) in factor.anchors {
                writeln!(out, "    {score}  {label}").map_err(Error::Stream)?;
            }
        }
    }

    out.flush().map_err(Error::Stream)
}

fn averaged_into(group: Group) -> &'static str {
    if group.is_likelihood() {
        "averaged into likelihood"
    } else {
        "averaged into impact"
    }
}

fn print_matrix(profile: Profile) -> Result<()> {
    let mut out = BufWriter::new(io::stdout().lock());

    writeln!(
        out,
        "Risk = Likelihood x Impact, `{}` profile ({}).\n",
        profile,
        profile.description()
    )
    .map_err(Error::Stream)?;
    writeln!(out, "{:<10} {:>32}", "", "Likelihood").map_err(Error::Stream)?;
    writeln!(
        out,
        "{:<10} {:>10} {:>10} {:>10}",
        "Impact", "LOW", "MEDIUM", "HIGH"
    )
    .map_err(Error::Stream)?;

    for (impact, row) in grid(profile) {
        writeln!(
            out,
            "{:<10} {:>10} {:>10} {:>10}",
            impact.as_str(),
            row[0].as_str(),
            row[1].as_str(),
            row[2].as_str()
        )
        .map_err(Error::Stream)?;
    }

    writeln!(
        out,
        "\nBand thresholds: 0 to <3 LOW, 3 to <6 MEDIUM, 6 to 9 HIGH."
    )
    .map_err(Error::Stream)?;

    out.flush().map_err(Error::Stream)
}

fn print_schema() -> Result<()> {
    let mut out = BufWriter::new(io::stdout().lock());
    let value = serde_json::to_vec_pretty(&schema::schema())?;
    out.write_all(&value).map_err(Error::Stream)?;
    out.write_all(b"\n").map_err(Error::Stream)?;
    out.flush().map_err(Error::Stream)
}

fn assess(args: AssessArgs) -> Result<()> {
    let formats = FormatArg::expand(&args.formats);
    let assessments = collect(&args)?;

    let profile = args.profile.into();
    let basis = args.impact_basis.into();
    let reports: Vec<Report> = assessments
        .into_iter()
        .map(|assessment| Report::new(assessment, profile, basis))
        .collect();

    emit(&reports, &formats, &args)
}

/// Gather threats from whichever input the invocation selected.
fn collect(args: &AssessArgs) -> Result<Vec<Assessment>> {
    if let Some(path) = &args.input {
        return file::load(path, args.allow_missing);
    }

    if !args.factors.is_empty() {
        let title = args.title.clone().ok_or(Error::MissingTitle)?;
        return Ok(vec![Assessment::build(
            title,
            args.id.clone(),
            args.notes.clone(),
            args.location.clone(),
            &args.factors.scores,
            args.allow_missing,
        )?]);
    }

    if !io::stdin().is_terminal() {
        return Err(Error::NoInput);
    }

    let mut input = io::stdin().lock();
    let mut output = io::stderr().lock();
    let assessment = interactive::prompt(
        &mut input,
        &mut output,
        args.title.clone(),
        args.id.clone(),
        args.notes.clone(),
        args.location.clone(),
    )?;

    Ok(vec![assessment])
}

fn emit(reports: &[Report], formats: &[Format], args: &AssessArgs) -> Result<()> {
    match &args.output {
        None => {
            if formats.len() > 1 {
                return Err(Error::OutputNotADirectory {
                    count: formats.len(),
                });
            }
            let format = formats[0];
            if format.is_binary() {
                return Err(Error::NeedsOutput {
                    format: format.as_str().to_string(),
                });
            }
            let bytes = format.render(reports)?;
            let mut out = BufWriter::new(io::stdout().lock());
            out.write_all(&bytes).map_err(Error::Stream)?;
            out.flush().map_err(Error::Stream)
        }
        Some(path) => {
            let as_directory = formats.len() > 1 || path.is_dir();

            if as_directory {
                ensure_directory(path, args.mkdir)?;
                for format in formats {
                    let target = path.join(format!("{}.{}", stem(reports), format.extension()));
                    write_one(reports, *format, &target, args.quiet)?;
                }
            } else {
                if let Some(parent) = path
                    .parent()
                    .filter(|parent| !parent.as_os_str().is_empty())
                {
                    ensure_directory(parent, args.mkdir)?;
                }
                write_one(reports, formats[0], path, args.quiet)?;
            }

            Ok(())
        }
    }
}

/// Base filename used when the output path is a directory.
fn stem(reports: &[Report]) -> String {
    if reports.len() == 1 {
        reports[0].id()
    } else {
        "threats".to_string()
    }
}

fn ensure_directory(path: &Path, mkdir: bool) -> Result<()> {
    if path.is_dir() {
        return Ok(());
    }
    if !mkdir {
        return Err(Error::MissingParent {
            path: path.to_path_buf(),
        });
    }
    std::fs::create_dir_all(path).map_err(|source| Error::io(path, source))
}

fn write_one(reports: &[Report], format: Format, target: &PathBuf, quiet: bool) -> Result<()> {
    if format.is_binary() {
        sqlite::write(reports, target)?;
    } else {
        let bytes = format.render(reports)?;
        std::fs::write(target, bytes).map_err(|source| Error::io(target, source))?;
    }

    if !quiet {
        eprintln!("wrote {} ({})", target.display(), format);
    }

    Ok(())
}
