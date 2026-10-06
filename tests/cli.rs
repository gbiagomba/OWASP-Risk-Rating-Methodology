//! End-to-end exercise of the binary: every subcommand, every format, and
//! the rejections that must exit non-zero.

use riskforge::model::catalog::FACTORS;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU32, Ordering};

const BINARY: &str = env!("CARGO_BIN_EXE_riskforge");
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A scratch directory under `target`, which is already ignored by git.
struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join("test-output")
            .join(format!("{label}-{}-{unique}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("scratch directory");
        Scratch(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(BINARY)
        .args(args)
        .output()
        .expect("the binary runs")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The reference example from the template spreadsheet, as CLI flags.
const REFERENCE_FLAGS: &[&str] = &[
    "--skill-level",
    "4",
    "--motive",
    "1",
    "--opportunity",
    "4",
    "--size",
    "5",
    "--ease-of-discovery",
    "3",
    "--ease-of-exploit",
    "3",
    "--awareness",
    "4",
    "--intrusion-detection",
    "3",
    "--loss-of-confidentiality",
    "2",
    "--loss-of-integrity",
    "0",
    "--loss-of-availability",
    "0",
    "--loss-of-accountability",
    "9",
    "--financial-damage",
    "1",
    "--reputation-damage",
    "1",
    "--non-compliance",
    "0",
    "--privacy-violation",
    "5",
];

fn reference_args<'a>(extra: &[&'a str]) -> Vec<&'a str> {
    let mut args = vec!["assess", "--title", "Full database theft from datacenter"];
    args.extend_from_slice(REFERENCE_FLAGS);
    args.extend_from_slice(extra);
    args
}

fn reference_yaml() -> String {
    let factors: Vec<String> = [
        ("skill_level", 4),
        ("motive", 1),
        ("opportunity", 4),
        ("size", 5),
        ("ease_of_discovery", 3),
        ("ease_of_exploit", 3),
        ("awareness", 4),
        ("intrusion_detection", 3),
        ("loss_of_confidentiality", 2),
        ("loss_of_integrity", 0),
        ("loss_of_availability", 0),
        ("loss_of_accountability", 9),
        ("financial_damage", 1),
        ("reputation_damage", 1),
        ("non_compliance", 0),
        ("privacy_violation", 5),
    ]
    .iter()
    .map(|(key, score)| format!("    {key}: {score}"))
    .collect();

    format!(
        "title: Full database theft from datacenter\nfactors:\n{}\n",
        factors.join("\n")
    )
}

// Informational subcommands.

#[test]
fn help_and_version_succeed() {
    for args in [vec!["--help"], vec!["--version"]] {
        let output = run(&args);
        assert!(output.status.success(), "{args:?} should succeed");
        assert!(!stdout(&output).is_empty());
    }
}

#[test]
fn help_lists_every_factor_flag_under_its_group() {
    let output = run(&["assess", "--help"]);
    assert!(output.status.success());
    let text = stdout(&output);

    for factor in FACTORS {
        assert!(
            text.contains(&format!("--{}", factor.flag)),
            "help should list --{}",
            factor.flag
        );
    }
    for heading in [
        "Threat agent factors",
        "Vulnerability factors",
        "Technical impact",
        "Business impact",
    ] {
        assert!(text.contains(heading), "help should group under {heading}");
    }
}

#[test]
fn factors_prints_the_whole_catalog() {
    let output = run(&["factors"]);
    assert!(output.status.success());
    let text = stdout(&output);

    for factor in FACTORS {
        assert!(text.contains(factor.name), "missing {}", factor.name);
        assert!(text.contains(factor.key), "missing {}", factor.key);
    }
    assert!(text.contains("Security penetration skills"));
    assert!(text.contains("Millions of people"));
}

#[test]
fn schema_is_valid_json_and_requires_every_factor() {
    let output = run(&["schema"]);
    assert!(output.status.success());

    let schema: serde_json::Value =
        serde_json::from_str(&stdout(&output)).expect("schema is valid JSON");

    let required = schema["$defs"]["threat"]["properties"]["factors"]["required"]
        .as_array()
        .expect("the factors object lists required keys");
    assert_eq!(required.len(), 16);

    for factor in FACTORS {
        assert!(
            required.iter().any(|key| key == factor.key),
            "schema should require {}",
            factor.key
        );
        let property =
            &schema["$defs"]["threat"]["properties"]["factors"]["properties"][factor.key];
        assert_eq!(property["maximum"], 9);
        assert_eq!(property["minimum"], 0);
    }
}

/// The severity cells of a printed matrix, read from the three data rows.
/// The surrounding prose names the tiers a profile excludes, so only the
/// cells themselves can be asserted on.
fn matrix_cells(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let first = fields.next()?;
            if ["LOW", "MEDIUM", "HIGH"].contains(&first) {
                Some(fields.map(str::to_string).collect::<Vec<_>>())
            } else {
                None
            }
        })
        .flatten()
        .collect()
}

#[test]
fn matrix_prints_both_profiles() {
    let capped = run(&["matrix", "--profile", "capped"]);
    assert!(capped.status.success());
    let capped_text = stdout(&capped);
    assert!(capped_text.contains("capped"));

    let capped_cells = matrix_cells(&capped_text);
    assert_eq!(capped_cells.len(), 9, "nine cells: {capped_cells:?}");
    assert!(
        !capped_cells.iter().any(|cell| cell == "Critical"),
        "the capped matrix has no Critical tier: {capped_cells:?}"
    );
    assert!(
        !capped_cells.iter().any(|cell| cell == "Note"),
        "the capped matrix has no Note tier: {capped_cells:?}"
    );

    let owasp = run(&["matrix", "--profile", "owasp"]);
    assert!(owasp.status.success());
    let owasp_cells = matrix_cells(&stdout(&owasp));
    assert_eq!(owasp_cells.len(), 9);
    assert!(owasp_cells.iter().any(|cell| cell == "Critical"));
    assert!(owasp_cells.iter().any(|cell| cell == "Note"));
}

// Scoring through flags.

#[test]
fn the_reference_example_rates_low_on_the_terminal() {
    let output = run(&reference_args(&[]));
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);

    assert!(text.contains("3.375"), "likelihood average");
    assert!(text.contains("2.750"), "technical impact average");
    assert!(text.contains("1.750"), "business impact average");
    assert!(text.contains("2.250"), "overall impact average");
    assert!(text.contains("MEDIUM x LOW = Low"), "matrix lookup: {text}");
}

#[test]
fn json_output_carries_the_whole_derivation() {
    let output = run(&reference_args(&["--format", "json"]));
    assert!(output.status.success(), "{}", stderr(&output));

    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    let threat = &document["threats"][0];

    assert_eq!(threat["severity"], "Low");
    assert_eq!(threat["likelihood"]["average"], 3.375);
    assert_eq!(threat["likelihood"]["band"], "MEDIUM");
    assert_eq!(threat["likelihood"]["sum"], 27);
    assert_eq!(threat["impact"]["technical"]["average"], 2.75);
    assert_eq!(threat["impact"]["business"]["average"], 1.75);
    assert_eq!(threat["impact"]["overall"]["average"], 2.25);
    assert_eq!(threat["impact"]["basis"], "overall");
    assert_eq!(threat["profile"], "capped");
    assert_eq!(threat["factors"]["skill_level"]["score"], 4);
    assert_eq!(
        threat["factors"]["loss_of_accountability"]["anchor"],
        "Completely anonymous"
    );
    // 4 is between the skill-level anchors at 3 and 5.
    assert!(threat["factors"]["skill_level"]["anchor"].is_null());
    assert_eq!(document["threats"].as_array().unwrap().len(), 1);
}

#[test]
fn the_owasp_profile_is_selectable() {
    let output = run(&reference_args(&["--format", "json", "--profile", "owasp"]));
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert_eq!(document["threats"][0]["profile"], "owasp");
}

#[test]
fn the_impact_basis_is_selectable() {
    let output = run(&reference_args(&[
        "--format",
        "json",
        "--impact-basis",
        "business",
    ]));
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert_eq!(document["threats"][0]["impact"]["basis"], "business");
    assert_eq!(document["threats"][0]["impact"]["used"]["average"], 1.75);
}

#[test]
fn sarif_output_validates_against_its_own_shape() {
    let output = run(&reference_args(&["--format", "sarif"]));
    assert!(output.status.success(), "{}", stderr(&output));

    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");

    assert_eq!(document["version"], "2.1.0");
    assert!(document["$schema"].as_str().unwrap().contains("sarif"));

    let run_object = &document["runs"][0];
    assert_eq!(run_object["tool"]["driver"]["name"], "riskforge");
    assert_eq!(
        run_object["tool"]["driver"]["rules"][0]["id"],
        "full-database-theft-from-datacenter"
    );

    let result = &run_object["results"][0];
    assert_eq!(result["level"], "note", "Low maps to the note level");
    assert_eq!(result["ruleId"], "full-database-theft-from-datacenter");
    assert!(result["partialFingerprints"]["riskforge/v1"].is_string());
    assert_eq!(result["properties"]["likelihood"]["average"], 3.375);
}

#[test]
fn a_location_becomes_a_sarif_physical_location() {
    let output = run(&reference_args(&[
        "--format",
        "sarif",
        "--location",
        "src/db/export.rs",
    ]));
    assert!(output.status.success());
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert_eq!(
        document["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
            ["uri"],
        "src/db/export.rs"
    );
}

#[test]
fn csv_output_has_one_header_and_one_row() {
    let output = run(&reference_args(&["--format", "csv"]));
    assert!(output.status.success());
    let text = stdout(&output);
    let lines: Vec<&str> = text.lines().collect();

    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("id,title,skill_level,"));
    assert!(lines[0].ends_with(",profile,severity"));
    assert!(lines[1].ends_with(",capped,Low"));
}

#[test]
fn markdown_output_carries_a_paste_ready_threat_row() {
    let output = run(&reference_args(&["--format", "md"]));
    assert!(output.status.success());
    let text = stdout(&output);

    assert!(text.contains("| Threat | Likelihood | Impact | Overall severity |"));
    assert!(text.contains("| MEDIUM (3.375) | LOW (2.250) | Low |"));
    assert!(text.contains("### Matrix applied"));
}

#[test]
fn html_output_is_self_contained() {
    let output = run(&reference_args(&["--format", "html"]));
    assert!(output.status.success());
    let text = stdout(&output);

    assert!(text.starts_with("<!DOCTYPE html>"));
    assert!(text.contains("</html>"));
    assert!(text.contains("<style>"));
    assert!(
        !text.contains("<script"),
        "the report should carry no script"
    );
    assert!(
        !text.contains("https://cdn"),
        "the report should fetch nothing"
    );
    assert!(text.contains("prefers-color-scheme"));
}

#[test]
fn sql_output_escapes_a_quote_in_a_title() {
    let mut args = vec![
        "assess",
        "--title",
        "Bobby's table'); DROP TABLE assessment; --",
        "--format",
        "sql",
    ];
    args.extend_from_slice(REFERENCE_FLAGS);

    let output = run(&args);
    assert!(output.status.success(), "{}", stderr(&output));
    let text = stdout(&output);

    assert!(text.contains("CREATE TABLE IF NOT EXISTS assessment"));
    assert!(
        text.contains("'Bobby''s table''); DROP TABLE assessment; --'"),
        "the quote should be doubled, got: {text}"
    );
    assert!(
        !text.contains("DROP TABLE assessment;\n"),
        "no statement should escape its literal"
    );
}

// File input and batches.

#[test]
fn a_file_produces_the_same_rating_as_the_flags() {
    let scratch = Scratch::new("file-input");
    let input = scratch.join("threat.yaml");
    std::fs::write(&input, reference_yaml()).expect("writes input");

    let output = run(&[
        "assess",
        "--input",
        input.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));

    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert_eq!(document["threats"][0]["likelihood"]["average"], 3.375);
    assert_eq!(document["threats"][0]["severity"], "Low");
}

#[test]
fn standard_input_is_accepted() {
    use std::io::Write as _;
    use std::process::Stdio;

    let mut child = Command::new(BINARY)
        .args(["assess", "--input", "-", "--format", "json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawns");

    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(reference_yaml().as_bytes())
        .expect("writes");

    let output = child.wait_with_output().expect("completes");
    assert!(output.status.success(), "{}", stderr(&output));
    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    assert_eq!(document["threats"][0]["severity"], "Low");
}

#[test]
fn a_batch_rates_every_threat_and_summarizes() {
    let scratch = Scratch::new("batch");
    let input = scratch.join("threats.yaml");

    let low = FACTORS
        .iter()
        .map(|factor| format!("      {}: 1", factor.key))
        .collect::<Vec<_>>()
        .join("\n");
    let high = FACTORS
        .iter()
        .map(|factor| format!("      {}: 8", factor.key))
        .collect::<Vec<_>>()
        .join("\n");

    let text = format!(
        "threats:\n  - title: Quiet risk\n    factors:\n{low}\n  \
         - title: Loud risk\n    factors:\n{high}\n"
    );
    std::fs::write(&input, text).expect("writes input");

    let output = run(&[
        "assess",
        "--input",
        input.to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));

    let document: serde_json::Value = serde_json::from_str(&stdout(&output)).expect("valid JSON");
    let threats = document["threats"].as_array().expect("an array");
    assert_eq!(threats.len(), 2);
    assert_eq!(threats[0]["severity"], "Low");
    assert_eq!(threats[1]["severity"], "High");

    // The terminal format appends a summary when there is more than one.
    let terminal = run(&["assess", "--input", input.to_str().unwrap()]);
    assert!(terminal.status.success());
    assert!(stdout(&terminal).contains("Summary of 2 threats"));
}

// Output paths.

#[test]
fn every_format_writes_into_a_directory() {
    let scratch = Scratch::new("all-formats");
    let input = scratch.join("threat.yaml");
    std::fs::write(&input, reference_yaml()).expect("writes input");
    let out_dir = scratch.join("out");

    let output = run(&[
        "assess",
        "--input",
        input.to_str().unwrap(),
        "--format",
        "all",
        "--output",
        out_dir.to_str().unwrap(),
        "--mkdir",
    ]);
    assert!(output.status.success(), "{}", stderr(&output));

    let stem = "full-database-theft-from-datacenter";
    for extension in ["txt", "json", "csv", "html", "md", "sarif", "db", "sql"] {
        let written = out_dir.join(format!("{stem}.{extension}"));
        let metadata = std::fs::metadata(&written)
            .unwrap_or_else(|_| panic!("{} should exist", written.display()));
        assert!(
            metadata.len() > 0,
            "{} should not be empty",
            written.display()
        );
    }

    // The SQLite file is a real database.
    let database = out_dir.join(format!("{stem}.db"));
    let bytes = std::fs::read(&database).expect("reads the database");
    assert!(
        bytes.starts_with(b"SQLite format 3\0"),
        "the .db file should carry the SQLite header"
    );
}

#[test]
fn a_single_format_writes_to_a_named_file() {
    let scratch = Scratch::new("single-file");
    let target = scratch.join("rating.json");

    let output = run(&reference_args(&[
        "--format",
        "json",
        "--output",
        target.to_str().unwrap(),
    ]));
    assert!(output.status.success(), "{}", stderr(&output));

    let text = std::fs::read_to_string(&target).expect("reads the report");
    let document: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    assert_eq!(document["threats"][0]["severity"], "Low");
    assert!(stderr(&output).contains("wrote"));
}

#[test]
fn quiet_suppresses_the_progress_line() {
    let scratch = Scratch::new("quiet");
    let target = scratch.join("rating.json");

    let output = run(&reference_args(&[
        "--format",
        "json",
        "--output",
        target.to_str().unwrap(),
        "--quiet",
    ]));
    assert!(output.status.success());
    assert!(stderr(&output).is_empty(), "stderr: {}", stderr(&output));
}

#[test]
fn a_missing_directory_is_not_created_without_mkdir() {
    let scratch = Scratch::new("no-mkdir");
    let target = scratch.join("nested/deeper/rating.json");

    let output = run(&reference_args(&[
        "--format",
        "json",
        "--output",
        target.to_str().unwrap(),
    ]));
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--mkdir"), "{}", stderr(&output));
    assert!(!target.exists());
}

// Rejections.

#[test]
fn a_score_above_nine_exits_non_zero_and_names_the_factor() {
    let mut args = reference_args(&[]);
    let position = args.iter().position(|arg| *arg == "--skill-level").unwrap();
    args[position + 1] = "10";

    let output = run(&args);
    assert!(!output.status.success());
    let text = stderr(&output);
    assert!(text.contains("skill_level"), "{text}");
    assert!(text.contains("0 to 9"), "{text}");
}

#[test]
fn a_non_numeric_score_is_rejected_by_the_parser() {
    let mut args = reference_args(&[]);
    let position = args.iter().position(|arg| *arg == "--motive").unwrap();
    args[position + 1] = "high";

    let output = run(&args);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("--motive"), "{}", stderr(&output));
}

#[test]
fn an_unknown_flag_is_rejected() {
    let output = run(&["assess", "--title", "x", "--skill-lvl", "4"]);
    assert!(!output.status.success());
}

#[test]
fn a_missing_factor_exits_non_zero_unless_allowed() {
    let mut args = reference_args(&[]);
    let position = args.iter().position(|arg| *arg == "--motive").unwrap();
    args.drain(position..position + 2);

    let rejected = run(&args);
    assert!(!rejected.status.success());
    let text = stderr(&rejected);
    assert!(text.contains("motive"), "{text}");
    assert!(text.contains("--allow-missing"), "{text}");

    let mut allowed = args.clone();
    allowed.extend_from_slice(&["--allow-missing", "--format", "json"]);
    let accepted = run(&allowed);
    assert!(accepted.status.success(), "{}", stderr(&accepted));

    let document: serde_json::Value = serde_json::from_str(&stdout(&accepted)).expect("valid JSON");
    assert_eq!(document["threats"][0]["factors"]["motive"]["score"], 0);
    assert_eq!(document["threats"][0]["factors"]["motive"]["assumed"], true);
    assert_eq!(document["threats"][0]["assumed_factors"][0], "motive");
}

#[test]
fn an_unknown_factor_key_in_a_file_suggests_the_right_one() {
    let scratch = Scratch::new("typo");
    let input = scratch.join("threat.yaml");
    std::fs::write(&input, reference_yaml().replace("skill_level", "skill_lvl"))
        .expect("writes input");

    let output = run(&["assess", "--input", input.to_str().unwrap()]);
    assert!(!output.status.success());
    let text = stderr(&output);
    assert!(text.contains("skill_lvl"), "{text}");
    assert!(text.contains("did you mean `skill_level`"), "{text}");
}

#[test]
fn a_title_is_required_when_scoring_with_flags() {
    let mut args = vec!["assess"];
    args.extend_from_slice(REFERENCE_FLAGS);

    let output = run(&args);
    assert!(!output.status.success());
    assert!(stderr(&output).contains("title"), "{}", stderr(&output));
}

#[test]
fn sqlite_to_standard_output_is_refused() {
    let output = run(&reference_args(&["--format", "sqlite"]));
    assert!(!output.status.success());
    let text = stderr(&output);
    assert!(text.contains("sqlite"), "{text}");
    assert!(text.contains("--output"), "{text}");
}

#[test]
fn several_formats_to_standard_output_are_refused() {
    let output = run(&reference_args(&["--format", "json,csv"]));
    assert!(!output.status.success());
    assert!(stderr(&output).contains("directory"), "{}", stderr(&output));
}

#[test]
fn a_missing_input_file_names_the_path() {
    let output = run(&["assess", "--input", "/no/such/threats.yaml"]);
    assert!(!output.status.success());
    assert!(
        stderr(&output).contains("/no/such/threats.yaml"),
        "{}",
        stderr(&output)
    );
}

#[test]
fn no_input_at_all_explains_the_options() {
    // Standard input is a pipe under the test harness, not a terminal, so
    // the tool must not sit waiting for prompts.
    use std::process::Stdio;

    let output = Command::new(BINARY)
        .arg("assess")
        .stdin(Stdio::null())
        .output()
        .expect("runs");

    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("--input"), "{text}");
}
