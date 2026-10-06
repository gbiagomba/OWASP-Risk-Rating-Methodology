# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-10-06

First release. `riskforge` scores threats with the OWASP Risk Rating
Methodology and documents how each rating was derived.

### Added

- Factor catalog: all 16 OWASP factors across four groups, with the anchored option text for every rung transcribed from the `Rating` sheet of the OWASP Risk Rating template spreadsheet (`src/model/catalog.rs`). Scores between two anchors are accepted as interpolation.
- Scoring: likelihood, technical impact, business impact and overall impact averages, with band mapping at `0 to <3` LOW, `3 to <6` MEDIUM and `6 to 9` HIGH (`src/model/score.rs`).
- Two severity matrices (`src/model/matrix.rs`): `capped`, the default, with three bands and a ceiling of High; and `owasp`, as published, including the Note and Critical tiers. The profiles agree on seven of nine cells and diverge only at the Low-by-Low and High-by-High corners.
- `--impact-basis overall|technical|business` selects which impact average feeds the matrix. `business` falls back to the technical average when every business factor is zero.
- Three input paths: interactive prompts driven by the catalog (`src/input/interactive.rs`), a YAML or JSON file accepting a single threat, a sequence or a `threats:` wrapper (`src/input/file.rs`), and 16 per-factor CLI flags generated from the catalog (`src/cli.rs`).
- Batch mode: one input file holding many threats rates in a single run and produces one table.
- Nine output formats (`src/report/`): `text`, `json`, `csv`, `html`, `md`, `sarif`, `sqlite`, `sql` and `all`.
- `riskforge schema` emits the JSON Schema for an input file, and `riskforge factors --json` the same catalog, so a coding agent never has to guess a field name or a score range.
- `riskforge matrix --profile <name>` prints either severity matrix.
- `riskforge factors` prints the catalog with every scored option.
- Example batch input at `examples/threats.yaml`, including a threat that rates High under `capped` and Critical under `owasp`.
- 95 tests, including a spreadsheet parity suite that reproduces the template's worked example and asserts every derived number against the value the spreadsheet shows.

### Security

- Band boundaries are compared on integer factor sums rather than on the floating point average, so a value sitting exactly on 3.0 or 6.0 cannot land in the wrong band through rounding.
- A score of `0` counts toward its average and never shrinks the divisor. Treating zeros as unscored would have changed the reference example's technical impact from 2.75 (LOW) to 5.5 (MEDIUM).
- Input validation rejects a score outside `0..=9` and an unknown factor key by name, with a did-you-mean suggestion, rather than silently scoring the factor 0. An omitted factor is an error unless `--allow-missing` is passed, and assumed scores are marked as such in every report.
- The `sql` renderer doubles single quotes and strips control characters, so no title or note can break out of its literal. The `sqlite` renderer binds every value as a parameter.
- The `html` renderer escapes all interpolated text and emits no scripts and no external references, so a report is safe to open and to pass on.
- Output paths are never created implicitly; a missing parent directory is an error unless `--mkdir` is passed.
- `panic = "abort"` in the release profile, and no unsafe code in the crate.

### Changed

- Project scaffold filled out for this tool: `Cargo.toml`, `Makefile` (upgraded from the Lite variant to Pro, which supplies the `ci` target the README documents), `Dockerfile`, `README.md`, install scripts and the CI workflow.

### Fixed

- `Dockerfile`: the dependency-cache layer copied `Cargo.lock` unconditionally while the file was gitignored and absent, so `docker build` failed at that layer. The copy now tolerates its absence, and the lock file is committed, which also makes builds reproducible.
- `scripts/install.sh`, `install.ps1` and `install.bat`: `REPO` was derived from the binary name. The binary is `riskforge` but the repository is `OWASP-Risk-Rating-Methodology`, so every installer resolved a release URL that does not exist. `REPO` is now set explicitly.
- `.github/workflows/ci-release.yml`: `actions/checkout` raised from v6 to v7 across all 7 call sites and `actions/setup-python` from v6 to v7, applying two Dependabot updates whose branches had been pushed without a pull request ever being opened.

---

**AGENT NOTE:** Update this file before EVERY release as per RULE 5
