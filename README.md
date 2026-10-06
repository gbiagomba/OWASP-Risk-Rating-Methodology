# riskforge

> VERSION: 1.0.0  
> DESCRIPTION: Score threat-model risk with the OWASP Risk Rating Methodology and document how the rating was derived  
> AUTHOR: Gilles Biagomba  
> LICENSE: GPL-3.0  

---

## 🔥 Background / Lore

Threat-table severities are usually settled in a spreadsheet, by hand, late in
a review. Sixteen numbers get averaged, two bands get crossed in a matrix, and
the only record of how `High` became `High` is a cell nobody will reopen.

`riskforge` takes that spreadsheet and makes it a tool. It asks the same
sixteen questions the OWASP Risk Rating Methodology asks, applies
`Risk = Likelihood x Impact`, and writes out the whole derivation: every factor
score, the option text behind it, both averages, the band each one falls in,
and the matrix cell they met in. The rating stops being an assertion and
becomes an artifact. A human can walk it; a coding agent can produce it.

---

## 📑 Table of Contents
- [Background / Lore](#-background--lore)
- [Features](#-features)
- [The methodology](#-the-methodology)
- [Installation](#-installation)
  - [Using GitHub Releases](#-using-github-releases)
  - [Using Cargo](#-using-cargo-rust-projects)
  - [Compiling From Source](#-compiling-from-source)
  - [Using Install Scripts](#-using-install-scripts)
- [Flags](#-flags)
- [Usage](#-usage)
  - [Interactive](#interactive)
  - [From a file](#from-a-file)
  - [From flags](#from-flags)
  - [For a coding agent](#for-a-coding-agent)
  - [Output formats](#output-formats)
  - [Running Tests](#-running-tests)
  - [Using Docker](#-using-docker)
  - [Using the Makefile](#-using-the-makefile)
- [Deviation from the OWASP wiki](#-deviation-from-the-owasp-wiki)
- [Contributing](#-contributing)
- [License](#license)

---

## ✨ Features

- Scores all 16 OWASP factors with the published option text for each rung
- Two severity matrices: `capped` (three bands, ceiling of High) and `owasp` (as published, with Note and Critical)
- Three ways in: interactive prompts, a YAML or JSON file, or per-factor flags
- Batch mode, so a whole threat table rates in one run
- Nine output formats: `text`, `json`, `csv`, `html`, `md`, `sarif`, `sqlite`, `sql`, `all`
- Self-describing: `riskforge schema` emits the JSON Schema a coding agent needs to produce valid input
- Shows its work: every report states the sums, the averages, the bands and the matrix cell
- Band boundaries compared on integer sums, so a value sitting exactly on 3.0 or 6.0 cannot drift
- Cross-platform binaries (Linux, macOS, Windows) on x64 and ARM64
- No network access, no telemetry, no runtime dependencies

---

## 🧮 The methodology

Sixteen factors, each scored 0 to 9.

| Side | Group | Factors |
|---|---|---|
| Likelihood | Threat agent | Skill level, Motive, Opportunity, Size |
| Likelihood | Vulnerability | Ease of discovery, Ease of exploit, Awareness, Intrusion detection |
| Impact | Technical | Loss of confidentiality, Loss of integrity, Loss of availability, Loss of accountability |
| Impact | Business | Financial damage, Reputation damage, Non-compliance, Privacy violation |

The eight likelihood factors average into a likelihood score and the eight
impact factors into an impact score. Each average maps to a band:

| Average | Band |
|---|---|
| 0 to <3 | LOW |
| 3 to <6 | MEDIUM |
| 6 to 9 | HIGH |

The two bands then meet in a matrix. Rows are impact, columns are likelihood.

**`capped` profile (default):** three bands, ceiling of High. For programs whose
threat tables top out at High.

| Impact | Likelihood LOW | MEDIUM | HIGH |
|---|---|---|---|
| HIGH | Medium | High | High |
| MEDIUM | Low | Medium | High |
| LOW | Low | Low | Medium |

**`owasp` profile:** the matrix as published, including the Note and Critical
tiers.

| Impact | Likelihood LOW | MEDIUM | HIGH |
|---|---|---|---|
| HIGH | Medium | High | Critical |
| MEDIUM | Low | Medium | High |
| LOW | Note | Low | Medium |

The profiles agree on seven of the nine cells. They diverge only at the two
corners, Low-by-Low and High-by-High.

### Two rules that are easy to get wrong

**A score of 0 is a real score.** It is not a way to say "unscored". It counts
toward its average and never shrinks the divisor. The reference example makes
this concrete: its technical impact is `(2 + 0 + 0 + 9) / 4 = 2.75`, which
bands LOW. Treating the zeros as absent would give `(2 + 9) / 2 = 5.5`, which
bands MEDIUM and changes the rating. To record a factor you genuinely have not
assessed, omit it and pass `--allow-missing`; the report then marks it as
assumed rather than scored.

**Band boundaries are compared on integer sums, not on the average.** For eight
factors, `average < 3` holds exactly when `sum < 24`. A likelihood summing to
exactly 24 bands MEDIUM every time, with no dependence on floating point
representation.

### Which impact feeds the matrix

`--impact-basis` selects it:

- `overall` (default): all eight impact factors averaged together, matching the reference spreadsheet
- `technical`: the four technical factors only
- `business`: the four business factors, which the methodology treats as governing when they are known. Falls back to the technical average when every business factor is zero.

Whichever basis is chosen, the report prints all four averages, so nothing is
hidden by the selection.

---

## 📦 Installation

### 🚀 Using GitHub Releases
Download the precompiled binary for your platform:

| Platform | Architecture | Binary |
|----------|-------------|--------|
| Linux | x64 | `riskforge-linux-x64` |
| Linux | ARM64 | `riskforge-linux-aarch64` |
| macOS | x64 | `riskforge-macos-x64` |
| macOS | ARM64 | `riskforge-macos-aarch64` |
| Windows | x64 | `riskforge-windows-x64.exe` |
| Windows | ARM64 | `riskforge-windows-aarch64.exe` |

Every release ships a `.sha256` next to each binary. Verify before installing:

```bash
sha256sum -c riskforge-linux-x64.sha256
chmod +x riskforge-linux-x64
sudo mv riskforge-linux-x64 /usr/local/bin/riskforge
```

---

### 📦 Using Cargo (Rust projects)

```bash
cargo install --git https://github.com/gbiagomba/OWASP-Risk-Rating-Methodology
```

---

### 🛠️ Compiling From Source

```bash
git clone https://github.com/gbiagomba/OWASP-Risk-Rating-Methodology
cd OWASP-Risk-Rating-Methodology
cargo build --release
```

The binary appears in:

```
target/release/riskforge
```

### 🔧 Using Install Scripts

**Linux/macOS/Unix:**
```bash
curl -sSL https://raw.githubusercontent.com/gbiagomba/OWASP-Risk-Rating-Methodology/main/scripts/install.sh | bash
# Or download and run locally:
wget https://raw.githubusercontent.com/gbiagomba/OWASP-Risk-Rating-Methodology/main/scripts/install.sh
chmod +x install.sh
./install.sh
```

**Windows (PowerShell - Run as Administrator):**
```powershell
irm https://raw.githubusercontent.com/gbiagomba/OWASP-Risk-Rating-Methodology/main/scripts/install.ps1 | iex
```

**Windows (Batch - Run as Administrator):**
```batch
curl -L https://raw.githubusercontent.com/gbiagomba/OWASP-Risk-Rating-Methodology/main/scripts/install.bat -o install.bat
install.bat
```

---

## 🚩 Flags

### Subcommands

```
assess     Score a threat and write its rating (the default)
factors    Print the factor catalog with every scored option
matrix     Print a severity matrix
schema     Emit the JSON Schema for an input file
```

### assess

```
-i, --input <FILE>          Read threats from a YAML or JSON file, or `-` for stdin
-t, --title <TEXT>          Threat title, required when scoring with flags
    --id <TEXT>             Stable identifier, defaults to a slug of the title
    --notes <TEXT>          Free-text note carried into the report
    --location <URI>        Artifact or code location, carried into SARIF output
-f, --format <FORMAT>       text, json, csv, html, md, sarif, sqlite, sql, all
-o, --output <PATH>         Output file, or directory when several formats are requested
    --mkdir                 Create the output directory when it does not exist
    --profile <PROFILE>     capped (default) or owasp
    --impact-basis <BASIS>  overall (default), technical or business
    --allow-missing         Score any unscored factor 0 and mark it as assumed
-q, --quiet                 Suppress the progress line on standard error
-h, --help                  Show help information
-V, --version               Show version
```

### Per-factor flags

One flag per factor, grouped in `--help` by the group it averages into. Each
takes a value from 0 to 9.

```
Threat agent factors:   --skill-level --motive --opportunity --size
Vulnerability factors:  --ease-of-discovery --ease-of-exploit --awareness --intrusion-detection
Technical impact:       --loss-of-confidentiality --loss-of-integrity
                        --loss-of-availability --loss-of-accountability
Business impact:        --financial-damage --reputation-damage --non-compliance
                        --privacy-violation
```

Run `riskforge factors` for the option text behind every score.

---

## 💡 Usage

### Interactive

With no input and a terminal attached, `riskforge` walks you through all 16
factors, printing the anchored options for each:

```bash
riskforge assess
```

```
Threat agent factors

  Skill level
    1  No technical skills
    3  Some technical skills
    5  Advanced computer user
    6  Network and programming skills
    9  Security penetration skills
  Skill level [0-9]: 4
```

Scores between two listed options are accepted as interpolation, exactly as the
spreadsheet drop-downs allow.

### From a file

```bash
riskforge assess -i examples/threats.yaml
```

One file can hold a single threat, a sequence of threats, or a `threats:`
sequence. See `examples/threats.yaml`.

```yaml
threats:
  - title: Unauthenticated export endpoint discloses customer records
    id: unauth-export-disclosure
    location: src/api/export.rs
    factors:
      skill_level: 3
      motive: 9
      # ... all 16 factors
```

### From flags

```bash
riskforge assess -t "Full database theft from datacenter" \
  --skill-level 4 --motive 1 --opportunity 4 --size 5 \
  --ease-of-discovery 3 --ease-of-exploit 3 --awareness 4 --intrusion-detection 3 \
  --loss-of-confidentiality 2 --loss-of-integrity 0 \
  --loss-of-availability 0 --loss-of-accountability 9 \
  --financial-damage 1 --reputation-damage 1 \
  --non-compliance 0 --privacy-violation 5
```

```
Overall likelihood:       3.375 (MEDIUM)
Overall technical impact: 2.750 (LOW)
Overall business impact:  1.750 (LOW)
Overall impact:           2.250 (LOW)

Risk = Likelihood x Impact = MEDIUM x LOW = Low
```

### For a coding agent

Read the contract, then produce input against it. No field names need guessing:

```bash
riskforge schema > schema.json          # JSON Schema for an input file
riskforge factors --json                # the same catalog, with every anchor
riskforge assess -i threats.yaml -f json --quiet
```

Bad input fails loudly and names the factor at fault, rather than silently
scoring it 0:

```
riskforge: unknown factor `skill_lvl`, did you mean `skill_level`?
riskforge: factor `motive`: score 42 is out of range, expected 0 to 9
riskforge: missing 2 factors: awareness, motive. Score them, or pass --allow-missing to treat them as 0
```

Every failure exits non-zero.

### Output formats

| Format | Written as | Good for |
|---|---|---|
| `text` | plain text | reading in the terminal |
| `json` | `.json` | pipelines, agents, diffing two ratings |
| `csv` | `.csv` | one flat row per threat, for a spreadsheet |
| `html` | `.html` | a self-contained report, light and dark, no scripts and no fetches |
| `md` | `.md` | a paste-ready threat table and the full derivation |
| `sarif` | `.sarif` | tools that already read static-analysis results |
| `sqlite` | `.db` | querying ratings over time. Needs `--output` |
| `sql` | `.sql` | loading into an existing database |
| `all` | every format | one run, one directory |

Writing every format for a whole threat table:

```bash
riskforge assess -i examples/threats.yaml -f all -o out/ --mkdir
```

Several formats at once need `--output` to name a directory. The `sqlite`
format always needs `--output`, since a database file cannot be streamed to
standard output.

---

### 🧪 Running Tests

```bash
make test
# or
cargo test
```

The suite includes a parity check that reproduces the worked example from the
OWASP Risk Rating template spreadsheet, asserting every derived number against
the value the spreadsheet shows. If the tool ever disagrees with the
methodology, that test fails.

---

### 🐳 Using Docker

Build image:

```bash
docker build -t riskforge .
```

Run:

```bash
docker run --rm riskforge --help
```

Pass arguments and a file:

```bash
docker run --rm -v "$PWD:/work" -w /work riskforge assess -i examples/threats.yaml
```

---

### ⚙️ Using the Makefile

**Build the tool**

```bash
make build
```

**Run with arguments**

```bash
make run ARGS="assess -i examples/threats.yaml"
```

**Lint, test and build**

```bash
make ci
```

**List every target**

```bash
make help
```

---

## 📐 Deviation from the OWASP wiki

The factor catalog is transcribed from the `Rating` sheet of the OWASP Risk
Rating template spreadsheet. On one factor, that sheet and the OWASP community
wiki disagree about where two options sit on the scale.

| Option | Template | Community wiki |
|---|---|---|
| Minimal critical data disclosed, extensive non-sensitive data disclosed | 4 | 6 |
| Extensive critical data disclosed | 5 | 7 |

`riskforge` follows the template, because the template is the artifact the
manual assessment process it replaces was already using. Scoring Loss of
confidentiality from the wiki text instead will shift a rating upward. The
divergence is recorded here, and in `src/model/catalog.rs`, so it stays a
conscious choice and not a transcription slip.

---

## 🤝 Contributing

Pull requests are welcome!

If proposing major changes, please open an issue first to discuss alignment with project goals.

### **Before submitting:**

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Run tests (`make ci`)
4. Commit changes (`git commit -m 'feat: Add amazing feature'`)
5. Push to branch (`git push origin feature/amazing-feature`)
6. Open Pull Request

A change to the methodology itself, meaning a factor, an option, a band
threshold or a matrix cell, needs a citation to the OWASP source it comes from
and a test that pins the new behavior.

---

## 📜 License

## Licensing

This project is **dual-licensed**.

### Open Source License (GPLv3)
riskforge is available under the **GNU General Public License v3.0 (GPLv3)**.  
Use of the software under GPLv3 is subject to the terms and obligations of that license, including its copyleft requirements. See LICENSE for details.

### Commercial License
For organizations that require **proprietary internal use** without GPLv3 obligations, a **Commercial License** is available.

The Commercial License allows:
- Internal organizational use
- Private modification
- Use by employees and contractors

The Commercial License does **not** allow:
- Redistribution or resale
- SaaS, hosted, or API offerings
- Embedding into third-party products or services
- Use of project branding without permission

Commercial licenses are governed by the **Commercial End User License Agreement (EULA)** located in `COMMERCIAL-EULA.md`.

### Choosing a License
- If you are building or distributing open-source software: **use GPLv3**
- If you are using the software internally and wish to keep modifications proprietary: **purchase a Commercial License**

For commercial licensing inquiries, contact:  
📧 gilles.infosec@gmail.com

### Methodology attribution
The OWASP Risk Rating Methodology is the work of Jeff Williams and the OWASP
community: https://owasp.org/www-community/OWASP_Risk_Rating_Methodology

---

**⚡ Built with Rust | 🛡️ Secured by Design | 🚀 Production Ready**
