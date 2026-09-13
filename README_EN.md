# Tiangang — SAST Static Application Security Testing Suite

> A professional SAST suite for AI agents: auto-detects languages, orchestrates Semgrep + language-specific scanners + ecosystem-wide SCA/secret dual channels, and produces one unified human-readable report. **Run the tools, read their output, explain it** — never fake a security review by eyeballing code.

[![version](https://img.shields.io/github/v/tag/Kirky-X/tiangang?style=flat-square)](https://github.com/Kirky-X/tiangang/tags) [![license](https://img.shields.io/github/license/Kirky-X/tiangang?style=flat-square)](LICENSE) [![python](https://img.shields.io/badge/python-3.8%2B-blue?style=flat-square)](scripts/)

English | [中文](README.md)

## ✨ Features

- **Four-step workflow** (four scripts in `scripts/`, each step feeding the next): `detect_languages` → `install_tools` → `run_scan` → `generate_report`
- **General SAST**: Semgrep (language-agnostic, always runs, catches hardcoded secrets and other cross-language patterns); CodeQL (deep scan, opt-in, not in the default flow — see `references/codeql.md`)
- **SCA + secret dual channels** (run regardless of detected languages): Trivy for ecosystem-wide dependency CVEs (install chain pinned to v0.74.0 with SHA256 checksum verification; DB staleness is materialized into `trivy-version.json` so zero results are no longer misread as "safe"); Gitleaks + Trufflehog as an independent secret-scanning dual channel decoupled from Semgrep `p/secrets` — the parser layer keeps only rule id/detector name, credential raw text never reaches disk or reports (`redact.py` is defense in depth)
- **10 language-specific scanners**: Python→Bandit; Java→FindSecBugs; Go→Gosec; C/C++→Flawfinder+Cppcheck; Ruby→Brakeman; PHP→Psalm; .NET→Security Code Scan; Rust→cargo-audit+Miri; JS/TS→njsscan+retire.js+eslint-plugin-security; IaC→checkov+tfsec
- **AI code review (OCR, separately triggered)**: `--ocr` whole-file audit / `--ocr-delegate` git diff review, run independently after SAST to catch logic bugs, performance and maintainability concerns
- **Agent codebase anti-pattern rules**: `--agent-rules` loads `rules/agent-antipatterns.yml`, turning 12-factor-agents architecture violations (framework black-box instantiation, missing intent dispatch, graph orchestration without explicit loops, etc.) into SAST signals
- **Engineering features**: `--ci` mode (exit code reflects severity + GitHub Actions annotations), `--gate` threshold, `--diff-only` incremental scan (hash cache), `--format md|html|json`, `--trend` comparison, `--triage` LLM false-positive filtering prompts, three-layer finding deduplication with multi-tool confirmation marks
- **Explicit failure**: missing/failed/skipped tools are annotated with reasons in the report; a clean scan reflects tool coverage only and is never presented as "the code is secure"

## 📦 Installation

```bash
# Option 1: one-command deploy from this repository root
# (syncs to ~/.zcode/skills/ and ~/.claude/skills/, LF-normalized)
bash scripts/sync-skills.sh tiangang

# Option 2: manual copy into an agent skills directory
cp -r tiangang/ ~/.zcode/skills/tiangang/
# Option 3: Remote install (GitHub repo)
npx skills add Kirky-X/tiangang --agent claude-code -y
```

First-run requirements: Python 3.8+ only (scripts use the standard library). The scanners themselves (Semgrep/Bandit/Trivy, etc.) are installed on demand by `scripts/install_tools.sh` on first run; OCR needs `npm install -g @alibaba-group/open-code-review` plus an LLM API key (`AGNES_TOKEN` or `OCR_LLM_TOKEN`).

## 🚀 Quick Start

Prerequisite: the skill is deployed; run the four steps against the target directory (`{SKILL_DIR}` is the install directory).

```bash
# 1. Detect languages (skip if the user already stated them; pass --langs instead)
python3 {SKILL_DIR}/scripts/detect_languages.py <target-dir> --json

# 2. Install missing tools (command -v pre-check, safe to re-run)
bash {SKILL_DIR}/scripts/install_tools.sh python go    # or: all

# 3. Run the scan (Semgrep always + SCA/secret channels + language-specific tools)
python3 {SKILL_DIR}/scripts/run_scan.py <target-dir> --out results
#    CI gate: --ci --gate high; incremental: --diff-only --since HEAD~1; agent repos: --agent-rules

# 4. Generate the unified report (md|html|json|all)
python3 {SKILL_DIR}/scripts/generate_report.py results --out report.md
#    Trends: --trend; LLM triage prompts: --triage
```

Natural-language triggers (in a skills-aware agent session): "security audit this project", "scan for hardcoded secrets", "pre-release security check", "SAST on this agent codebase".

## ✅ Tests & Verification

Measured pytest run (2026-09-13, Python 3.12):

```text
$ python3 -m pytest tests -q
.......................................................................  [100%]
503 passed in 11.13s
```

Eleven test files covering: language-detection coverage, report generation, run_scan orchestration, SARIF output, redaction, OCR integration, secret dual-channel absorption (strix absorption), fix regressions, and optimization items.

Smoke tests: `detect_languages.py` correctly returns `{"languages": ["python"]}` on a sample directory containing `requirements.txt`; the Trivy installer in `install_tools.sh` verifies the downloaded binary's SHA256 checksum (`TRIVY_VERSION="0.74.0"`).

## 📁 Directory Structure

```text
tiangang/
├── SKILL.md                 # Entry: four-step workflow + OCR triggers + report-reading discipline
├── skill.json               # Metadata (v0.2.1, MIT)
├── references/
│   ├── tools.md             # Full language tool table: detection signals/install/scan commands/output formats
│   ├── codeql.md            # Standalone CodeQL deep-scan workflow (read only when opted in)
│   └── agent-semgrep-rules.md  # agent anti-pattern rule-set docs
├── rules/
│   └── agent-antipatterns.yml  # materialized Semgrep agent anti-pattern rules
├── scripts/
│   ├── detect_languages.py  # Step 1: manifest strong signals + extension-count weak signals
│   ├── install_tools.sh     # Step 2: installs only missing tools; Trivy pinned v0.74.0 + checksum
│   ├── run_scan.py          # Step 3: plugin-based orchestration (ToolPlugin), --ci/--gate/--diff-only/--ocr
│   ├── generate_report.py   # Step 4: multi-format parsing → unified report (--trend/--triage)
│   ├── sarif_report.py      # SARIF aggregation
│   └── redact.py            # generic regex redaction (defense in depth)
├── open-code-review/        # OCR integration reference
└── tests/                   # pytest suite (503 cases, 11 files)
```

## 🔮 Boundaries

- **Code quality/style/architecture review and PR review orchestration (`review pr`) belong to [diting](../diting/)**: this skill only does security scanning, not general code review
- **OCR never auto-triggers**: it runs as a standalone step after SAST only when the user explicitly asks for AI code review
- **CodeQL stays out of the default flow**: it requires building a query database and is markedly slower — run the standalone `references/codeql.md` flow only when the user asks for a "deep" audit or names CodeQL
- **A clean scan ≠ secure**: the report states the actual coverage (which tools, which languages) and honestly marks coverage gaps

## 📄 License & Attribution

MIT License (© 2026 Kirky-X). The SCA/secret channel design absorbs a source-aware SAST playbook (strix); the OCR layer is based on the open-source project [open-code-review](https://github.com/alibaba/open-code-review) (`@alibaba-group/open-code-review`), snapshotted in `open-code-review/`.
