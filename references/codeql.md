# CodeQL — optional deep scan

CodeQL is heavier than everything else in this skill: it needs a compiled query database built
from the target codebase before it can run any queries, it's slow on large projects, and the CLI
is a ~200MB download rather than a package-manager install. Treat it as an opt-in "deep" pass, not
part of the default scan — only build a CodeQL database when the user asks for a deeper scan or
explicitly names CodeQL.

## Setup

- Check: `command -v codeql`
- Install: no package manager install. Download the CLI bundle from the
  [CodeQL releases page](https://github.com/github/codeql-action/releases) (or
  `github.com/github/codeql-cli-binaries`) and add it to `PATH`. On a fresh machine:
  ```bash
  git clone https://github.com/github/codeql.git ~/codeql-repo   # query packs
  # download+unzip the CLI bundle for your platform from the releases page, then:
  export PATH="$PATH:/path/to/codeql-bundle/codeql"
  ```
- If the environment's network policy blocks `github.com`/`codeload.github.com`, CodeQL simply
  can't be installed there — say so plainly and stick to Semgrep + the language-specific tool
  instead of pretending the scan ran.

## Running a scan

Two-step process — build a database, then analyze it:

```bash
# 1. Build a database (language must be one CodeQL supports: cpp, csharp, go, java,
#    javascript, python, ruby, rust)
codeql database create <db-path> --language=<lang> --source-root=<target>

# 2. Run the standard security query suite against it
codeql database analyze <db-path> \
  codeql/<lang>-queries:codeql-suites/<lang>-security-and-quality.qls \
  --format=sarif-latest --output=<out>/codeql-<lang>.sarif
```

For compiled languages (Java, C/C++, C#, Go, Rust), database creation needs to actually build the
project — CodeQL traces the compiler. If the build fails, the database will be empty or missing;
don't report "no findings" in that case, report that the build (and therefore the scan) failed.
For interpreted languages (Python, JavaScript/TypeScript, Ruby), no build step is needed —
`database create` just indexes the source.

## Output

SARIF at `<out>/codeql-<lang>.sarif`, one file per language if the project is multi-language.
`generate_report.py` parses CodeQL SARIF the same way it parses Semgrep/Gosec/Brakeman SARIF, so
no separate report logic is needed — just make sure the file lands in the same `<out>/` directory
as everything else before running `generate_report.py`.

## When to actually use this

CodeQL's value is deep interprocedural taint tracking — it can trace user input through several
function calls to a dangerous sink in a way pattern-matching tools can't. That's worth the setup
cost for a pre-release security review or a codebase handling sensitive data. It's usually
overkill for a quick pre-commit check, where Semgrep + the language-specific linter already give
good coverage in a fraction of the time. If the user hasn't said "deep" or "thorough" or named
CodeQL specifically, don't default to it — mention it's available and ask.
