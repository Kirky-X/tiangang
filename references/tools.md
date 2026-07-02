# Security scanning tools by language

For each language, the table gives: the tool, how to check if it's already installed, how to
install it, the command used to run a scan, and where its findings end up (format + typical
path). `run_scan.py` uses this exact set of commands — if you add a tool here, wire it into
`run_scan.py` and `generate_report.py` too so the report parser understands its output.

Every scan command writes machine-readable output (SARIF or JSON) to a file rather than relying
on stdout, because `generate_report.py` parses files, not terminal text.

## Universal (all languages)

**Semgrep** — the first tool to run regardless of language. It has rulesets for nearly everything
and catches cross-language issues (hardcoded secrets, insecure configs, generic injection
patterns) that language-specific linters miss.

- Check: `command -v semgrep`
- Install: `uv tool install semgrep` (or `pipx install semgrep` if pipx is available and preferred)
- Scan: `semgrep scan --config auto --sarif --output <out>/semgrep.sarif <target>`
  - If offline or `--config auto` can't reach Semgrep's registry, fall back to
    `semgrep scan --config p/security-audit --config p/secrets --sarif --output <out>/semgrep.sarif <target>`
    which uses bundled rulesets and needs no network call after the packs are cached.
- Output: SARIF at `<out>/semgrep.sarif`

## Python — Bandit

- Detect: `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile`, or a majority of `.py` files
- Check: `command -v bandit`
- Install: `uv tool install bandit`
- Scan: `bandit -r <target> -f json -o <out>/bandit.json -x '*/tests/*,*/venv/*,*/.venv/*'`
- Output: JSON at `<out>/bandit.json`
- Catches: `eval`/`exec`, hardcoded passwords/keys, weak crypto (MD5/SHA1 for security), insecure
  deserialization (`pickle`, `yaml.load`), shell injection (`subprocess` with `shell=True`), SQL
  string formatting.

## Java — FindSecBugs (SpotBugs plugin)

- Detect: `pom.xml`, `build.gradle`/`build.gradle.kts`, or a majority of `.java` files
- Check: `command -v spotbugs` and presence of the FindSecBugs plugin jar
- Install: FindSecBugs ships as a SpotBugs plugin, not a standalone CLI. Two paths:
  1. **Maven project**: add the `spotbugs-maven-plugin` with FindSecBugs as a plugin dependency to
     `pom.xml`, then `mvn compile spotbugs:check`. Give the user the exact XML snippet if they
     don't already have it (see below) rather than silently editing their build file.
  2. **Standalone**: download SpotBugs CLI + the FindSecBugs plugin jar from GitHub releases and
     run `spotbugs -textui -pluginList findsecbugs-plugin.jar -sarif -output <out>/findsecbugs.sarif <compiled-classes-dir>`.
     Note this needs *compiled* `.class` files, not source — build the project first
     (`mvn compile` / `gradle compileJava`).
- Output: SARIF (with `-sarif`) or XML, at `<out>/findsecbugs.sarif`
- If the project can't be built in the current environment, say so explicitly rather than
  reporting a false "no findings" — an unbuildable project means the scan didn't run at all.

Maven pom.xml snippet to hand the user if they want it wired into their build:
```xml
<plugin>
  <groupId>com.github.spotbugs</groupId>
  <artifactId>spotbugs-maven-plugin</artifactId>
  <configuration>
    <plugins>
      <plugin>
        <groupId>com.h3xstream.findsecbugs</groupId>
        <artifactId>findsecbugs-plugin</artifactId>
        <version>LATEST</version>
      </plugin>
    </plugins>
  </configuration>
</plugin>
```

## Go — Gosec

- Detect: `go.mod`, or a majority of `.go` files
- Check: `command -v gosec`
- Install: `go install github.com/securego/gosec/v2/cmd/gosec@latest` (needs `$GOPATH/bin` on
  `PATH`, or run the binary with its full path)
- Scan: `gosec -fmt=sarif -out=<out>/gosec.sarif ./...` (run from the module root)
- Output: SARIF at `<out>/gosec.sarif`
- Catches: SQL injection via string concatenation, path traversal, weak random number generation
  for security purposes, hardcoded credentials, unsafe use of `os/exec`.

## C / C++ — Flawfinder + Cppcheck

Run both — they catch different things. Flawfinder is fast pattern-matching for dangerous
function calls; Cppcheck does deeper static analysis including some data-flow.

**Flawfinder**
- Check: `command -v flawfinder`
- Install: `uv tool install flawfinder`
- Scan: `flawfinder --sarif <target> > <out>/flawfinder.sarif`
- Output: SARIF (via `--sarif`) or CSV (`--csv`)
- Catches: `strcpy`/`gets`/`sprintf` and other buffer-overflow-prone calls, format string bugs.

**Cppcheck**
- Check: `command -v cppcheck`
- Install: `apt-get install -y cppcheck` (Debian/Ubuntu) — if apt isn't usable in the current
  environment, tell the user to install it via their system package manager or from source.
- Scan: `cppcheck --enable=warning,portability --xml --xml-version=2 <target> 2> <out>/cppcheck.xml`
  (Cppcheck writes XML to stderr, hence the redirect)
- Output: XML at `<out>/cppcheck.xml`
- Catches: buffer overruns, null pointer dereferences, use-after-free, uninitialized variables.

## Ruby — Brakeman

- Detect: `Gemfile` + a `app/` or `config/routes.rb` (Rails signature), or a majority of `.rb` files
- Check: `command -v brakeman`
- Install: `gem install brakeman`
- Scan: `brakeman -f sarif -o <out>/brakeman.sarif <target>`
- Output: SARIF at `<out>/brakeman.sarif`
- Catches: SQL injection, mass assignment, unsafe redirects, cross-site scripting, unsafe
  deserialization — all Rails-specific patterns, so Brakeman is only useful on Rails apps, not
  arbitrary Ruby scripts (for plain Ruby, lean more heavily on Semgrep).

## PHP — Psalm (security plugin)

- Detect: `composer.json`, or a majority of `.php` files
- Check: `command -v psalm`
- Install: `composer require --dev vimeo/psalm psalm/plugin-security` then
  `vendor/bin/psalm-plugin enable psalm/plugin-security` (needs a `composer.json` already in the
  project; if there isn't one, Psalm can't run — fall back to Semgrep's PHP ruleset instead)
- Scan: `psalm --taint-analysis --report=<out>/psalm.sarif`
- Output: SARIF (via `--report=*.sarif`) at `<out>/psalm.sarif`
- Catches (via taint analysis): SQL injection, XSS, command injection, unsafe file inclusion,
  tracked end-to-end from user input to dangerous sink.

## .NET (C#) — Security Code Scan

- Detect: `.csproj`, `.sln`, or a majority of `.cs` files
- Check: look for the analyzer already referenced in the `.csproj`, or `dotnet list package` for
  `SecurityCodeScan.VS2019`
- Install: `dotnet add package SecurityCodeScan.VS2019` in the project directory (it's a Roslyn
  analyzer, so it hooks into `dotnet build` rather than running as a separate CLI)
- Scan: `dotnet build /p:TreatWarningsAsErrors=false /clp:ErrorsOnly` and capture the analyzer
  warnings from build output, or use `dotnet build -warnaserror:SCS0001-SCS9999` to make specific
  rules fail the build. There's no native SARIF export — parse the build log for `SCSxxxx`
  warning codes and map them to `<out>/security-code-scan.json` yourself (see
  `generate_report.py`'s `parse_dotnet_build_log` for the expected shape).
- Catches: SQL injection, weak crypto/hashing, XXE, path traversal, insecure deserialization,
  hardcoded passwords, weak randomness for tokens.

## Rust — cargo-audit (dependency CVEs) + Miri (memory safety)

These check different things: cargo-audit is software composition analysis (known CVEs in your
dependency tree), Miri is an interpreter that catches undefined behavior in `unsafe` code. Run
both if the project has any `unsafe` blocks; cargo-audit alone is usually enough otherwise.

**cargo-audit**
- Check: `cargo audit --version`
- Install: `cargo install cargo-audit`
- Scan: `cargo audit --json > <out>/cargo-audit.json` (run from the directory with `Cargo.lock`)
- Output: JSON at `<out>/cargo-audit.json`
- Catches: dependencies with published RUSTSEC advisories — outdated or vulnerable crates, not
  bugs in the project's own code.

**Miri**
- Check: `cargo +nightly miri --version`
- Install: `rustup +nightly component add miri` (needs a nightly toolchain; Miri doesn't ship on
  stable)
- Scan: `cargo +nightly miri test 2> <out>/miri.log` (Miri runs your test suite under an
  interpreter that flags UB as it happens — it doesn't do static analysis, so it only catches
  what's exercised by your tests. More tests = more coverage.)
- Output: plain text log at `<out>/miri.log`, parsed for `error: Undefined Behavior` blocks
- Only worth running if the project has `unsafe` blocks — check `grep -r "unsafe" --include=*.rs`
  first and skip Miri with a note if there are none.

## Detection reference (used by `detect_languages.py`)

| Language | Strong signal (manifest file) | Weak signal (extension majority) |
|---|---|---|
| Python | `requirements.txt`, `pyproject.toml`, `setup.py`, `Pipfile` | `.py` |
| Java | `pom.xml`, `build.gradle`, `build.gradle.kts` | `.java` |
| Go | `go.mod` | `.go` |
| C/C++ | `CMakeLists.txt`, `Makefile` + `.c`/`.h`/`.cpp`/`.hpp` present | `.c`, `.h`, `.cpp`, `.hpp`, `.cc` |
| Ruby | `Gemfile` | `.rb` |
| PHP | `composer.json` | `.php` |
| .NET | `.csproj`, `.sln` | `.cs` |
| Rust | `Cargo.toml` | `.rs` |

A project can (and often does) contain more than one language — a Python backend with a small Go
service, for example. Scan every language detected above the noise threshold, not just the
dominant one.
