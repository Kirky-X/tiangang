#!/usr/bin/env bash
# Check which security scanning tools are already available, and install the
# missing ones for the given languages. Idempotent: skips anything already
# on PATH. Mirrors the install commands documented in references/tools.md —
# keep the two in sync if you change one.
#
# Usage: ./install_tools.sh [--target <dir>] <lang1> [lang2 ...]
#        ./install_tools.sh [--target <dir>] all
#
# Prints a per-tool OK / INSTALLED / FAILED status line to stdout, and exits
# non-zero only if a language was requested but none of its tools could be
# checked or installed. Individual tool failures (e.g. no network access to
# a package registry) are reported but don't stop the others from being
# attempted — some tools working is better than aborting entirely.

set -uo pipefail

TARGET="."
[[ "${1:-}" == "--target" ]] && TARGET="$2" && shift 2

LANGS=("$@")
if [[ ${#LANGS[@]} -eq 0 ]]; then
  echo "Usage: $0 <lang1> [lang2 ...] | all" >&2
  exit 1
fi
if [[ "${LANGS[0]}" == "all" ]]; then
  LANGS=(python java go c_cpp ruby php dotnet rust javascript)
fi

STATUS_OK=0
STATUS_FAIL=0

check_or_install() {
  local name="$1" check_cmd="$2" install_cmd="$3"
  if eval "$check_cmd" >/dev/null 2>&1; then
    echo "OK        $name (already installed)"
    STATUS_OK=$((STATUS_OK + 1))
    return 0
  fi
  echo "Installing $name ..."
  # B6: mktemp creates an unpredictable log path (mitigates symlink attacks
  # where an attacker pre-creates /tmp/install_<name>.log as a symlink to a
  # system file that this script — when run as root — would overwrite).
  # mktemp failure (e.g. /tmp full) leaves logfile empty, the subsequent
  # redirection fails, and the `if` branch reports FAILED (no silent success).
  local logfile
  logfile=$(mktemp /tmp/install_${name// /_}.XXXXXX.log)
  if eval "$install_cmd" >"$logfile" 2>&1; then
    echo "INSTALLED $name"
    STATUS_OK=$((STATUS_OK + 1))
  else
    echo "FAILED    $name — see $logfile (check network access to the required registry, or install manually per references/tools.md)"
    STATUS_FAIL=$((STATUS_FAIL + 1))
  fi
}

# Semgrep is universal — always check it once regardless of which languages were requested.
check_or_install "semgrep" "command -v semgrep" "uv tool install semgrep"

# Universal SCA + secret channel (absorbed from strix's source-aware SAST
# playbook). These run on every scan regardless of detected language —
# trivy covers all ecosystems via lockfile scanning, gitleaks + trufflehog
# form an independent secret-detection channel so hardcoded credentials
# don't depend solely on semgrep's p/secrets ruleset.
check_or_install "trivy" "command -v trivy" "curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
check_or_install "gitleaks" "command -v gitleaks" "go install github.com/gitleaks/gitleaks/v8@latest"
check_or_install "trufflehog" "command -v trufflehog" "go install github.com/trufflesecurity/trufflehog/v3@latest"

for lang in "${LANGS[@]}"; do
  case "$lang" in
    python)
      check_or_install "bandit" "command -v bandit" "uv tool install bandit"
      ;;
    java)
      echo "SKIP      findsecbugs (needs project-specific Maven/Gradle wiring or compiled classes — see references/tools.md, no generic install)"
      ;;
    go)
      check_or_install "gosec" "command -v gosec" "go install github.com/securego/gosec/v2/cmd/gosec@latest"
      ;;
    c_cpp)
      check_or_install "flawfinder" "command -v flawfinder" "uv tool install flawfinder"
      check_or_install "cppcheck" "command -v cppcheck" "apt-get install -y cppcheck"
      ;;
    ruby)
      check_or_install "brakeman" "command -v brakeman" "gem install brakeman"
      ;;
    php)
      if [[ -f "$TARGET/composer.json" ]]; then
        check_or_install "psalm" "command -v psalm || [[ -x vendor/bin/psalm ]]" "composer require --dev vimeo/psalm psalm/plugin-security"
      else
        echo "SKIP      psalm (no composer.json in project root — falling back to semgrep's PHP ruleset)"
      fi
      ;;
    dotnet)
      echo "SKIP      security-code-scan (Roslyn analyzer — add via 'dotnet add package SecurityCodeScan.VS2019' inside the project, see references/tools.md)"
      ;;
    rust)
      check_or_install "cargo-audit" "cargo audit --version" "cargo install cargo-audit"
      if grep -rq "unsafe" --include='*.rs' "$TARGET" 2>/dev/null; then
        check_or_install "miri" "cargo +nightly miri --version" "rustup +nightly component add miri"
      else
        echo "SKIP      miri (no 'unsafe' blocks found — not worth the nightly toolchain setup)"
      fi
      ;;
    javascript)
      # njsscan is a standalone Python CLI (non-intrusive) — auto-install.
      check_or_install "njsscan" "command -v njsscan" "uv tool install njsscan"
      # retire.js: scans for known-CVE versions of frontend/Node libraries
      # (jquery, lodash, …) that ship in the project. Complements trivy's
      # npm lockfile scan by catching vendored/minified copies. Absorbed
      # from strix's source-aware SAST playbook.
      check_or_install "retire" "command -v retire" "npm install -g retire"
      # eslint-plugin-security requires project-local config (eslint.config.js
      # + the plugin) and would otherwise modify the user's package.json.
      # Mirror the findsecbugs/security-code-scan pattern: detect a wired
      # setup, else print the wiring step rather than silently skipping.
      if [[ -f "$TARGET/package.json" ]] && { [[ -f "$TARGET/eslint.config.js" ]] || [[ -f "$TARGET/eslint.config.mjs" ]] || [[ -f "$TARGET/.eslintrc.js" ]] || [[ -f "$TARGET/.eslintrc.json" ]]; }; then
        if grep -rqE "eslint-plugin-security|plugin:security" "$TARGET/eslint.config.js" "$TARGET/eslint.config.mjs" "$TARGET/.eslintrc.js" "$TARGET/.eslintrc.json" 2>/dev/null; then
          echo "OK        eslint-plugin-security (configured in project)"
        else
          echo "SKIP      eslint-plugin-security (eslint config found but plugin not wired — run: npm install --save-dev eslint eslint-plugin-security, then add 'security' to your eslint config extends/plugins)"
        fi
      else
        echo "SKIP      eslint-plugin-security (no eslint config + package.json in $TARGET — add via 'npm install --save-dev eslint eslint-plugin-security', see references/tools.md)"
      fi
      ;;
    *)
      echo "UNKNOWN   language '$lang' — no tool mapping, see references/tools.md"
      ;;
  esac
done

echo ""
echo "Summary: $STATUS_OK ready, $STATUS_FAIL failed"
if [[ $STATUS_FAIL -gt 0 && $STATUS_OK -eq 0 ]]; then
  exit 1
fi
exit 0
