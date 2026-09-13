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
#
# Security: all commands are executed as argument lists (no eval, no shell
# interpolation of tool arguments). The trivy installer verifies the download
# against a SHA256 checksum before installing.

set -uo pipefail

TARGET="."
[[ "${1:-}" == "--target" ]] && TARGET="$2" && shift 2

LANGS=("$@")
if [[ ${#LANGS[@]} -eq 0 ]]; then
  echo "Usage: $0 <lang1> [lang2 ...] | all" >&2
  exit 1
fi
if [[ "${LANGS[0]}" == "all" ]]; then
  LANGS=(python java go c_cpp ruby php dotnet rust javascript iac)
fi

STATUS_OK=0
STATUS_FAIL=0

# check_or_install NAME CHECK_CMD_ARRAY... INSTALL_CMD_ARRAY...
#
# CHECK_CMD and INSTALL_CMD are bash arrays — executed directly without eval,
# preventing any shell injection via tool names or arguments.
check_or_install() {
  local name="$1"; shift
  local -a check_cmd=() install_cmd=()
  # Parse named array arguments: --check CMD... --install CMD...
  local section=""
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --check)  section=check;  shift; continue ;;
      --install) section=install; shift; continue ;;
    esac
    if [[ "$section" == "check" ]]; then
      check_cmd+=("$1")
    elif [[ "$section" == "install" ]]; then
      install_cmd+=("$1")
    fi
    shift
  done

  if "${check_cmd[@]}" >/dev/null 2>&1; then
    echo "OK        $name (already installed)"
    STATUS_OK=$((STATUS_OK + 1))
    return 0
  fi
  echo "Installing $name ..."
  # B6: mktemp creates an unpredictable log path (mitigates symlink attacks
  # where an attacker pre-creates /tmp/install_<name>.log as a symlink to a
  # system file that this script — when run as root — would overwrite).
  local logfile
  logfile=$(mktemp /tmp/install_${name// /_}.XXXXXX.log)
  if "${install_cmd[@]}" >"$logfile" 2>&1; then
    echo "INSTALLED $name"
    STATUS_OK=$((STATUS_OK + 1))
  else
    echo "FAILED    $name — see $logfile (check network access to the required registry, or install manually per references/tools.md)"
    STATUS_FAIL=$((STATUS_FAIL + 1))
  fi
}

# install_trivy_with_checksum
#
# Downloads the trivy binary and its SHA256 checksum from a release URL
# pinned to an exact tag, and verifies the binary against the checksum
# BEFORE installing — prevents a MITM on the download from injecting a
# malicious binary. The old `curl | sh` pattern would execute arbitrary
# code if the download was intercepted; that fallback was removed
# deliberately — a failed download must fail loudly, never silently
# degrade into piping an installer script into a shell.
#
# Pinned version (not the moving "latest" alias): pairing a latest-release
# redirect with a hardcoded filename is self-contradictory — the filename
# stops resolving the moment upstream ships a newer release, so the request
# 404s forever.
# NOTE: the previously used v0.58.0 release assets are no longer published
# upstream; bump TRIVY_VERSION when upgrading (verify the tag still has
# trivy_<version>_checksums.txt on the GitHub release page first).
TRIVY_VERSION="0.74.0"

install_trivy_with_checksum() {
  local tmpdir
  tmpdir=$(mktemp -d /tmp/trivy-install.XXXXXX)
  trap 'rm -rf "$tmpdir"' RETURN

  # goreleaser asset naming (see the release's checksums.txt): OS is
  # capitalized ("Linux"/"macOS") and arch is 64bit / ARM64 / ARM (32-bit).
  local arch
  arch=$(uname -m)
  case "$arch" in
    x86_64)  arch="64bit" ;;
    aarch64) arch="ARM64" ;;
    armv7*|armv6*) arch="ARM" ;;
    *) echo "unsupported architecture: $arch — install trivy manually per references/tools.md" >&2; return 1 ;;
  esac
  local os
  case "$(uname -s)" in
    Linux)  os="Linux" ;;
    Darwin) os="macOS" ;;
    *) echo "unsupported OS: $(uname -s) — install trivy manually per references/tools.md" >&2; return 1 ;;
  esac
  local base="trivy_${TRIVY_VERSION}_${os}-${arch}"
  local release_url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"

  if ! curl -sfL -o "$tmpdir/${base}.tar.gz" "${release_url}/${base}.tar.gz" 2>/dev/null; then
    echo "FAILED to download ${release_url}/${base}.tar.gz" >&2
    echo "No pipe-to-shell fallback: install trivy manually per references/tools.md" >&2
    echo "(e.g. 'apt-get install trivy', 'brew install trivy', or download the release asset yourself)." >&2
    return 1
  fi
  if ! curl -sfL -o "$tmpdir/checksums.txt" "${release_url}/trivy_${TRIVY_VERSION}_checksums.txt" 2>/dev/null; then
    echo "could not download trivy_${TRIVY_VERSION}_checksums.txt — refusing to install without verification" >&2
    echo "Install trivy manually per references/tools.md." >&2
    return 1
  fi

  # Verify SHA256 before extracting. The checksum line names the asset as
  # published, so the download must live under that exact name for
  # sha256sum -c to find it.
  if ! (cd "$tmpdir" && grep -F "${base}.tar.gz" checksums.txt | sha256sum -c --status 2>/dev/null); then
    echo "SHA256 verification failed — binary may be tampered; not installing" >&2
    return 1
  fi

  tar -xzf "$tmpdir/${base}.tar.gz" -C "$tmpdir"
  if [[ -w /usr/local/bin ]]; then
    mv "$tmpdir/trivy" /usr/local/bin/trivy
  else
    mkdir -p "$HOME/.local/bin"
    mv "$tmpdir/trivy" "$HOME/.local/bin/trivy"
  fi
}

# Semgrep is universal — always check it once regardless of which languages were requested.
check_or_install "semgrep" \
  --check command -v semgrep \
  --install uv tool install semgrep

# defusedxml — preferred XML parser for generate_report.py (XXE-safe).
# Install alongside semgrep so the report generator uses it by default.
# Install channel must match the check channel: generate_report.py imports
# defusedxml with `python3 -c "import defusedxml"`, so it must be installed
# into python3's module search path (`pip install --user`), NOT as a uv tool
# (uv tool install puts it in an isolated venv the python3 check never sees,
# which made this step reinstall on every run and left the report generator
# on the stdlib fallback).
check_or_install "defusedxml" \
  --check python3 -c "import defusedxml" \
  --install python3 -m pip install --user defusedxml

# Universal SCA + secret channel (absorbed from strix's source-aware SAST
# playbook). These run on every scan regardless of detected language —
# trivy covers all ecosystems via lockfile scanning, gitleaks + trufflehog
# form an independent secret-detection channel so hardcoded credentials
# don't depend solely on semgrep's p/secrets ruleset.
check_or_install "trivy" \
  --check command -v trivy \
  --install install_trivy_with_checksum
check_or_install "gitleaks" \
  --check command -v gitleaks \
  --install go install github.com/gitleaks/gitleaks/v8@latest
check_or_install "trufflehog" \
  --check command -v trufflehog \
  --install go install github.com/trufflesecurity/trufflehog/v3@latest

# AI-powered code review — opt-in via --ocr / --ocr-delegate in run_scan.py.
# OCR is a Go-based CLI tool distributed via npm. Requires a configured LLM
# API endpoint for scan/review modes; delegate mode needs no LLM on OCR side.
check_or_install "ocr" \
  --check command -v ocr \
  --install npm install -g @alibaba-group/open-code-review

for lang in "${LANGS[@]}"; do
  case "$lang" in
    python)
      check_or_install "bandit" \
        --check command -v bandit \
        --install uv tool install bandit
      ;;
    java)
      echo "SKIP      findsecbugs (needs project-specific Maven/Gradle wiring or compiled classes — see references/tools.md, no generic install)"
      ;;
    go)
      check_or_install "gosec" \
        --check command -v gosec \
        --install go install github.com/securego/gosec/v2/cmd/gosec@latest
      ;;
    c_cpp)
      check_or_install "flawfinder" \
        --check command -v flawfinder \
        --install uv tool install flawfinder
      check_or_install "cppcheck" \
        --check command -v cppcheck \
        --install apt-get install -y cppcheck
      ;;
    ruby)
      check_or_install "brakeman" \
        --check command -v brakeman \
        --install gem install brakeman
      ;;
    php)
      if [[ -f "$TARGET/composer.json" ]]; then
        check_or_install "psalm" \
          --check bash -c "command -v psalm || test -x vendor/bin/psalm" \
          --install composer require --dev vimeo/psalm psalm/plugin-security
      else
        echo "SKIP      psalm (no composer.json in project root — falling back to semgrep's PHP ruleset)"
      fi
      ;;
    dotnet)
      echo "SKIP      security-code-scan (Roslyn analyzer — add via 'dotnet add package SecurityCodeScan.VS2019' inside the project, see references/tools.md)"
      ;;
    rust)
      check_or_install "cargo-audit" \
        --check cargo audit --version \
        --install cargo install cargo-audit
      if grep -rq "unsafe" --include='*.rs' "$TARGET" 2>/dev/null; then
        check_or_install "miri" \
          --check cargo +nightly miri --version \
          --install rustup +nightly component add miri
      else
        echo "SKIP      miri (no 'unsafe' blocks found — not worth the nightly toolchain setup)"
      fi
      ;;
    javascript)
      # njsscan is a standalone Python CLI (non-intrusive) — auto-install.
      check_or_install "njsscan" \
        --check command -v njsscan \
        --install uv tool install njsscan
      # retire.js: scans for known-CVE versions of frontend/Node libraries
      # (jquery, lodash, …) that ship in the project. Complements trivy's
      # npm lockfile scan by catching vendored/minified copies. Absorbed
      # from strix's source-aware SAST playbook.
      check_or_install "retire" \
        --check command -v retire \
        --install npm install -g retire
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
    iac)
      # IaC security scanners — Terraform/Kubernetes/Docker/CloudFormation
      check_or_install "checkov" \
        --check command -v checkov \
        --install uv tool install checkov
      check_or_install "tfsec" \
        --check command -v tfsec \
        --install go install github.com/aquasecurity/tfsec/cmd/tfsec@latest
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
