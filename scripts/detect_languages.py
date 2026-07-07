#!/usr/bin/env python3
"""
Detect which languages a codebase uses, so the orchestrator knows which
security tools to run. Combines strong signals (manifest files) with weak
signals (file extension counts) — see references/tools.md for the table
this mirrors.

Usage:
    python3 detect_languages.py <target-dir> [--json]

Exits with the detected languages printed one per line (or as JSON with
--json), most-prevalent first. A project can contain more than one language;
this script reports all of them above a small noise threshold rather than
just the dominant one.
"""

import argparse
import json
import os
import sys

# extension -> language
EXT_MAP = {
    ".py": "python",
    ".java": "java",
    ".go": "go",
    ".c": "c_cpp",
    ".h": "c_cpp",
    ".cpp": "c_cpp",
    ".hpp": "c_cpp",
    ".cc": "c_cpp",
    ".cxx": "c_cpp",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "dotnet",
    ".rs": "rust",
    # JavaScript / TypeScript share the "javascript" language bucket and the
    # same scanner set (njsscan + eslint-plugin-security). TypeScript's type
    # system does not change which SAST tools apply, so both go to one language.
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "javascript",
    ".tsx": "javascript",
    ".mts": "javascript",
    ".cts": "javascript",
}

# manifest file (relative to a directory) -> language, treated as a strong
# signal — one hit is enough to include the language regardless of file count
MANIFEST_MAP = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "setup.py": "python",
    "Pipfile": "python",
    "pom.xml": "java",
    "build.gradle": "java",
    "build.gradle.kts": "java",
    "go.mod": "go",
    "Gemfile": "ruby",
    "composer.json": "php",
    "Cargo.toml": "rust",
    # JS/TS manifest files — package.json covers Node/JS/TS; tsconfig.json is a
    # strong TypeScript signal even when .ts file count is low.
    "package.json": "javascript",
    "package-lock.json": "javascript",
    "tsconfig.json": "javascript",
}

# directories that would otherwise pollute the extension counts with
# vendored / generated code that isn't the user's own
SKIP_DIRS = {
    ".git",
    "node_modules",
    "vendor",
    "venv",
    ".venv",
    "__pycache__",
    "target",
    "dist",
    "build",
    ".tox",
    "bin",
    "obj",
}

# extension-count threshold below which we treat a language as noise (e.g.
# a single stray .py script in an otherwise all-Go repo isn't worth scanning)
MIN_FILE_COUNT = 3


def detect(target: str):
    strong = set()
    ext_counts = {}

    for root, dirs, files in os.walk(target):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
        for fname in files:
            if fname in MANIFEST_MAP:
                strong.add(MANIFEST_MAP[fname])
            ext = os.path.splitext(fname)[1]
            if ext in EXT_MAP:
                lang = EXT_MAP[ext]
                ext_counts[lang] = ext_counts.get(lang, 0) + 1

    weak = {lang for lang, count in ext_counts.items() if count >= MIN_FILE_COUNT}

    detected = strong | weak
    # sort by manifest presence first (stronger signal), then file count
    ordered = sorted(
        detected,
        key=lambda lang: (lang not in strong, -ext_counts.get(lang, 0)),
    )
    return ordered, ext_counts, sorted(strong)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if not os.path.isdir(args.target):
        print(f"error: {args.target} is not a directory", file=sys.stderr)
        sys.exit(1)

    ordered, ext_counts, strong = detect(args.target)

    if not ordered:
        if args.json:
            print(
                json.dumps({"languages": [], "file_counts": {}, "manifest_matches": []})
            )
        else:
            print(
                "No supported language detected. Falling back to semgrep (language-agnostic) only."
            )
        return

    if args.json:
        print(
            json.dumps(
                {
                    "languages": ordered,
                    "file_counts": ext_counts,
                    "manifest_matches": strong,
                },
                indent=2,
            )
        )
    else:
        for lang in ordered:
            marker = (
                " (manifest file found)"
                if lang in strong
                else f" ({ext_counts.get(lang, 0)} files)"
            )
            print(f"{lang}{marker}")


if __name__ == "__main__":
    main()
