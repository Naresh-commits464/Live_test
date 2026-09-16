"""Runner for the GitHub Actions workflow: scans every tracked file in the
checked-out repo and fails the job (non-zero exit) if any secret is found.

This runs post-push, same as the CodeCommit Lambda -- it cannot stop the
`git push` itself, but a failing check shows up as a red X on the commit /
PR immediately, and can be turned into a required status check in branch
protection settings to block merges.
"""
from __future__ import annotations

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(__file__))
from detectors import Finding, is_scannable, scan_text  # noqa: E402

REPO_ROOT = os.getcwd()


def _tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files"], cwd=REPO_ROOT, capture_output=True, text=True, check=True
    )
    return [line for line in result.stdout.splitlines() if line.strip()]


def main() -> int:
    all_findings: list[tuple[str, Finding]] = []

    for rel_path in _tracked_files():
        abs_path = os.path.join(REPO_ROOT, rel_path)
        if not os.path.isfile(abs_path):
            continue
        size = os.path.getsize(abs_path)
        if not is_scannable(rel_path, size):
            continue
        try:
            with open(abs_path, "r", encoding="utf-8") as fh:
                content = fh.read()
        except (UnicodeDecodeError, OSError):
            continue

        for finding in scan_text(rel_path, content):
            all_findings.append((rel_path, finding))

    if not all_findings:
        print("No secrets detected.")
        return 0

    high_count = sum(1 for _, f in all_findings if f.severity == "high")
    print(f"\n*** {len(all_findings)} finding(s), {high_count} high severity ***\n")
    for _, f in all_findings:
        print(f"[{f.severity.upper()}] {f.detector} - {f.file_path}:{f.line_number}")
        print(f"    {f.line_preview}")

    return 1


if __name__ == "__main__":
    sys.exit(main())
