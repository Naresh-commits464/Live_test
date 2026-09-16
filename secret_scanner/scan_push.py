```python
"""
GitHub Actions push-time secret scanner.

This scanner checks ONLY the content introduced by the current push.

Behavior:
    1. GitHub Actions provides:
         - GITHUB_EVENT_BEFORE = previous commit
         - GITHUB_SHA          = current commit
    2. We calculate the diff between those commits.
    3. Only added lines from changed files are scanned.
    4. Deleted/unchanged lines are ignored.
    5. If a secret is found, the GitHub Actions job exits with code 1.

Important:
    This is still a POST-PUSH CI check. It does not prevent the original
    `git push` from being accepted by GitHub.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from detectors import Finding, is_scannable, scan_text  # noqa: E402


REPO_ROOT = os.getcwd()


def _run_git_command(args: list[str]) -> str:
    """Run a git command and return stdout."""
    result = subprocess.run(
        args,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return result.stdout


def _get_commit_range() -> tuple[str, str]:
    """
    Get the before/after commits for the current GitHub push.

    GitHub Actions sets:
        GITHUB_EVENT_BEFORE = commit before the push
        GITHUB_SHA          = commit after the push
    """
    before = os.environ.get("GITHUB_EVENT_BEFORE", "").strip()
    after = os.environ.get("GITHUB_SHA", "").strip()

    if not after:
        raise RuntimeError(
            "GITHUB_SHA is not set. "
            "This scanner must run inside GitHub Actions."
        )

    # First push / special events may not have a usable "before" commit.
    # In that case, compare against the empty Git tree so that files
    # introduced by the initial commit are scanned.
    if not before or before == "0" * 40:
        before = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

    return before, after


def _get_changed_files(before: str, after: str) -> list[str]:
    """
    Return files changed by this push.

    Deleted files are included by git diff, but they will be skipped later
    because we only scan content that exists in the new commit.
    """
    output = _run_git_command(
        [
            "git",
            "diff",
            "--name-only",
            "--diff-filter=ACMR",
            before,
            after,
        ]
    )

    return [
        line.strip()
        for line in output.splitlines()
        if line.strip()
    ]


def _get_added_lines(
    before: str,
    after: str,
    rel_path: str,
) -> str:
    """
    Return only added lines from a file's diff.

    Example:
        - old password = "..."
        + api_key = "..."

    Only:
        + api_key = "..."
    is returned for scanning.
    """
    output = _run_git_command(
        [
            "git",
            "diff",
            "--unified=0",
            "--no-color",
            before,
            after,
            "--",
            rel_path,
        ]
    )

    added_lines: list[str] = []

    for line in output.splitlines():
        # Ignore file headers and hunk metadata.
        if line.startswith("+++"):
            continue

        if line.startswith("@@"):
            continue

        # Only scan additions.
        if line.startswith("+"):
            added_lines.append(line[1:])

    return "\n".join(added_lines)


def main() -> int:
    try:
        before, after = _get_commit_range()
    except RuntimeError as exc:
        print(f"Scanner configuration error: {exc}")
        return 2

    print("Starting push-diff secret scan...")
    print(f"Before commit: {before}")
    print(f"After commit:  {after}")

    try:
        changed_files = _get_changed_files(before, after)
    except subprocess.CalledProcessError as exc:
        print("Failed to determine changed files.")
        print(exc.stderr or exc.stdout)
        return 2

    if not changed_files:
        print("No changed files found.")
        print("No secrets detected.")
        return 0

    print(f"Changed files: {len(changed_files)}")

    all_findings: list[tuple[str, Finding]] = []

    for rel_path in changed_files:
        try:
            # Get the file size from the current checkout.
            # Deleted files are excluded by --diff-filter above.
            abs_path = Path(REPO_ROOT) / rel_path

            if not abs_path.is_file():
                continue

            size = abs_path.stat().st_size

            if not is_scannable(rel_path, size):
                continue

            # Scan only content introduced by this push.
            added_content = _get_added_lines(
                before,
                after,
                rel_path,
            )

            if not added_content:
                continue

            findings = scan_text(rel_path, added_content)

            for finding in findings:
                all_findings.append((rel_path, finding))

        except (OSError, UnicodeError):
            # Ignore files that cannot safely be inspected.
            continue
        except subprocess.CalledProcessError as exc:
            print(f"Warning: could not diff {rel_path}")
            print(exc.stderr or exc.stdout)
            continue

    if not all_findings:
        print("\nNo secrets detected in this push.")
        return 0

    high_count = sum(
        1
        for _, finding in all_findings
        if finding.severity == "high"
    )

    print(
        f"\n*** {len(all_findings)} finding(s), "
        f"{high_count} high severity ***\n"
    )

    for _, finding in all_findings:
        print(
            f"[{finding.severity.upper()}] "
            f"{finding.detector} - "
            f"{finding.file_path}:{finding.line_number}"
        )
        print(f"    {finding.line_preview}")

    return 1


if __name__ == "__main__":
    sys.exit(main())
```
