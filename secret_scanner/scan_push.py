"""
GitHub Actions push-time secret scanner.

This scanner checks ONLY content introduced by the current push.

Behavior:
    1. GitHub Actions provides the current commit through GITHUB_SHA.
    2. The push event JSON provides the previous commit through
       GITHUB_EVENT_PATH -> "before".
    3. The scanner calculates the Git diff between those commits.
    4. ONLY added lines are scanned.
    5. Deleted and unchanged lines are ignored.
    6. If a secret is detected, the job exits with code 1.
    7. Every finding includes a direct GitHub URL to the exact file/line
       in the exact commit that triggered the finding.

Important:
    This is a POST-PUSH CI check. It does not prevent the original
    `git push` from being accepted by GitHub.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))

from detectors import Finding, is_scannable, scan_text  # noqa: E402


REPO_ROOT = os.getcwd()

# GitHub Actions automatically provides this as:
#   OWNER/REPOSITORY
GITHUB_REPOSITORY = os.environ.get("GITHUB_REPOSITORY", "").strip()


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
    Get the before/after commit SHAs for the current GitHub push.

    Current commit:
        GITHUB_SHA

    Previous commit:
        GITHUB_EVENT_PATH -> event["before"]

    For an initial push, GitHub may provide an all-zero "before" SHA.
    In that case we use Git's empty-tree SHA.
    """

    after = os.environ.get("GITHUB_SHA", "").strip()

    if not after:
        raise RuntimeError(
            "GITHUB_SHA is not set. "
            "This scanner must run inside GitHub Actions."
        )

    event_path = os.environ.get("GITHUB_EVENT_PATH", "").strip()

    before = ""

    if event_path:
        try:
            with open(event_path, "r", encoding="utf-8") as fh:
                event = json.load(fh)

            before = str(event.get("before", "")).strip()

        except (OSError, json.JSONDecodeError):
            before = ""

    # Initial push / branch creation.
    #
    # Git's empty tree object lets us diff:
    #
    #     empty tree -> first commit
    #
    # which means all files introduced by the first push are scanned.
    if not before or before == "0" * 40:
        before = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

    return before, after


def _ensure_commit_available(commit_sha: str) -> None:
    """
    Ensure the requested commit exists in the local checkout.

    This normally works when actions/checkout uses:

        fetch-depth: 0
    """
    result = subprocess.run(
        [
            "git",
            "cat-file",
            "-e",
            f"{commit_sha}^{{commit}}",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise RuntimeError(
            f"Commit {commit_sha} is not available in the GitHub Actions "
            "checkout. Make sure actions/checkout uses fetch-depth: 0."
        )


def _get_changed_files(before: str, after: str) -> list[str]:
    """
    Return files changed by the current push.

    We scan:
        A = Added
        C = Copied
        M = Modified
        R = Renamed

    Deleted files are excluded because there is no current file content
    to scan.
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
    Return ONLY the lines added by this push.

    Example:

        - password = "old-value"
        + api_key = "new-value"

    Only the following is returned:

        api_key = "new-value"

    This prevents old, unchanged secrets from being reported repeatedly
    on unrelated later pushes.
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

        # Git diff file header
        if line.startswith("+++"):
            continue

        # Hunk metadata
        if line.startswith("@@"):
            continue

        # Only added lines
        if line.startswith("+"):
            added_lines.append(line[1:])

    return "\n".join(added_lines)


def _github_file_url(
    commit_sha: str,
    rel_path: str,
    line_number: int,
) -> str:
    """
    Build a direct GitHub URL to the exact file and line in the
    exact commit that was scanned.
    """

    if not GITHUB_REPOSITORY:
        return ""

    return (
        f"https://github.com/{GITHUB_REPOSITORY}"
        f"/blob/{commit_sha}/{rel_path}"
        f"#L{line_number}"
    )


def main() -> int:
    # ---------------------------------------------------------------
    # 1. Determine the push commit range
    # ---------------------------------------------------------------
    try:
        before, after = _get_commit_range()

        # Make sure the previous commit exists locally.
        _ensure_commit_available(before)

    except RuntimeError as exc:
        print(f"Scanner configuration error: {exc}")
        return 2

    print("Starting push-diff secret scan...")
    print(f"Before commit: {before}")
    print(f"After commit:  {after}")

    # ---------------------------------------------------------------
    # 2. Find files changed by this push
    # ---------------------------------------------------------------
    try:
        changed_files = _get_changed_files(before, after)

    except subprocess.CalledProcessError as exc:
        print("Failed to determine changed files.")

        if exc.stderr:
            print(exc.stderr)

        return 2

    if not changed_files:
        print("No changed files found.")
        print("No secrets detected in this push.")
        return 0

    print(f"Changed files: {len(changed_files)}")

    # ---------------------------------------------------------------
    # 3. Scan only newly-added content
    # ---------------------------------------------------------------
    all_findings: list[Finding] = []

    for rel_path in changed_files:
        try:
            abs_path = Path(REPO_ROOT) / rel_path

            # File may have disappeared from the working tree even though
            # Git reported it as changed.
            if not abs_path.is_file():
                continue

            size = abs_path.stat().st_size

            # Reuse existing scanner file filters.
            if not is_scannable(rel_path, size):
                continue

            # IMPORTANT:
            # Scan only content added by this push.
            added_content = _get_added_lines(
                before,
                after,
                rel_path,
            )

            if not added_content:
                continue

            findings = scan_text(
                rel_path,
                added_content,
            )

            all_findings.extend(findings)

        except (OSError, UnicodeError) as exc:
            print(
                f"Warning: could not inspect {rel_path}: {exc}"
            )
            continue

        except subprocess.CalledProcessError as exc:
            print(f"Warning: could not diff {rel_path}")

            if exc.stderr:
                print(exc.stderr)

            continue

    # ---------------------------------------------------------------
    # 4. No findings
    # ---------------------------------------------------------------
    if not all_findings:
        print("\nNo secrets detected in this push.")
        return 0

    # ---------------------------------------------------------------
    # 5. Findings
    # ---------------------------------------------------------------
    high_count = sum(
        1
        for finding in all_findings
        if finding.severity == "high"
    )

    print(
        f"\n*** {len(all_findings)} finding(s), "
        f"{high_count} high severity ***\n"
    )

    for finding in all_findings:

        print(
            f"[{finding.severity.upper()}] "
            f"{finding.detector} - "
            f"{finding.file_path}:{finding.line_number}"
        )

        # Detector already returns a redacted preview.
        print(
            f"    {finding.line_preview}"
        )

        # Direct link to exact commit/file/line.
        github_url = _github_file_url(
            after,
            finding.file_path,
            finding.line_number,
        )

        if github_url:
            print(
                f"    View in GitHub: {github_url}"
            )

        print()

    # Non-zero exit causes GitHub Actions to mark the job as failed.
    return 1


if __name__ == "__main__":
    sys.exit(main())
