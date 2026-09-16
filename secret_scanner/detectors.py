"""Secret detection engine: regex signatures + Shannon-entropy heuristics.

Identical logic to lambda/scanner/detectors.py in the AWS CodeCommit version
of this project -- copied here so it can run standalone inside a GitHub
Actions workflow with no AWS dependency.

Design notes:
- Signature detectors are checked first (cheap, high precision, easy to attribute
  to a provider). Entropy detection runs only on lines that also contain a
  credential-flavored keyword, to keep the false-positive rate manageable
  without a verification/liveness step.
- Every finding carries a `redacted` preview instead of the raw secret so
  workflow logs never persist the real value.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

SUPPRESS_MARKER = re.compile(r"#\s*secret-scanner:\s*allow", re.IGNORECASE)

CONTEXT_KEYWORDS = re.compile(
    r"(api[_-]?key|secret|token|password|passwd|pwd|credential|access[_-]?key|"
    r"private[_-]?key|auth|bearer)",
    re.IGNORECASE,
)

BINARY_OR_NOISY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".jar", ".class", ".so", ".dll", ".exe", ".woff", ".woff2", ".ttf",
    ".lock", ".min.js", ".map",
}

MAX_SCANNABLE_BYTES = 100 * 1024


@dataclass
class Finding:
    detector: str
    severity: str  # "high" | "medium"
    file_path: str
    line_number: int
    redacted: str
    line_preview: str

    def to_dict(self) -> dict:
        return {
            "detector": self.detector,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "redacted": self.redacted,
            "line_preview": self.line_preview,
        }


@dataclass
class _Signature:
    name: str
    pattern: re.Pattern
    severity: str = "high"


SIGNATURES: list[_Signature] = [
    _Signature("aws_access_key_id", re.compile(r"\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b")),
    _Signature("aws_secret_access_key", re.compile(
        r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?"
    )),
    _Signature("private_key_block", re.compile(
        r"-----BEGIN\s*(RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY-----"
    )),
    _Signature("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    _Signature("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{60,}\b")),
    _Signature("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    _Signature("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]{20,}")),
    _Signature("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    _Signature("stripe_key", re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{20,}\b")),
    _Signature("twilio_key", re.compile(r"\bSK[0-9a-fA-F]{32}\b")),
    _Signature("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), severity="medium"),
    _Signature("generic_api_key_assignment", re.compile(
        r"(?i)\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"][A-Za-z0-9_\-/+=]{16,}['\"]"
    ), severity="medium"),
]

_ENTROPY_CANDIDATE = re.compile(r"['\"]([A-Za-z0-9+/_=\-]{20,})['\"]")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def is_scannable(file_path: str, size_bytes: int) -> bool:
    if size_bytes > MAX_SCANNABLE_BYTES:
        return False
    lower = file_path.lower()
    return not any(lower.endswith(ext) for ext in BINARY_OR_NOISY_EXTENSIONS)


def scan_text(file_path: str, content: str, entropy_threshold: float = 4.3) -> list[Finding]:
    findings: list[Finding] = []

    for line_number, line in enumerate(content.splitlines(), start=1):
        if SUPPRESS_MARKER.search(line):
            continue

        for sig in SIGNATURES:
            match = sig.pattern.search(line)
            if match:
                findings.append(Finding(
                    detector=sig.name,
                    severity=sig.severity,
                    file_path=file_path,
                    line_number=line_number,
                    redacted=_redact(match.group(0)),
                    line_preview=_redact_line(line, match.group(0)),
                ))

        if CONTEXT_KEYWORDS.search(line):
            for candidate in _ENTROPY_CANDIDATE.findall(line):
                entropy = _shannon_entropy(candidate)
                if entropy >= entropy_threshold:
                    findings.append(Finding(
                        detector="high_entropy_string",
                        severity="medium",
                        file_path=file_path,
                        line_number=line_number,
                        redacted=_redact(candidate),
                        line_preview=_redact_line(line, candidate),
                    ))

    return findings


def _redact_line(line: str, secret: str) -> str:
    redacted_line = line.replace(secret, _redact(secret))
    return redacted_line.strip()[:200]
