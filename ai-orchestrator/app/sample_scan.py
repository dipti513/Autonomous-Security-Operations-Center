from __future__ import annotations

from pathlib import Path
from uuid import uuid4

from .models import VulnerabilityFinding


SCAN_PATTERNS = [
    (
        "hardcoded-secret",
        "HIGH",
        "Password or secret-like literal in code",
        "Move the credential to an environment variable or secret manager.",
        ("password =", "secret =", "api_key ="),
    ),
    (
        "unsafe-sql-string",
        "CRITICAL",
        "String concatenation in SQL execution path",
        "Replace string-built SQL with parameterized queries or repository methods.",
        ("createNativeQuery(", "Statement ", "SELECT * FROM"),
    ),
]


def scan_codebase(root: Path) -> list[VulnerabilityFinding]:
    findings: list[VulnerabilityFinding] = []
    for path in root.rglob("*.java"):
        try:
            content = path.read_text(encoding="utf-8")
        except OSError:
            continue
        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            lowered = line.lower()
            for pattern_id, severity, explanation, remediation, needles in SCAN_PATTERNS:
                if any(needle.lower() in lowered for needle in needles):
                    findings.append(
                        VulnerabilityFinding(
                            finding_id=str(uuid4()),
                            title=pattern_id,
                            severity=severity,
                            file_path=str(path),
                            line_number=idx,
                            pattern=pattern_id,
                            explanation=f"{explanation}. The scanner matched line-level code that often leads to exploitable data flow.",
                            remediation=remediation,
                            source_snippet=line.strip(),
                        )
                    )
    return findings

