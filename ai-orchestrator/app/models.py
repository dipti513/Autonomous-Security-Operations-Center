from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ThreatLabel(str, Enum):
    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    DDOS = "ddos"
    INJECTION = "injection"


class IncidentStatus(str, Enum):
    OPEN = "open"
    BLOCKED = "blocked"
    MONITORING = "monitoring"
    RESOLVED = "resolved"


class EnforcementStatus(str, Enum):
    PROPOSED = "proposed"
    APPLIED = "applied"
    FAILED = "failed"
    EXPIRED = "expired"
    SKIPPED = "skipped"


@dataclass(slots=True)
class TrafficEvent:
    request_id: str
    source_ip: str
    path: str
    method: str
    status_code: int
    request_count_last_minute: int
    path_entropy: float
    status_burst_score: float
    repeated_payload_score: float
    sqli_token_hits: list[str]
    user_agent: str
    body_preview: str = ""
    received_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["received_at"] = self.received_at.isoformat()
        return payload


@dataclass(slots=True)
class ThreatAssessment:
    label: ThreatLabel
    confidence: float
    rationale: str
    matched_patterns: list[str]
    features: dict[str, Any]
    source_ip: str
    request_id: str
    enrichment: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["label"] = self.label.value
        return payload


@dataclass(slots=True)
class EnforcementAction:
    incident_id: str
    source_ip: str
    reason: str
    confidence: float
    ttl_seconds: int
    status: EnforcementStatus
    action_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=utc_now)
    expires_at: datetime | None = None
    error_message: str | None = None

    def __post_init__(self) -> None:
        if self.expires_at is None and self.ttl_seconds > 0:
            self.expires_at = self.created_at + timedelta(seconds=self.ttl_seconds)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["status"] = self.status.value
        payload["created_at"] = self.created_at.isoformat()
        payload["expires_at"] = self.expires_at.isoformat() if self.expires_at else None
        return payload


@dataclass(slots=True)
class AuditEntry:
    actor: str
    action: str
    summary: str
    incident_id: str | None = None
    event_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat()
        return payload


@dataclass(slots=True)
class VulnerabilityFinding:
    finding_id: str
    title: str
    severity: str
    file_path: str
    pattern: str
    explanation: str
    remediation: str
    line_number: int | None = None
    source_snippet: str = ""
    discovered_at: datetime = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["discovered_at"] = self.discovered_at.isoformat()
        return payload


@dataclass(slots=True)
class Incident:
    source_ip: str
    summary: str
    assessment: ThreatAssessment
    status: IncidentStatus
    incident_id: str = field(default_factory=lambda: str(uuid4()))
    created_at: datetime = field(default_factory=utc_now)
    enforcement: EnforcementAction | None = None
    audit_trail: list[AuditEntry] = field(default_factory=list)
    vulnerability_findings: list[VulnerabilityFinding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "source_ip": self.source_ip,
            "summary": self.summary,
            "status": self.status.value,
            "created_at": self.created_at.isoformat(),
            "assessment": self.assessment.to_dict(),
            "enforcement": self.enforcement.to_dict() if self.enforcement else None,
            "audit_trail": [entry.to_dict() for entry in self.audit_trail],
            "vulnerability_findings": [finding.to_dict() for finding in self.vulnerability_findings],
        }


@dataclass(slots=True)
class AgentMessage:
    agent: str
    kind: str
    content: str
    incident_id: str | None = None
    created_at: datetime = field(default_factory=utc_now)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["created_at"] = self.created_at.isoformat()
        return payload

