from __future__ import annotations

from collections import deque
from threading import Lock

from .models import AgentMessage, AuditEntry, EnforcementAction, Incident, VulnerabilityFinding


class InMemoryRepository:
    def __init__(self) -> None:
        self._lock = Lock()
        self._incidents: dict[str, Incident] = {}
        self._messages: deque[AgentMessage] = deque(maxlen=200)
        self._blocked_actions: dict[str, EnforcementAction] = {}
        self._vulnerability_findings: list[VulnerabilityFinding] = []

    def save_incident(self, incident: Incident) -> Incident:
        with self._lock:
            self._incidents[incident.incident_id] = incident
        return incident

    def list_incidents(self) -> list[Incident]:
        with self._lock:
            return sorted(self._incidents.values(), key=lambda item: item.created_at, reverse=True)

    def get_incident(self, incident_id: str) -> Incident | None:
        with self._lock:
            return self._incidents.get(incident_id)

    def record_message(self, message: AgentMessage) -> None:
        with self._lock:
            self._messages.appendleft(message)

    def recent_messages(self) -> list[AgentMessage]:
        with self._lock:
            return list(self._messages)

    def mark_blocked(self, action: EnforcementAction) -> None:
        with self._lock:
            self._blocked_actions[action.source_ip] = action

    def unblock(self, source_ip: str) -> None:
        with self._lock:
            self._blocked_actions.pop(source_ip, None)

    def get_active_block(self, source_ip: str) -> EnforcementAction | None:
        with self._lock:
            return self._blocked_actions.get(source_ip)

    def list_active_blocks(self) -> list[EnforcementAction]:
        with self._lock:
            return list(self._blocked_actions.values())

    def add_audit(self, incident_id: str, entry: AuditEntry) -> None:
        with self._lock:
            incident = self._incidents[incident_id]
            incident.audit_trail.append(entry)

    def add_vulnerability_finding(self, finding: VulnerabilityFinding) -> None:
        with self._lock:
            self._vulnerability_findings.append(finding)

    def list_vulnerability_findings(self) -> list[VulnerabilityFinding]:
        with self._lock:
            return list(self._vulnerability_findings)

