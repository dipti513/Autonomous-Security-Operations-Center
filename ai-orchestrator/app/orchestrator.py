from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Protocol
from urllib import error, request

from .agent_bus import AgentStream
from .detection import TrafficClassifier
from .models import (
    AgentMessage,
    AuditEntry,
    EnforcementAction,
    EnforcementStatus,
    Incident,
    IncidentStatus,
    TrafficEvent,
    ThreatLabel,
)
from .repository import InMemoryRepository
from .sample_scan import scan_codebase


class FirewallGateway(Protocol):
    def block_ip(self, source_ip: str, incident_id: str, reason: str, confidence: float, ttl_seconds: int) -> tuple[bool, str]:
        ...


class LocalFirewallGateway:
    def block_ip(self, source_ip: str, incident_id: str, reason: str, confidence: float, ttl_seconds: int) -> tuple[bool, str]:
        return True, f"Simulated Spring Security block for {source_ip} ({ttl_seconds}s)."


class HttpFirewallGateway:
    def __init__(self, base_url: str, admin_token: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.admin_token = admin_token

    def block_ip(self, source_ip: str, incident_id: str, reason: str, confidence: float, ttl_seconds: int) -> tuple[bool, str]:
        payload = json.dumps(
            {
                "sourceIp": source_ip,
                "incidentId": incident_id,
                "reason": reason,
                "confidence": confidence,
                "ttlSeconds": ttl_seconds,
            }
        ).encode("utf-8")
        req = request.Request(
            f"{self.base_url}/api/admin/firewall/block",
            method="POST",
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Admin-Token": self.admin_token,
            },
        )
        try:
            with request.urlopen(req, timeout=5) as response:
                if 200 <= response.status < 300:
                    return True, f"Spring firewall block applied to {source_ip}."
                return False, f"Spring firewall rejected block request with status {response.status}."
        except error.URLError as exc:
            return False, f"Spring firewall call failed: {exc.reason}"


class AsocSupervisor:
    BLOCK_CONFIDENCE = 0.8
    DEFAULT_TTL_SECONDS = 900

    def __init__(
        self,
        repository: InMemoryRepository | None = None,
        classifier: TrafficClassifier | None = None,
        firewall: FirewallGateway | None = None,
        stream: AgentStream | None = None,
    ) -> None:
        self.repository = repository or InMemoryRepository()
        self.classifier = classifier or TrafficClassifier()
        self.firewall = firewall or self._build_firewall_gateway()
        self.stream = stream or AgentStream()

    async def process_traffic_event(self, event: TrafficEvent) -> Incident:
        await self._emit("traffic-monitor", "analysis", f"Analyzing request {event.request_id} from {event.source_ip}.")
        assessment = self.classifier.assess(event)
        incident = Incident(
            source_ip=event.source_ip,
            summary=assessment.rationale,
            assessment=assessment,
            status=IncidentStatus.MONITORING if assessment.label == ThreatLabel.SUSPICIOUS else IncidentStatus.OPEN,
        )
        self.repository.save_incident(incident)
        self.repository.add_audit(
            incident.incident_id,
            AuditEntry(
                actor="traffic-monitor",
                action="classify-traffic",
                summary=assessment.rationale,
                incident_id=incident.incident_id,
                metadata=assessment.to_dict(),
            ),
        )
        await self._emit("supervisor", "decision", f"Threat classified as {assessment.label.value} at {assessment.confidence:.2f} confidence.", incident.incident_id)

        if assessment.label in {ThreatLabel.DDOS, ThreatLabel.INJECTION} and assessment.confidence >= self.BLOCK_CONFIDENCE:
            action = await self._enforce_block(incident)
            incident.enforcement = action
            incident.status = IncidentStatus.BLOCKED if action.status == EnforcementStatus.APPLIED else IncidentStatus.OPEN
        elif assessment.label == ThreatLabel.BENIGN:
            incident.status = IncidentStatus.RESOLVED
            self.repository.add_audit(
                incident.incident_id,
                AuditEntry(
                    actor="supervisor",
                    action="resolve-benign",
                    summary="Traffic resolved as benign and closed automatically.",
                    incident_id=incident.incident_id,
                ),
            )
        else:
            self.repository.add_audit(
                incident.incident_id,
                AuditEntry(
                    actor="supervisor",
                    action="monitor",
                    summary="Traffic retained for monitoring because it did not cross the block threshold.",
                    incident_id=incident.incident_id,
                ),
            )

        await self._emit("auditor", "audit", f"Audit trail recorded for incident {incident.incident_id}.", incident.incident_id)
        return incident

    async def run_vulnerability_scan(self, project_root: Path) -> list[dict]:
        await self._emit("vulnerability-hunter", "scan", "Running repository scan for insecure code paths.")
        findings = scan_codebase(project_root)
        for finding in findings:
            self.repository.add_vulnerability_finding(finding)
            await self._emit(
                "vulnerability-hunter",
                "finding",
                f"{finding.severity} finding in {Path(finding.file_path).name}: {finding.title}.",
            )
        await self._emit("auditor", "audit", f"Recorded {len(findings)} vulnerability findings from scheduled scan.")
        return [finding.to_dict() for finding in findings]

    async def _enforce_block(self, incident: Incident) -> EnforcementAction:
        active = self.repository.get_active_block(incident.source_ip)
        if active:
            action = EnforcementAction(
                incident_id=incident.incident_id,
                source_ip=incident.source_ip,
                reason="Active block already exists for source IP.",
                confidence=incident.assessment.confidence,
                ttl_seconds=0,
                status=EnforcementStatus.SKIPPED,
            )
            self.repository.add_audit(
                incident.incident_id,
                AuditEntry(
                    actor="incident-responder",
                    action="dedupe-block",
                    summary="Skipped duplicate block request because an active firewall rule already exists.",
                    incident_id=incident.incident_id,
                ),
            )
            await self._emit("incident-responder", "skip", f"Skipped duplicate block for {incident.source_ip}.", incident.incident_id)
            return action

        success, details = self.firewall.block_ip(
            source_ip=incident.source_ip,
            incident_id=incident.incident_id,
            reason=incident.assessment.rationale,
            confidence=incident.assessment.confidence,
            ttl_seconds=self.DEFAULT_TTL_SECONDS,
        )
        action = EnforcementAction(
            incident_id=incident.incident_id,
            source_ip=incident.source_ip,
            reason=incident.assessment.rationale,
            confidence=incident.assessment.confidence,
            ttl_seconds=self.DEFAULT_TTL_SECONDS,
            status=EnforcementStatus.APPLIED if success else EnforcementStatus.FAILED,
            error_message=None if success else details,
        )
        if success:
            self.repository.mark_blocked(action)
        self.repository.add_audit(
            incident.incident_id,
            AuditEntry(
                actor="incident-responder",
                action="block-ip",
                summary=details,
                incident_id=incident.incident_id,
                metadata=action.to_dict(),
            ),
        )
        await self._emit("incident-responder", "enforcement", details, incident.incident_id)
        return action

    async def _emit(self, agent: str, kind: str, content: str, incident_id: str | None = None) -> None:
        message = AgentMessage(agent=agent, kind=kind, content=content, incident_id=incident_id)
        self.repository.record_message(message)
        await self.stream.publish(message)

    def _build_firewall_gateway(self) -> FirewallGateway:
        base_url = os.getenv("ASOC_SPRING_APP_BASE_URL", "").strip()
        admin_token = os.getenv("ASOC_ADMIN_TOKEN", "").strip()
        if base_url and admin_token:
            return HttpFirewallGateway(base_url=base_url, admin_token=admin_token)
        return LocalFirewallGateway()
