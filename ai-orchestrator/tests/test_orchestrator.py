import asyncio
from pathlib import Path
import unittest

from app.models import EnforcementStatus, IncidentStatus
from app.orchestrator import AsocSupervisor
from tests.test_detection import make_event


class OrchestratorTests(unittest.TestCase):
    def test_high_confidence_threat_triggers_block(self):
        supervisor = AsocSupervisor()
        incident = asyncio.run(
            supervisor.process_traffic_event(
                make_event(request_count_last_minute=2000, status_burst_score=0.95, repeated_payload_score=0.92)
            )
        )
        self.assertEqual(incident.status, IncidentStatus.BLOCKED)
        self.assertIsNotNone(incident.enforcement)
        self.assertEqual(incident.enforcement.status, EnforcementStatus.APPLIED)

    def test_duplicate_threat_does_not_duplicate_block(self):
        supervisor = AsocSupervisor()
        first = asyncio.run(
            supervisor.process_traffic_event(
                make_event(request_id="req-first", request_count_last_minute=2000, status_burst_score=0.95, repeated_payload_score=0.92)
            )
        )
        second = asyncio.run(
            supervisor.process_traffic_event(
                make_event(request_id="req-second", request_count_last_minute=2100, status_burst_score=0.98, repeated_payload_score=0.94)
            )
        )
        self.assertIsNotNone(first.enforcement)
        self.assertIsNotNone(second.enforcement)
        self.assertEqual(second.enforcement.status, EnforcementStatus.SKIPPED)

    def test_vulnerability_scan_returns_findings(self):
        supervisor = AsocSupervisor()
        findings = asyncio.run(supervisor.run_vulnerability_scan(Path(__file__).resolve().parents[2] / "spring-boot-app"))
        self.assertIsInstance(findings, list)
        self.assertGreaterEqual(len(findings), 1)


if __name__ == "__main__":
    unittest.main()
