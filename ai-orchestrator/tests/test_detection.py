import unittest

from app.detection import TrafficClassifier
from app.models import ThreatLabel, TrafficEvent


def make_event(**overrides):
    data = {
        "request_id": "req-1",
        "source_ip": "203.0.113.10",
        "path": "/login",
        "method": "POST",
        "status_code": 200,
        "request_count_last_minute": 50,
        "path_entropy": 0.4,
        "status_burst_score": 0.2,
        "repeated_payload_score": 0.1,
        "sqli_token_hits": [],
        "user_agent": "pytest",
        "body_preview": "",
    }
    data.update(overrides)
    return TrafficEvent(**data)


class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.classifier = TrafficClassifier()

    def test_benign_traffic_stays_benign(self):
        assessment = self.classifier.assess(make_event())
        self.assertEqual(assessment.label, ThreatLabel.BENIGN)

    def test_ddos_traffic_becomes_ddos(self):
        assessment = self.classifier.assess(
            make_event(request_count_last_minute=1800, status_burst_score=0.91, repeated_payload_score=0.9)
        )
        self.assertEqual(assessment.label, ThreatLabel.DDOS)
        self.assertGreaterEqual(assessment.confidence, 0.8)

    def test_sqli_payload_becomes_injection(self):
        assessment = self.classifier.assess(
            make_event(status_code=500, sqli_token_hits=["' OR 1=1", "UNION SELECT"], body_preview="' OR 1=1 --")
        )
        self.assertEqual(assessment.label, ThreatLabel.INJECTION)
        self.assertGreaterEqual(assessment.confidence, 0.8)

    def test_low_confidence_event_stays_suspicious(self):
        assessment = self.classifier.assess(make_event(request_count_last_minute=950, status_burst_score=0.86))
        self.assertEqual(assessment.label, ThreatLabel.SUSPICIOUS)

if __name__ == "__main__":
    unittest.main()
