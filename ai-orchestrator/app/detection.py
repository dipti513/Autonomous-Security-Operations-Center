from __future__ import annotations

from dataclasses import dataclass
from math import exp

from .models import ThreatAssessment, ThreatLabel, TrafficEvent


SQLI_PATTERNS = [
    "' OR 1=1",
    "UNION SELECT",
    "DROP TABLE",
    "xp_cmdshell",
]


@dataclass(slots=True)
class RetrievalMatch:
    label: str
    confidence: float
    summary: str


class AttackFingerprintStore:
    """In-memory fingerprint hook for demo retrieval enrichment."""

    def __init__(self) -> None:
        self._fingerprints = [
            RetrievalMatch("ddos", 0.88, "High-rate credential stuffing burst from a single IP."),
            RetrievalMatch("injection", 0.84, "SQLi payload shape matched a known UNION SELECT attempt."),
        ]

    def similar_context(self, event: TrafficEvent) -> list[str]:
        matches: list[str] = []
        if event.request_count_last_minute >= 1200:
            matches.append(self._fingerprints[0].summary)
        if event.sqli_token_hits:
            matches.append(self._fingerprints[1].summary)
        return matches


class TrafficClassifier:
    def __init__(self, fingerprint_store: AttackFingerprintStore | None = None) -> None:
        self.fingerprint_store = fingerprint_store or AttackFingerprintStore()

    def assess(self, event: TrafficEvent) -> ThreatAssessment:
        matched_patterns: list[str] = []
        ddos_score = 0.0
        injection_score = 0.0

        if event.request_count_last_minute >= 1500:
            ddos_score += 0.55
            matched_patterns.append("request-rate-threshold")
        elif event.request_count_last_minute >= 900:
            ddos_score += 0.35
            matched_patterns.append("request-rate-warning")

        if event.status_burst_score >= 0.85:
            ddos_score += 0.2
            matched_patterns.append("status-burst")

        if event.repeated_payload_score >= 0.85:
            ddos_score += 0.15
            matched_patterns.append("repeated-payload")

        token_hits = event.sqli_token_hits or []
        if token_hits:
            injection_score += min(0.75, 0.25 * len(token_hits))
            matched_patterns.append("sqli-token-hit")

        if any(token.lower() in event.body_preview.lower() for token in SQLI_PATTERNS):
            injection_score += 0.2
            matched_patterns.append("payload-preview-match")

        if event.status_code >= 500 and token_hits:
            injection_score += 0.1
            matched_patterns.append("error-assisted-injection")

        ddos_conf = _squash(ddos_score)
        injection_conf = _squash(injection_score)
        enrichment = self.fingerprint_store.similar_context(event)

        if injection_conf >= 0.8:
            label = ThreatLabel.INJECTION
            confidence = injection_conf
            rationale = "Payload markers and runtime behavior strongly indicate a SQL injection attempt."
        elif ddos_conf >= 0.8:
            label = ThreatLabel.DDOS
            confidence = ddos_conf
            rationale = "Request volume and burst behavior strongly indicate a denial-of-service pattern."
        elif max(ddos_conf, injection_conf) >= 0.55:
            label = ThreatLabel.SUSPICIOUS
            confidence = max(ddos_conf, injection_conf)
            rationale = "Traffic is anomalous but did not cross the autonomous blocking threshold."
        else:
            label = ThreatLabel.BENIGN
            confidence = 1.0 - max(ddos_conf, injection_conf)
            rationale = "Observed request features look consistent with benign traffic."

        return ThreatAssessment(
            label=label,
            confidence=round(confidence, 3),
            rationale=rationale,
            matched_patterns=matched_patterns,
            features={
                "request_count_last_minute": event.request_count_last_minute,
                "status_burst_score": event.status_burst_score,
                "repeated_payload_score": event.repeated_payload_score,
                "sqli_token_hits": token_hits,
            },
            source_ip=event.source_ip,
            request_id=event.request_id,
            enrichment=enrichment,
        )


def _squash(score: float) -> float:
    bounded = max(0.0, min(score, 1.0))
    return round(1 / (1 + exp(-8 * (bounded - 0.5))), 3)

