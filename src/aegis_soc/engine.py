from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .models import Decision, Enrichment, Indicator

SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
DOMAIN_RE = re.compile(r"\b(?=.{4,253}\b)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[A-Za-z]{2,63}\b")

SEVERITY_POINTS = {
    "informational": 0,
    "low": 10,
    "medium": 25,
    "high": 40,
    "critical": 60,
}


def load_json(path: str | Path) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def normalize_alert(raw: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize common SIEM-style fields into a stable internal schema."""
    alert_id = str(raw.get("id") or raw.get("alert_id") or raw.get("event_id") or "unknown")
    severity = str(raw.get("severity") or raw.get("level") or "medium").lower()
    title = str(raw.get("title") or raw.get("name") or raw.get("rule_name") or "Untitled alert")
    source = str(raw.get("source") or raw.get("product") or raw.get("vendor") or "unknown")
    description = str(raw.get("description") or raw.get("message") or "")

    if severity not in SEVERITY_POINTS:
        severity = "medium"

    return {
        "alert_id": alert_id,
        "severity": severity,
        "title": title,
        "source": source,
        "description": description,
        "raw": raw,
    }


def _walk_values(obj: Any, key: str = "") -> Iterable[Tuple[str, str]]:
    if isinstance(obj, dict):
        for child_key, value in obj.items():
            yield from _walk_values(value, str(child_key).lower())
    elif isinstance(obj, list):
        for value in obj:
            yield from _walk_values(value, key)
    elif isinstance(obj, (str, int, float)):
        yield key, str(obj)


def extract_indicators(event: Dict[str, Any]) -> List[Indicator]:
    values = list(_walk_values(event.get("raw", {})))
    found: set[Tuple[str, str]] = set()

    non_domain_keys = {"user", "username", "account", "process", "process_name", "filename", "file_name"}
    non_domain_suffixes = (".exe", ".dll", ".ps1", ".bat", ".cmd", ".sh", ".py")

    for key, text in values:
        for token in re.findall(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])", text):
            try:
                ip = ipaddress.ip_address(token)
                if ip.version == 4:
                    found.add(("ipv4", str(ip)))
            except ValueError:
                pass

        for sha in SHA256_RE.findall(text):
            found.add(("sha256", sha.lower()))

        if key in non_domain_keys or text.lower().endswith(non_domain_suffixes):
            continue

        for domain in DOMAIN_RE.findall(text):
            candidate = domain.lower()
            if candidate.endswith(non_domain_suffixes):
                continue
            try:
                ipaddress.ip_address(candidate)
            except ValueError:
                found.add(("domain", candidate))

    return [Indicator(kind=k, value=v) for k, v in sorted(found)]


def enrich(indicators: List[Indicator], intel_db: Dict[str, Any]) -> List[Enrichment]:
    enrichments: List[Enrichment] = []
    for indicator in indicators:
        record = intel_db.get(indicator.kind, {}).get(indicator.value)
        if record:
            enrichments.append(
                Enrichment(
                    indicator=indicator,
                    malicious=bool(record.get("malicious", True)),
                    confidence=int(record.get("confidence", 50)),
                    source=str(record.get("source", "local-demo-intel")),
                    tags=list(record.get("tags", [])),
                )
            )
        else:
            enrichments.append(
                Enrichment(
                    indicator=indicator,
                    malicious=False,
                    confidence=0,
                    source="no-match",
                    tags=[],
                )
            )
    return enrichments


def score_event(event: Dict[str, Any], enrichments: List[Enrichment]) -> Decision:
    score = SEVERITY_POINTS[event["severity"]]
    reasons = [f"SIEM severity {event['severity']} => +{score}"]

    for hit in [e for e in enrichments if e.malicious]:
        points = min(30, max(5, round(hit.confidence * 0.3)))
        score += points
        reasons.append(
            f"Malicious {hit.indicator.kind} {hit.indicator.value} "
            f"({hit.confidence}% confidence) => +{points}"
        )

    raw_text = json.dumps(event.get("raw", {}), sort_keys=True).lower()
    for term, points in {
        "powershell": 10,
        "credential": 10,
        "ransomware": 20,
        "mimikatz": 25,
        "lateral movement": 15,
    }.items():
        if term in raw_text:
            score += points
            reasons.append(f"Suspicious context '{term}' => +{points}")

    score = min(score, 100)

    if score >= 80:
        risk, action = "critical", "escalate"
    elif score >= 50:
        risk, action = "high", "create_ticket"
    elif score >= 25:
        risk, action = "medium", "create_ticket"
    else:
        risk, action = "low", "monitor"

    return Decision(score=score, risk=risk, action=action, reasons=reasons, alert_id=event["alert_id"])


def build_ticket(event: Dict[str, Any], decision: Decision, enrichments: List[Enrichment]) -> Dict[str, Any]:
    malicious = [
        {
            "type": e.indicator.kind,
            "value": e.indicator.value,
            "confidence": e.confidence,
            "source": e.source,
            "tags": e.tags,
        }
        for e in enrichments if e.malicious
    ]
    return {
        "external_id": f"AEGIS-{event['alert_id']}",
        "summary": f"[{decision.risk.upper()}] {event['title']}",
        "priority": decision.risk,
        "source": event["source"],
        "risk_score": decision.score,
        "recommended_action": decision.action,
        "malicious_indicators": malicious,
        "description": event["description"],
    }


def build_notification(event: Dict[str, Any], decision: Decision) -> Dict[str, Any]:
    return {
        "channel": "soc-alerts",
        "subject": f"AegisAutomata: {decision.risk.upper()} alert {event['alert_id']}",
        "message": (
            f"{event['title']} | score={decision.score}/100 | "
            f"action={decision.action} | source={event['source']}"
        ),
    }
