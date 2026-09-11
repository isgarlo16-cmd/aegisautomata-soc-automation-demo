from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from .engine import (
    build_notification,
    build_ticket,
    enrich,
    extract_indicators,
    normalize_alert,
    score_event,
)


def _write_json(path: Path, payload: Dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def process_alert(raw_alert: Dict[str, Any], intel_db: Dict[str, Any], output_dir: str | Path | None = None) -> Dict[str, Any]:
    event = normalize_alert(raw_alert)
    indicators = extract_indicators(event)
    enrichments = enrich(indicators, intel_db)
    decision = score_event(event, enrichments)
    ticket = build_ticket(event, decision, enrichments)
    notification = build_notification(event, decision)

    result = {
        "event": {k: v for k, v in event.items() if k != "raw"},
        "indicators": [asdict(i) for i in indicators],
        "enrichments": [asdict(e) for e in enrichments],
        "decision": decision.to_dict(),
        "ticket": ticket,
        "notification": notification,
    }

    if output_dir is not None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        _write_json(out / "decision.json", decision.to_dict())
        _write_json(out / "ticket.json", ticket)
        _write_json(out / "notification.json", notification)
        audit_record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": event["alert_id"],
            "risk_score": decision.score,
            "risk": decision.risk,
            "action": decision.action,
            "indicator_count": len(indicators),
            "malicious_indicator_count": sum(1 for e in enrichments if e.malicious),
        }
        with open(out / "audit.jsonl", "a", encoding="utf-8") as fh:
            fh.write(json.dumps(audit_record, sort_keys=True) + "\n")

    return result
