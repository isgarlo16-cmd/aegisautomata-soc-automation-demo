from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, Dict, List


@dataclass(frozen=True)
class Indicator:
    kind: str
    value: str


@dataclass
class Enrichment:
    indicator: Indicator
    malicious: bool
    confidence: int
    source: str
    tags: List[str]


@dataclass
class Decision:
    score: int
    risk: str
    action: str
    reasons: List[str]
    alert_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
