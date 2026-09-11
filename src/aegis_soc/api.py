from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, HTTPException

from .engine import load_json
from .workflow import process_alert

app = FastAPI(title="AegisAutomata SOC Automation Demo", version="1.0.0")
INTEL_PATH = Path(__file__).resolve().parents[2] / "data" / "threat_intel.json"


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.post("/process-alert")
def process(alert: dict) -> dict:
    if not isinstance(alert, dict) or not alert:
        raise HTTPException(status_code=400, detail="Alert must be a non-empty JSON object")
    intel = load_json(INTEL_PATH)
    return process_alert(alert, intel)
