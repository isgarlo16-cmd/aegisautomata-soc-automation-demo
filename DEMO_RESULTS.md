# Demo result

Using the included `data/sample_alert.json`, the workflow produces a deterministic result suitable for a portfolio demonstration:

- Alert ID: `SENTINEL-2026-00042`
- Source: `Microsoft Sentinel`
- Base severity: `high`
- Detected malicious indicators: demo IPv4, domain and SHA-256
- Final risk score: `100/100`
- Final risk: `critical`
- Automated action: `escalate`
- Generated artifacts: decision, ticket payload, notification payload, audit record

All indicators use documentation/example data and are not intended to represent live malicious infrastructure.
