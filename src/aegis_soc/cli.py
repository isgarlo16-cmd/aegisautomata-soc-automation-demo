from __future__ import annotations

import argparse
import json

from .engine import load_json
from .workflow import process_alert


def main() -> None:
    parser = argparse.ArgumentParser(description="AegisAutomata SOC automation demo")
    parser.add_argument("--alert", required=True, help="Path to SIEM alert JSON")
    parser.add_argument("--intel", required=True, help="Path to local threat intel JSON")
    parser.add_argument("--output", default="output", help="Directory for generated outputs")
    args = parser.parse_args()

    result = process_alert(load_json(args.alert), load_json(args.intel), args.output)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
