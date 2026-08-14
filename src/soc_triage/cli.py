from __future__ import annotations

import argparse
import json
from pathlib import Path

from .data import DEFAULT_DATASET, load_alert_frame
from .evaluation import evaluate
from .triage import OpenAITriageEngine, RuleTriageEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate SOC alert triage decisions")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATASET)
    parser.add_argument("--engine", choices=("rules", "openai"), default="rules")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", type=Path, default=None)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    frame = load_alert_frame(args.data)
    if args.limit:
        frame = frame.head(args.limit)
    engine = RuleTriageEngine() if args.engine == "rules" else OpenAITriageEngine()
    results, metrics = evaluate(frame, engine)
    print(json.dumps(metrics, indent=2))
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        results.to_csv(args.output, index=False)
        print(f"Wrote {len(results)} decisions to {args.output}")


if __name__ == "__main__":
    main()

