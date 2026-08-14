from __future__ import annotations

import pandas as pd

from .data import alerts_from_frame
from .enrichment import enrich
from .models import Severity
from .triage import TriageEngine


EXPECTED = {
    "BENIGN": (False, Severity.low, "N/A"),
    "PortScan": (True, Severity.medium, "T1046"),
    "FTP-Patator": (True, Severity.high, "T1110"),
    "SSH-Patator": (True, Severity.high, "T1110"),
    "DDoS": (True, Severity.critical, "T1498.001"),
    "Bot": (True, Severity.high, "T1071.001"),
}
SEVERITY_RANK = {Severity.low: 0, Severity.medium: 1, Severity.high: 2, Severity.critical: 3}


def evaluate(frame: pd.DataFrame, engine: TriageEngine) -> tuple[pd.DataFrame, dict[str, float]]:
    decisions = [engine.triage(enrich(alert)) for alert in alerts_from_frame(frame)]
    rows: list[dict[str, object]] = []
    for source, decision in zip(frame.to_dict("records"), decisions, strict=True):
        label = str(source["ground_truth_label"])
        if label not in EXPECTED:
            raise ValueError(f"No evaluation rubric for ground-truth label {label!r}")
        expected_attack, expected_severity, expected_technique = EXPECTED[label]
        rows.append(
            {
                "alert_id": source["alert_id"],
                "timestamp": source["timestamp"],
                "src_ip": source["src_ip"],
                "dst_ip": source["dst_ip"],
                "ground_truth_label": label,
                "expected_severity": expected_severity.value,
                **decision.model_dump(mode="json"),
                "attack_correct": decision.predicted_attack == expected_attack,
                "severity_close": abs(SEVERITY_RANK[decision.severity] - SEVERITY_RANK[expected_severity]) <= 1,
                "technique_correct": decision.technique_id == expected_technique,
            }
        )

    results = pd.DataFrame(rows)
    actual = results["ground_truth_label"] != "BENIGN"
    predicted = results["predicted_attack"].astype(bool)
    tp = int((actual & predicted).sum())
    fp = int((~actual & predicted).sum())
    fn = int((actual & ~predicted).sum())
    metrics = {
        "alerts": float(len(results)),
        "attack_precision": tp / (tp + fp) if tp + fp else 0.0,
        "attack_recall": tp / (tp + fn) if tp + fn else 0.0,
        "attack_f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else 0.0,
        "severity_within_one": float(results["severity_close"].mean()),
        "technique_accuracy": float(results["technique_correct"].mean()),
    }
    return results, metrics

