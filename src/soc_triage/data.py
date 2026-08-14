from __future__ import annotations

from pathlib import Path

import pandas as pd

from .models import Alert


PACKAGE_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET = PACKAGE_ROOT / "data" / "sample_alerts.csv"

# Common CICIDS2017 spellings plus the compact demo schema.
COLUMN_ALIASES = {
    "Flow ID": "alert_id",
    "Timestamp": "timestamp",
    "Source IP": "src_ip",
    "Destination IP": "dst_ip",
    "Source Port": "src_port",
    "Destination Port": "dst_port",
    "Protocol": "protocol",
    "Total Length of Fwd Packets": "payload_bytes",
    "Flow Duration": "flow_duration_us",
    "Total Fwd Packets": "packets_forward",
    "Total Backward Packets": "packets_backward",
    "SYN Flag Count": "syn_flag_count",
    "Label": "ground_truth_label",
}

REQUIRED = {
    "timestamp",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "payload_bytes",
    "packets_forward",
    "packets_backward",
    "syn_flag_count",
    "ground_truth_label",
}


def load_alert_frame(path: str | Path = DEFAULT_DATASET) -> pd.DataFrame:
    frame = pd.read_csv(path).rename(columns=COLUMN_ALIASES)
    missing = REQUIRED - set(frame.columns)
    if missing:
        raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")

    if "alert_id" not in frame:
        frame["alert_id"] = [f"alert-{index:05d}" for index in range(len(frame))]
    if "flow_duration_ms" not in frame:
        if "flow_duration_us" in frame:
            frame["flow_duration_ms"] = frame["flow_duration_us"] / 1_000
        else:
            frame["flow_duration_ms"] = 0.0
    if "failed_logins" not in frame:
        frame["failed_logins"] = 0

    frame["protocol"] = frame["protocol"].map(_normalize_protocol)
    return frame


def alerts_from_frame(frame: pd.DataFrame) -> list[Alert]:
    allowed = set(Alert.model_fields)
    return [Alert.model_validate({key: value for key, value in row.items() if key in allowed}) for row in frame.to_dict("records")]


def _normalize_protocol(value: object) -> str:
    text = str(value).strip().upper()
    return {"6": "TCP", "17": "UDP", "1": "ICMP", "6.0": "TCP", "17.0": "UDP"}.get(text, text)

