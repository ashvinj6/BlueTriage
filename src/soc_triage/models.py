from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class Alert(BaseModel):
    """Normalized fields made available to the triage pipeline."""

    model_config = ConfigDict(extra="ignore")

    alert_id: str
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: str
    payload_bytes: int = Field(ge=0)
    flow_duration_ms: float = Field(ge=0)
    packets_forward: int = Field(ge=0)
    packets_backward: int = Field(ge=0)
    syn_flag_count: int = Field(ge=0)
    failed_logins: int = Field(default=0, ge=0)


class EnrichedAlert(Alert):
    src_is_private: bool
    dst_is_private: bool
    src_known_bad: bool
    dst_asset: str
    dst_asset_criticality: Severity
    destination_service: str
    bytes_per_packet: float
    direction: str


class TriageDecision(BaseModel):
    predicted_attack: bool
    severity: Severity
    technique_id: str = Field(description="MITRE ATT&CK technique ID or N/A")
    technique_name: str
    summary: str
    recommended_action: str
    confidence: float = Field(ge=0, le=1)
    engine: str = "rules"

