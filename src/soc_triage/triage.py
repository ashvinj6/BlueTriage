from __future__ import annotations

import json
import os
from typing import Protocol

from .models import EnrichedAlert, Severity, TriageDecision


class TriageEngine(Protocol):
    def triage(self, alert: EnrichedAlert) -> TriageDecision: ...


class RuleTriageEngine:
    """Transparent offline baseline for demos, tests, and LLM comparison."""

    def triage(self, alert: EnrichedAlert) -> TriageDecision:
        prefix = f"{alert.protocol} flow from {alert.src_ip} to {alert.dst_asset} ({alert.dst_ip}:{alert.dst_port})"

        if alert.failed_logins >= 5:
            severity = Severity.critical if alert.dst_asset_criticality == Severity.critical else Severity.high
            return self._decision(True, severity, "T1110", "Brute Force", f"{prefix} recorded {alert.failed_logins} failed logins, consistent with repeated authentication attempts.", "Block or rate-limit the source, preserve authentication logs, and escalate for account-compromise review.", 0.96)

        if alert.packets_forward >= 800 and alert.flow_duration_ms <= 10_000:
            return self._decision(True, Severity.critical, "T1498.001", "Direct Network Flood", f"{prefix} delivered {alert.packets_forward:,} forward packets in {alert.flow_duration_ms:,.0f} ms, consistent with a volumetric denial-of-service flow.", "Escalate immediately and apply upstream rate limiting or DDoS mitigation while validating service availability.", 0.94)

        if alert.syn_flag_count >= 20 and alert.packets_backward <= 3:
            return self._decision(True, Severity.medium, "T1046", "Network Service Discovery", f"{prefix} shows {alert.syn_flag_count} SYN flags with little response traffic, consistent with service probing.", "Monitor the source across destinations, block if unauthorized, and review exposed services.", 0.91)

        if alert.src_known_bad:
            return self._decision(True, Severity.high, "T1071.001", "Web Protocols", f"{prefix} originated from a locally listed known-bad network and may represent command-and-control over a common web protocol.", "Isolate the destination if communication is confirmed, block the source, and collect endpoint telemetry.", 0.82)

        return self._decision(False, Severity.low, "N/A", "No technique assigned", f"{prefix} does not cross the MVP's attack thresholds and has no known-bad source match.", "Continue monitoring; no immediate containment action is recommended.", 0.78)

    @staticmethod
    def _decision(predicted_attack: bool, severity: Severity, technique_id: str, technique_name: str, summary: str, action: str, confidence: float) -> TriageDecision:
        return TriageDecision(predicted_attack=predicted_attack, severity=severity, technique_id=technique_id, technique_name=technique_name, summary=summary, recommended_action=action, confidence=confidence, engine="rules")


SYSTEM_PROMPT = """You are a defensive SOC triage assistant. Assess only the supplied single alert.
Do not assume facts not present. Ground truth labels are intentionally unavailable.
Set predicted_attack false and technique_id 'N/A' when evidence is insufficient.
Use an Enterprise MITRE ATT&CK technique ID. Keep the summary to one plain-English paragraph.
Recommended actions are advisory: monitor, investigate, block, isolate, or escalate; never claim an action occurred."""


class OpenAITriageEngine:
    """Schema-constrained LLM engine. Import is lazy so offline mode has no SDK dependency."""

    def __init__(self, model: str | None = None) -> None:
        try:
            from openai import OpenAI
        except ImportError as exc:
            raise RuntimeError("Install the LLM extra: pip install -e '.[llm]'") from exc
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError("OPENAI_API_KEY is not set")
        self.client = OpenAI()
        self.model = model or os.getenv("OPENAI_MODEL", "gpt-5.4-mini")

    def triage(self, alert: EnrichedAlert) -> TriageDecision:
        response = self.client.responses.parse(
            model=self.model,
            input=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(alert.model_dump(mode="json"), indent=2)},
            ],
            text_format=TriageDecision,
        )
        result = response.output_parsed
        if result is None:
            raise RuntimeError("The model did not return a parsed triage decision")
        return result.model_copy(update={"engine": f"openai:{self.model}"})

