from pathlib import Path

from soc_triage.data import alerts_from_frame, load_alert_frame
from soc_triage.enrichment import enrich
from soc_triage.evaluation import evaluate
from soc_triage.triage import RuleTriageEngine


DATA = Path(__file__).parents[1] / "data" / "sample_alerts.csv"


def test_enrichment_marks_known_bad_source() -> None:
    frame = load_alert_frame(DATA)
    alert = next(item for item in alerts_from_frame(frame) if item.src_ip == "198.51.100.4")
    enriched = enrich(alert)
    assert enriched.src_known_bad is True
    assert enriched.dst_asset == "public-web-01"


def test_ground_truth_is_not_an_alert_or_prompt_field() -> None:
    frame = load_alert_frame(DATA)
    alert = alerts_from_frame(frame)[0]
    assert "ground_truth_label" not in alert.model_dump()
    assert "ground_truth_label" not in enrich(alert).model_dump()


def test_rule_pipeline_scores_bundled_dataset() -> None:
    results, metrics = evaluate(load_alert_frame(DATA), RuleTriageEngine())
    assert len(results) == 24
    assert metrics["attack_precision"] >= 0.9
    assert metrics["attack_recall"] >= 0.9
    assert metrics["technique_accuracy"] >= 0.85

