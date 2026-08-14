# BlueTriage: AI SOC Triage Agent

The app supports two engines:

- **Rules:** a transparent, offline baseline that makes the project runnable without credentials.
- **OpenAI:** a schema-constrained LLM path that returns the same typed decision object.

Both engines produce an attack/not-attack decision, severity, MITRE ATT&CK technique, plain-English summary, recommended next action, confidence, and engine identifier.

## What the Agent demonstrates

```text
static CSV -> normalize -> enrich -> triage -> analyst queue
                                      |
ground truth ------------------------> evaluation metrics
```

The dataset label is deliberately removed before alert validation. It is joined back only during evaluation, preventing the most serious failure mode in this kind of portfolio project: label leakage into the prompt.

Enrichment is deterministic and local:

- private/public IP classification
- small CIDR-based known-bad list
- destination asset name and criticality
- port-to-service mapping
- traffic direction and bytes-per-packet

The ATT&CK rubric currently covers [T1046 Network Service Discovery](https://attack.mitre.org/techniques/T1046/), [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/), [T1498.001 Direct Network Flood](https://attack.mitre.org/techniques/T1498/001/), and [T1071.001 Web Protocols](https://attack.mitre.org/techniques/T1071/001/).

## Quick start

Python 3.10 or newer is required.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[dev]'
pytest -q
soc-triage --output results/baseline.csv
streamlit run app.py
```

The dashboard opens at `http://localhost:8501`. It uses `data/sample_alerts.csv` unless a CSV is uploaded.

## Optional LLM engine

Install the SDK and export credentials:

```bash
pip install -e '.[llm]'
export OPENAI_API_KEY='...'
export OPENAI_MODEL='gpt-5.4-mini'
soc-triage --engine openai --limit 10 --output results/openai.csv
```

The implementation uses the Responses API's Pydantic parsing path, following the [official OpenAI Structured Outputs documentation](https://developers.openai.com/api/docs/guides/structured-outputs). The model name is configurable so evaluation runs can be pinned and compared. Do not commit API keys; `.env.example` contains names only.

## Using CICIDS2017

The bundled 24-row CSV is **CICIDS-shaped synthetic demo data**, not a redistribution of CICIDS2017. It exists to exercise every branch quickly and deterministically. Its perfect baseline score is a smoke-test result, not evidence of real-world performance.

To run a meaningful experiment:

1. Obtain CICIDS2017 from its official distributor and retain the original license/citation.
2. Combine the relevant day files or select 100–200 stratified rows across `BENIGN`, `PortScan`, `FTP-Patator`, `SSH-Patator`, `DDoS`, and `Bot`.
3. Keep the original column names. The loader already maps common CICIDS2017 names into the internal schema.
4. Add `Source IP` and `Destination IP` when using a feature CSV variant that omitted identifiers. If those fields cannot be recovered, use explicit placeholders and disable IP-based enrichment rather than fabricating values.
5. Run the same sample through both engines and save both result CSVs.

Example stratified selection in a notebook:

```python
sample = (
    full[full["Label"].isin(labels)]
    .groupby("Label", group_keys=False)
    .sample(n=20, random_state=42)
)
sample.to_csv("data/cicids_eval_120.csv", index=False)
```

For an honest resume metric, freeze the sample and rubric before prompt iteration. Report macro results and per-class counts, then disclose the sample size, model snapshot, prompt version, and whether any rows were used during development.

## Metrics

`soc_triage.evaluation.evaluate` calculates:

- attack precision, recall, and F1
- severity within one ordinal level
- exact ATT&CK technique accuracy

Severity is a rubric, not a native CICIDS2017 target. The current mapping is explicit in `evaluation.py`, so it can be reviewed and replaced with a small analyst-labeled severity set. Exact technique accuracy is intentionally strict; a later version could add parent/sub-technique partial credit.

Current bundled smoke-test:

| Metric | Result |
|---|---:|
| Attack precision | 100% |
| Attack recall | 100% |
| Attack F1 | 100% |
| Severity within one level | 100% |
| Exact technique accuracy | 100% |

## Project layout

```text
app.py                         Streamlit analyst view
data/sample_alerts.csv         Synthetic, CICIDS-shaped smoke-test set
src/soc_triage/data.py         CSV normalization and label isolation
src/soc_triage/enrichment.py   Local context gathering
src/soc_triage/triage.py       Rules and schema-constrained LLM engines
src/soc_triage/evaluation.py   Rubric and metrics
src/soc_triage/cli.py          Reproducible batch runner
tests/test_pipeline.py         Leakage, enrichment, and end-to-end tests
```

## Design choices and limitations

- **Single alerts only.** A port scan or DDoS campaign is fundamentally multi-flow behavior; this MVP infers from per-flow counters and will miss distributed or slow activity.
- **Known-bad data is illustrative.** The bundled CIDRs are documentation ranges, not a live threat-intelligence feed.
- **No geo-IP call.** It adds network failure, privacy questions, and limited signal. A local MaxMind database is a sensible v2 addition.
- **No auto-remediation.** Recommended actions remain advisory and require analyst review.
- **The rule baseline is intentionally visible.** It provides a sanity check, an explainability reference, and a way to measure whether the LLM adds value.
- **Confidence is self-reported.** It is not calibrated probability. Calibration requires a larger held-out set.
- **Prompt injection risk remains.** Treat all alert strings as untrusted data, keep them in a structured user payload, restrict outputs to the schema, and never connect recommendations directly to execution.

## Sensible v2 work

After the held-out v1 evaluation is credible: local GeoIP/threat-intel snapshots, per-class confusion matrices, caching and concurrency for LLM runs, prompt/model version tracking, and multi-alert correlation. Live ingestion and automated response should remain later milestones.

