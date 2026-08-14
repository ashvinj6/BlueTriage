from __future__ import annotations

import os

import streamlit as st

from soc_triage.data import DEFAULT_DATASET, load_alert_frame
from soc_triage.evaluation import evaluate
from soc_triage.triage import OpenAITriageEngine, RuleTriageEngine


st.set_page_config(page_title="SOC Triage Agent", page_icon="🛡️", layout="wide")
st.title("SOC Triage Agent")
st.caption("Static alert enrichment, explainable triage, ATT&CK mapping, and ground-truth evaluation")

with st.sidebar:
    st.header("Run configuration")
    uploaded = st.file_uploader("CICIDS-shaped CSV", type="csv")
    engine_name = st.selectbox("Triage engine", ["Rules (offline baseline)", "OpenAI (structured output)"])
    limit = st.slider("Alerts to process", 1, 200, 24)
    run = st.button("Run triage", type="primary", use_container_width=True)

if not run:
    st.info("Choose an engine and run triage. The bundled demo data is used when no CSV is uploaded.")
    st.stop()

try:
    frame = load_alert_frame(uploaded if uploaded is not None else DEFAULT_DATASET).head(limit)
    if engine_name.startswith("OpenAI"):
        if not os.getenv("OPENAI_API_KEY"):
            st.error("Set OPENAI_API_KEY before using the OpenAI engine.")
            st.stop()
        engine = OpenAITriageEngine()
    else:
        engine = RuleTriageEngine()
    with st.spinner(f"Triaging {len(frame)} alerts..."):
        results, metrics = evaluate(frame, engine)
except Exception as exc:
    st.exception(exc)
    st.stop()

columns = st.columns(5)
labels = ["Attack precision", "Attack recall", "Attack F1", "Severity ±1", "Technique accuracy"]
keys = ["attack_precision", "attack_recall", "attack_f1", "severity_within_one", "technique_accuracy"]
for column, label, key in zip(columns, labels, keys, strict=True):
    column.metric(label, f"{metrics[key]:.0%}")

st.subheader("Analyst queue")
severity = st.multiselect("Severity", ["critical", "high", "medium", "low"], default=["critical", "high", "medium", "low"])
filtered = results[results["severity"].isin(severity)]
st.dataframe(
    filtered[["timestamp", "src_ip", "dst_ip", "ground_truth_label", "predicted_attack", "severity", "technique_id", "confidence", "summary", "recommended_action"]],
    use_container_width=True,
    hide_index=True,
    column_config={"confidence": st.column_config.ProgressColumn(format="%.2f", min_value=0.0, max_value=1.0)},
)

st.download_button("Download decisions as CSV", filtered.to_csv(index=False), "triage_decisions.csv", "text/csv")
st.caption("Ground-truth labels are used only after inference to compute metrics; they are never included in the triage prompt.")

