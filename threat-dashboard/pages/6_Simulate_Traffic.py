"""
Streamlit Page 6: Simulate Traffic
Interactive telemetry generator that runs synthetic or NSL-KDD test packets through
the pipeline to test detection speed, classification, and alerting.
"""
import streamlit as st
import pandas as pd
import numpy as np
import time
from src.data_loader import generate_synthetic_stream
from src.pipeline import run_pipeline, append_event

st.set_page_config(page_title="Simulate Traffic - SOC Threat Intel", layout="wide")
st.title("⚡ Telemetry & Attack Simulation Engine")
st.caption("Generate realistic synthetic telemetry batches and stream them through the ML + Risk scoring pipeline.")

col_ctrl1, col_ctrl2, col_ctrl3 = st.columns(3)
with col_ctrl1:
    batch_size = st.slider("Batch Size (Events)", min_value=10, max_value=250, value=50, step=10)
with col_ctrl2:
    attack_ratio = st.slider("Attack Ratio", min_value=0.05, max_value=0.90, value=0.35, step=0.05)
with col_ctrl3:
    sim_speed = st.selectbox("Injection Speed", ["Burst (Instant)", "Gradual (100ms delay)", "Real-time (300ms delay)"])

if st.button("🚀 Run Live Traffic Simulation", type="primary"):
    status_box = st.empty()
    progress_bar = st.progress(0)

    status_box.info(f"Generating {batch_size} network telemetry records with {int(attack_ratio*100)}% anomalous bias...")
    raw_df = generate_synthetic_stream(n_samples=batch_size, attack_ratio=attack_ratio)
    
    status_box.info("Feeding records into SOC Threat Pipeline (Classifier + Anomaly + Geo + ATT&CK + Risk)...")
    
    start_time = time.time()
    scored_events = run_pipeline(raw_df)
    elapsed = time.time() - start_time

    # Inject into session state / pipeline active buffer
    delay = 0.0
    if sim_speed == "Gradual (100ms delay)":
        delay = 0.1
    elif sim_speed == "Real-time (300ms delay)":
        delay = 0.3

    for idx, evt in enumerate(scored_events):
        append_event(evt)
        progress_bar.progress((idx + 1) / len(scored_events))
        if delay > 0:
            time.sleep(delay)

    progress_bar.empty()
    status_box.success(f"Simulation completed! Processed {len(scored_events)} events in {elapsed:.3f}s ({len(scored_events)/max(elapsed, 0.001):.1f} eps).")

    # Metrics summary
    scored_df = pd.DataFrame(scored_events)
    m1, m2, m3, m4 = st.columns(4)
    with m1:
        st.metric("Total Simulated", len(scored_df))
    with m2:
        crits = (scored_df["risk_level"] == "CRITICAL").sum()
        st.metric("Critical Alerts", crits)
    with m3:
        highs = (scored_df["risk_level"] == "HIGH").sum()
        st.metric("High Alerts", highs)
    with m4:
        avg_risk = scored_df["risk_score"].mean()
        st.metric("Avg Risk Score", f"{avg_risk:.1f}/100")

    st.markdown("---")
    st.subheader("📋 Generated Batch Event Stream (Top 20)")
    cols_to_show = ["id", "timestamp", "src_ip", "dst_ip", "attack_type", "ml_prob", "anomaly_score", "mitre_id", "risk_score", "risk_level"]
    st.dataframe(scored_df[cols_to_show].head(20), use_container_width=True)
