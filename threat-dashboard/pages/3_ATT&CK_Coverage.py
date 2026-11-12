"""
Streamlit Page 3: ATT&CK Coverage
Heatmap and matrix coverage of MITRE ATT&CK tactics and techniques.
"""
import streamlit as st
import pandas as pd
import os
import plotly.express as px
import plotly.graph_objects as go
from src.pipeline import get_active_events

st.set_page_config(page_title="ATT&CK Coverage - SOC Threat Intel", layout="wide")
st.title("🎯 MITRE ATT&CK Coverage Matrix")
st.caption("Visualizing detection coverage across enterprise cyber kill chain tactics and mapped adversary techniques.")

TECHNIQUES_CSV = os.path.join(os.path.dirname(__file__), "..", "data", "mitre", "techniques.csv")

@st.cache_data
def load_catalog():
    if os.path.exists(TECHNIQUES_CSV):
        return pd.read_csv(TECHNIQUES_CSV)
    return pd.DataFrame()

catalog_df = load_catalog()
events = get_active_events()

# Count mapped alerts
technique_counts = {}
for evt in events:
    tid = evt.get("mitre_id")
    if tid:
        technique_counts[tid] = technique_counts.get(tid, 0) + 1

# Merge with catalog
if not catalog_df.empty:
    catalog_df["alert_count"] = catalog_df["id"].map(lambda tid: technique_counts.get(tid, 0))
    catalog_df["detection_status"] = catalog_df["alert_count"].apply(
        lambda c: "High Activity" if c >= 5 else ("Active" if c > 0 else "Monitored")
    )
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Catalog Techniques", len(catalog_df))
    with col2:
        covered = (catalog_df["alert_count"] > 0).sum()
        st.metric("Active Detections", f"{covered} / {len(catalog_df)}")
    with col3:
        pct = (covered / len(catalog_df) * 100) if len(catalog_df) else 0
        st.metric("Coverage %", f"{pct:.1f}%")
    with col4:
        st.metric("Total Mapped Alerts", sum(technique_counts.values()))

    st.markdown("---")

    # Heatmap / Bar chart of detections by tactic
    st.subheader("📊 Detections by Enterprise Tactic")
    tactic_summary = catalog_df.groupby("tactic")["alert_count"].sum().reset_index()
    tactic_summary = tactic_summary.sort_values(by="alert_count", ascending=False)

    fig = px.bar(
        tactic_summary,
        x="tactic",
        y="alert_count",
        color="alert_count",
        color_continuous_scale="Reds",
        labels={"tactic": "MITRE Tactic", "alert_count": "Active Alerts"},
        title="Alert Density Across Tactics"
    )
    fig.update_layout(template="plotly_dark", height=350)
    st.plotly_chart(fig, use_container_width=True)

    # Coverage matrix by tactic
    st.subheader("🛡️ Enterprise ATT&CK Matrix")
    tactics = catalog_df["tactic"].unique()
    tabs = st.tabs(list(tactics))

    for tab, tactic in zip(tabs, tactics):
        with tab:
            tact_df = catalog_df[catalog_df["tactic"] == tactic]
            for _, row in tact_df.iterrows():
                badge = "🔴" if row["alert_count"] >= 5 else ("🟡" if row["alert_count"] > 0 else "⚪")
                with st.expander(f"{badge} {row['id']} - {row['name']} ({row['alert_count']} alerts)"):
                    st.write(f"**Description:** {row['description']}")
                    st.write(f"**Keywords:** `{row['keywords']}`")
                    st.write(f"**Status:** {row['detection_status']}")

    st.markdown("---")
    st.subheader("📋 Complete Technique Catalog")
    st.dataframe(catalog_df[["id", "tactic", "name", "alert_count", "detection_status", "keywords"]], use_container_width=True)
else:
    st.warning("Technique catalog not found at data/mitre/techniques.csv")
