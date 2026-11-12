"""
pages/1_Live_Alerts.py - Member C
Live alerts working queue with sortable table, detail panel, and CSV export.
"""
import streamlit as st
import pandas as pd
import os

st.set_page_config(page_title="Live Alerts - Threat SOC", page_icon="🚨", layout="wide")
st.title("🚨 Live Alerts Working Queue")

csv_path = "data/processed/scored_events.csv"
if not os.path.exists(csv_path):
    st.warning("scored_events.csv not found. Running baseline pipeline...")
    # Trigger fallback load
    import app
    df = app.load_data()
else:
    df = pd.read_csv(csv_path)

search_term = st.text_input("🔍 Search IP, Asset, Category, or MITRE Technique", "")
if search_term:
    df = df[
        df['src_ip'].astype(str).str.contains(search_term, case=False) |
        df['destination_asset'].astype(str).str.contains(search_term, case=False) |
        df['attack_category'].astype(str).str.contains(search_term, case=False) |
        df['mitre_technique'].astype(str).str.contains(search_term, case=False)
    ]

# Download button for filtered alerts as CSV (Section 7 Page 2 requirement)
csv_data = df.to_csv(index=False).encode('utf-8')
st.download_button(
    label="📥 Download Filtered Alerts as CSV",
    data=csv_data,
    file_name="filtered_alerts.csv",
    mime="text/csv"
)

# Display sortable alerts table
st.dataframe(
    df[['event_id', 'src_ip', 'destination_asset', 'attack_category', 'risk_score', 'risk_level', 'mitre_technique', 'time']],
    use_container_width=True
)

# Row detail panel (Section 7 Page 2 requirement)
st.subheader("Event Detail Inspection Panel")
selected_event_id = st.selectbox("Select Event ID to inspect model inference & raw features:", df['event_id'].tolist())

if selected_event_id:
    row = df[df['event_id'] == selected_event_id].iloc[0]
    c1, c2, c3 = st.columns(3)
    c1.metric("Supervised Attack Probability", f"{round(row['attack_prob'] * 100, 1)}%")
    c2.metric("Isolation Forest Outlier Score", f"{row['anomaly_score']}")
    c3.metric("Continuous Risk Score", f"{row['risk_score']} / 100 ({row['risk_level']})")
    
    st.info(f"**Recommended SOC Action**: {'Block source IP at edge perimeter firewall & drop active sessions' if row['risk_level'] == 'Critical' else 'Isolate host, reset credentials, and monitor SIEM telemetry'}")
    st.json(row.to_dict())
