"""
pages/2_Threat_Map.py - Member C
Plotly scatter_geo threat map sized by risk score, colored by severity, and top 10 countries chart.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import os

st.set_page_config(page_title="Threat Map - Threat SOC", page_icon="🌐", layout="wide")
st.title("🌐 Geospatial Threat Map")

# Section 7 Page 3 requirement: Note on page that locations are from GeoLite2 or simulated data
st.info("ℹ️ **Data Note**: Origin geographic locations are resolved via MaxMind GeoLite2 & IP heuristics (Simulated Telemetry).")

csv_path = "data/processed/scored_events.csv"
if os.path.exists(csv_path):
    df = pd.read_csv(csv_path)
else:
    import app
    df = app.load_data()

# Ensure lat and lon exist
coords = {
    'United States': (37.77, -122.42), 'China': (39.90, 116.40),
    'Russia': (55.75, 37.61), 'Germany': (52.52, 13.40),
    'United Kingdom': (51.50, -0.12), 'Brazil': (-23.55, -46.63),
    'Netherlands': (52.36, 4.90), 'India': (28.61, 77.20)
}
if 'lat' not in df.columns:
    df['lat'] = df['country'].map(lambda c: coords.get(c, (20, 0))[0])
    df['lon'] = df['country'].map(lambda c: coords.get(c, (20, 0))[1])

# Plotly scatter_geo (Section 7 Page 3 requirement)
fig = px.scatter_geo(
    df,
    lat='lat',
    lon='lon',
    color='attack_category',
    size='risk_score',
    hover_name='src_ip',
    hover_data=['country', 'attack_category', 'risk_score', 'destination_asset'],
    projection="natural earth",
    title="Global Attack Origins Sized by Risk Score",
    color_discrete_map={'DoS': '#38bdf8', 'Probe': '#fbbf24', 'R2L': '#c084fc', 'U2R': '#fb7185', 'Normal': '#34d399'}
)
fig.update_layout(template="plotly_dark", margin=dict(l=0, r=0, t=40, b=0))
st.plotly_chart(fig, use_container_width=True)

# Bar chart of top 10 source countries (Section 7 Page 3 requirement)
st.subheader("Top Source Countries")
top_countries = df['country'].value_counts().reset_index().head(10)
top_countries.columns = ['Country', 'Alert Count']
fig_bar = px.bar(top_countries, x='Country', y='Alert Count', color='Country')
fig_bar.update_layout(template="plotly_dark", margin=dict(l=0, r=0, t=20, b=0))
st.plotly_chart(fig_bar, use_container_width=True)
