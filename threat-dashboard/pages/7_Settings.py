"""
Streamlit Page 7: Settings
Configuration of composite risk weights, risk tier thresholds, and telemetry buffer sizes.
"""
import streamlit as st
from src.risk_engine import get_risk_config, update_risk_config

st.set_page_config(page_title="Settings - SOC Threat Intel", layout="wide")
st.title("⚙️ SOC Risk Engine & Telemetry Settings")
st.caption("Configure dynamic risk score formula weights, threshold boundaries, and alert dispatch parameters.")

cfg = get_risk_config()

st.subheader("⚖️ Composite Risk Scoring Formula Weights")
st.markdown("$$\\text{Risk} = (w_{ml} \\cdot P_{ml} + w_{anom} \\cdot S_{anom} + w_{asset} \\cdot C_{asset} + w_{geo} \\cdot G_{geo} + w_{ti} \\cdot T_{ti}) \\times 100$$")

c1, c2 = st.columns(2)
with c1:
    w_ml = st.slider("ML Classification Weight (w_ml)", 0.0, 1.0, float(cfg["weights"]["w_ml"]), 0.05)
    w_anom = st.slider("Anomaly Score Weight (w_anom)", 0.0, 1.0, float(cfg["weights"]["w_anom"]), 0.05)
    w_asset = st.slider("Asset Criticality Weight (w_asset)", 0.0, 1.0, float(cfg["weights"]["w_asset"]), 0.05)
with c2:
    w_geo = st.slider("Geo Risk Weight (w_geo)", 0.0, 1.0, float(cfg["weights"]["w_geo"]), 0.05)
    w_ti = st.slider("Threat Intel Weight (w_ti)", 0.0, 1.0, float(cfg["weights"]["w_ti"]), 0.05)

total_w = w_ml + w_anom + w_asset + w_geo + w_ti
if abs(total_w - 1.0) > 0.01:
    st.warning(f"⚠️ Current weight sum is {total_w:.2f}. Weights should ideally sum to 1.00 for calibrated 0-100 scores.")
else:
    st.success("✅ Weights correctly sum to 1.00.")

st.markdown("---")
st.subheader("🎯 Severity Level Thresholds")

t1, t2, t3 = st.columns(3)
with t1:
    crit_thresh = st.slider("Critical Threshold", min_value=70, max_value=95, value=int(cfg["thresholds"]["critical"]), step=1)
with t2:
    high_thresh = st.slider("High Threshold", min_value=50, max_value=85, value=int(cfg["thresholds"]["high"]), step=1)
with t3:
    med_thresh = st.slider("Medium Threshold", min_value=20, max_value=60, value=int(cfg["thresholds"]["medium"]), step=1)

st.markdown("---")
btn_save, btn_reset = st.columns([1, 4])
with btn_save:
    if st.button("💾 Save Settings", type="primary"):
        new_config = {
            "weights": {
                "w_ml": w_ml,
                "w_anom": w_anom,
                "w_asset": w_asset,
                "w_geo": w_geo,
                "w_ti": w_ti
            },
            "thresholds": {
                "critical": crit_thresh,
                "high": high_thresh,
                "medium": med_thresh
            }
        }
        update_risk_config(new_config)
        st.success("Risk engine configuration saved and applied to active scoring pipeline.")

with btn_reset:
    if st.button("🔄 Reset Defaults"):
        default_config = {
            "weights": {
                "w_ml": 0.35,
                "w_anom": 0.20,
                "w_asset": 0.20,
                "w_geo": 0.15,
                "w_ti": 0.10
            },
            "thresholds": {
                "critical": 80,
                "high": 60,
                "medium": 40
            }
        }
        update_risk_config(default_config)
        st.info("Settings reset to default baseline configuration.")
