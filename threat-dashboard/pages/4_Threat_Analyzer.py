"""
Streamlit Page 4: Threat Analyzer
NLP IOC extraction, regex parsing, and semantic MITRE ATT&CK technique mapping.
"""
import streamlit as st
import os
import glob
from src.nlp_engine import extract_iocs, map_mitre, score_report_text
import pandas as pd

st.set_page_config(page_title="Threat Analyzer - SOC Threat Intel", layout="wide")
st.title("🔬 CTI Threat Analyzer (NLP & IOC Extraction)")
st.caption("Paste unstructured threat reports, OSINT feeds, or forensic notes to extract indicators and map adversary techniques.")

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "reports")

# Load sample reports list
sample_files = sorted(glob.glob(os.path.join(REPORTS_DIR, "*.txt")))
sample_options = {"-- Select a sample report --": ""}
for fpath in sample_files:
    fname = os.path.basename(fpath)
    sample_options[fname] = fpath

col_sample, col_thresh = st.columns([3, 1])
with col_sample:
    selected_sample = st.selectbox("Load Sample Incident Report", list(sample_options.keys()))
with col_thresh:
    sim_threshold = st.slider("Similarity Threshold", min_value=0.05, max_value=0.50, value=0.15, step=0.01)

initial_text = ""
if selected_sample and selected_sample != "-- Select a sample report --":
    with open(sample_options[selected_sample], "r", encoding="utf-8") as f:
        initial_text = f.read()

report_text = st.text_area(
    "Threat Report Text (Raw)",
    value=initial_text,
    height=260,
    placeholder="Paste incident narrative, C2 report, malware analysis, or firewall dump..."
)

if st.button("🚀 Analyze Threat Report", type="primary"):
    if not report_text.strip():
        st.warning("Please enter or load report text to analyze.")
    else:
        with st.spinner("Extracting IOCs and vectorizing MITRE techniques..."):
            iocs = extract_iocs(report_text)
            matched_techniques = map_mitre(report_text, top_k=5, threshold=sim_threshold)
            analysis = score_report_text(report_text)

        st.markdown("---")
        
        # Summary metrics
        m1, m2, m3, m4, m5 = st.columns(5)
        with m1:
            st.metric("Risk Score", f"{analysis['risk_score']}/100")
        with m2:
            st.metric("Risk Level", analysis["risk_level"])
        with m3:
            st.metric("IPs Found", len(iocs["ips"]))
        with m4:
            st.metric("Domains / Hashes", len(iocs["domains"]) + len(iocs["hashes"]))
        with m5:
            st.metric("CVEs Found", len(iocs["cves"]))

        st.markdown("### 🏷️ Extracted Indicators of Compromise (IOCs)")
        
        c_ip, c_dom, c_hash, c_cve = st.columns(4)
        with c_ip:
            st.markdown(f"**IP Addresses ({len(iocs['ips'])})**")
            if iocs["ips"]:
                for ip in iocs["ips"]:
                    st.code(ip, language="text")
            else:
                st.caption("No IP indicators identified")

        with c_dom:
            st.markdown(f"**Domains / Hostnames ({len(iocs['domains'])})**")
            if iocs["domains"]:
                for dom in iocs["domains"]:
                    st.code(dom, language="text")
            else:
                st.caption("No domain indicators identified")

        with c_hash:
            st.markdown(f"**File Hashes ({len(iocs['hashes'])})**")
            if iocs["hashes"]:
                for h in iocs["hashes"]:
                    st.code(h, language="text")
            else:
                st.caption("No hashes identified")

        with c_cve:
            st.markdown(f"**Vulnerability CVEs ({len(iocs['cves'])})**")
            if iocs["cves"]:
                for cve in iocs["cves"]:
                    st.code(cve, language="text")
            else:
                st.caption("No CVE identifiers")

        st.markdown("---")
        st.markdown("### 🎯 Mapped MITRE ATT&CK Techniques (Top Matches)")
        
        if matched_techniques:
            for item in matched_techniques:
                score_pct = int(item["similarity"] * 100)
                st.progress(item["similarity"], text=f"{item['id']} - {item['name']} ({score_pct}% confidence - {item['tactic']})")
                st.caption(f"{item.get('description', '')}")
        else:
            st.info("No MITRE techniques exceeded the cosine similarity threshold.")
