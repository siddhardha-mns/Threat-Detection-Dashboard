# AI-Based Threat Intelligence & SOC Dashboard (Python Edition)

A production-grade Python implementation of the AI-Based Threat Intelligence Dashboard specified in the SOC Architecture Document. This repository contains the complete standalone Python machine learning, NLP, risk evaluation, and multi-page Streamlit application.

---

## 🏛️ Architecture & Shared Contracts

The platform is structured according to the modular 3-member development plan:

| Member / Role | Scope | Key Modules |
| :--- | :--- | :--- |
| **Member A (ML & Pipeline)** | NSL-KDD Ingestion, Random Forest Classifier, Isolation Forest Anomaly Detector, Rule Baseline | `src/data_loader.py`, `src/ml_engine.py`, `src/baseline.py`, `scripts/train_models.py` |
| **Member B (NLP & Risk)** | IOC Extraction (IPv4, Domains, Hashes, CVEs), TF-IDF MITRE ATT&CK Mapping, Continuous Risk Scoring | `src/nlp_engine.py`, `src/risk_engine.py`, `src/geo.py`, `scripts/build_mitre_index.py` |
| **Member C (UI & Dashboards)** | Multi-Page Streamlit SOC Dashboard, Plotly Metrics, Folium Geolocation Map | `app.py`, `pages/1_Live_Alerts.py` to `pages/7_Settings.py` |

---

## 📂 Project Directory Layout

```
threat-dashboard/
├── app.py                      # Streamlit application entrypoint & SOC Overview
├── pages/
│   ├── 1_Live_Alerts.py        # Real-time event queue, filters, and alert detail drawer
│   ├── 2_Threat_Map.py          # Global cyber threat attack map with IP geolocation & markers
│   ├── 3_ATT&CK_Coverage.py     # MITRE ATT&CK matrix heatmap and tactic density bars
│   ├── 4_Threat_Analyzer.py     # CTI report analysis, regex IOC extraction & technique vectorizer
│   ├── 5_Model_Performance.py   # Side-by-side benchmark (RF vs IF vs Baseline, ROC curves, MDI)
│   ├── 6_Simulate_Traffic.py    # Batch telemetry generator & attack injection testbed
│   └── 7_Settings.py            # Dynamic risk weights (w_ml, w_anom, w_asset, w_geo) & thresholds
├── src/
│   ├── data_loader.py           # NSL-KDD parser & synthetic network telemetry generator
│   ├── ml_engine.py             # Random Forest & Isolation Forest training and inference
│   ├── baseline.py              # Rule-based expert heuristic baseline
│   ├── nlp_engine.py            # Regex IOC parser & token-based cosine similarity MITRE mapper
│   ├── risk_engine.py           # Section 4 continuous composite risk formula & level buckets
│   ├── geo.py                   # IP geolocation resolver (MaxMind / deterministic fallback)
│   └── pipeline.py              # End-to-end telemetry ingestion & active event buffer
├── scripts/
│   ├── train_models.py          # Automated offline model training & pickle serialization
│   └── build_mitre_index.py     # MITRE techniques indexer & TF-IDF matrix builder
├── data/
│   ├── mitre/techniques.csv     # Enterprise ATT&CK catalog (15 core techniques)
│   └── reports/                 # 10 realistic threat intelligence & incident reports (.txt)
├── test_contracts.py            # Standalone unit test suite verifying Section 4 contracts
├── requirements.txt             # Python dependencies (Streamlit, Scikit-Learn, Plotly, etc.)
└── README.md                    # This documentation
```

---

## 🚀 Getting Started & Local Execution

### 1. Prerequisites
- Python 3.9, 3.10, or 3.11 installed on your workstation (`python3 --version`).
- `venv` module for isolated dependency management.

### 2. Create and Activate Virtual Environment
```bash
# Navigate to the Python dashboard folder
cd threat-dashboard

# Create virtual environment
python3 -m venv venv

# Activate on Linux/macOS:
source venv/bin/activate

# Or activate on Windows PowerShell:
# .\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 4. Verify Shared Contracts (Test Suite)
Run the unit test suite to verify risk scoring formulas, regex IOC extraction, baseline rules, and geo lookups:
```bash
python3 test_contracts.py
```
*Expected output:*
```
.....
----------------------------------------------------------------------
Ran 5 tests in 0.002s
OK
```

### 5. Train Models and Build MITRE Index
To build the TF-IDF index and train the initial detection models:
```bash
# Build MITRE ATT&CK similarity index
python3 scripts/build_mitre_index.py

# Train Random Forest and Isolation Forest models
python3 scripts/train_models.py
```
*(Note: If raw NSL-KDD files are not present in `data/nsl_kdd/KDDTrain+.txt`, the script automatically utilizes the realistic synthetic telemetry generator to train and save `models/rf_classifier.pkl` and `models/isolation_forest.pkl`).*

### 6. Launch the Streamlit Dashboard
```bash
streamlit run app.py
```
Open your browser to `http://localhost:8501`. You can navigate between all 8 pages using Streamlit's sidebar:
1. **SOC Overview** (`app.py`)
2. **Live Alerts** (`pages/1_Live_Alerts.py`)
3. **Threat Map** (`pages/2_Threat_Map.py`)
4. **ATT&CK Coverage** (`pages/3_ATT&CK_Coverage.py`)
5. **Threat Analyzer** (`pages/4_Threat_Analyzer.py`)
6. **Model Performance** (`pages/5_Model_Performance.py`)
7. **Simulate Traffic** (`pages/6_Simulate_Traffic.py`)
8. **Settings** (`pages/7_Settings.py`)

---

## 🧮 Contract Specifications (Section 4 Compliance)

### Continuous Risk Score Formula
$$\text{Risk} = (w_{ml} \cdot P_{ml} + w_{anom} \cdot S_{anom} + w_{asset} \cdot C_{asset} + w_{geo} \cdot G_{geo} + w_{ti} \cdot T_{ti}) \times 100$$
- Default weights: $w_{ml} = 0.35$, $w_{anom} = 0.20$, $w_{asset} = 0.20$, $w_{geo} = 0.15$, $w_{ti} = 0.10$.
- Risk Tiers:
  - **CRITICAL**: $\ge 80$
  - **HIGH**: $60 \le \text{Score} < 80$
  - **MEDIUM**: $40 \le \text{Score} < 60$
  - **LOW**: $< 40$

### Machine Learning Benchmark Targets (NSL-KDD)
- **Random Forest**: Precision $\ge 0.98$, Recall $\ge 0.98$, FPR $\le 0.02$, Inference $< 1.0\text{ ms}$.
- **Isolation Forest**: Zero-day anomaly detector trained on benign profiles ($y = 0$).
- **Heuristic Baseline**: Heuristic rules flagging count $> 100$, serror\_rate $> 0.5$, or src\_bytes $> 10000$.

---

## 🔄 Dual Experience: Web vs Python

You have two complementary implementations of this system:
1. **Interactive Web App (Port 3000)**: Built in React 19 + TypeScript + Express + Tailwind CSS + Google Maps Platform (with dark tactical styling, real GPS proximity tracking, and Gemini AI Threat Analyzer integration). Runs natively in this browser sandbox.
2. **Standalone Python App (`/threat-dashboard`)**: Complete Python source code with `requirements.txt`, CLI training scripts, unit tests, and multi-page Streamlit application designed for local workstations, data science notebooks, or production Python microservices.
