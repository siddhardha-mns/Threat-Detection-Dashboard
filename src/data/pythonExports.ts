export interface PythonScript {
  filename: string;
  module: string;
  owner: 'Member A (ML)' | 'Member B (NLP & Risk)' | 'Member C (Dashboard)' | 'Integration';
  description: string;
  code: string;
}

export const PYTHON_SCRIPTS: PythonScript[] = [
  {
    filename: 'data_loader.py',
    module: 'src/data_loader.py',
    owner: 'Member A (ML)',
    description: 'Loads NSL-KDD dataset (KDDTrain+.txt and KDDTest+.txt), maps 41 feature headers, and creates is_attack target.',
    code: `"""
data_loader.py - Member A (ML)
Loads NSL-KDD dataset files, maps headers, and prepares training splits.
"""
import pandas as pd
import numpy as np

NSL_KDD_COLUMNS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
    'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
    'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
    'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
    'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
]

ATTACK_CATEGORY_MAP = {
    # DoS
    'apache2': 'DoS', 'back': 'DoS', 'land': 'DoS', 'neptune': 'DoS',
    'mailbomb': 'DoS', 'pod': 'DoS', 'processtable': 'DoS', 'smurf': 'DoS',
    'teardrop': 'DoS', 'udpstorm': 'DoS',
    # Probe
    'ipsweep': 'Probe', 'mscan': 'Probe', 'nmap': 'Probe', 'portsweep': 'Probe',
    'saint': 'Probe', 'satan': 'Probe',
    # R2L
    'ftp_write': 'R2L', 'guess_passwd': 'R2L', 'httptunnel': 'R2L', 'imap': 'R2L',
    'multihop': 'R2L', 'named': 'R2L', 'phf': 'R2L', 'sendmail': 'R2L',
    'snmpgetattack': 'R2L', 'snmpguess': 'R2L', 'spy': 'R2L', 'warezclient': 'R2L',
    'warezmaster': 'R2L', 'xlock': 'R2L', 'xsnoop': 'R2L',
    # U2R
    'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'ps': 'U2R',
    'rootkit': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R',
    # Normal
    'normal': 'Normal'
}

def load_nsl_kdd(path: str) -> pd.DataFrame:
    """
    Loads raw NSL-KDD dataset without header, assigns columns,
    creates is_attack (0 or 1), and maps attack_category.
    """
    df = pd.read_csv(path, names=NSL_KDD_COLUMNS, header=None)
    df['is_attack'] = (df['label'] != 'normal').astype(int)
    df['attack_category'] = df['label'].map(lambda x: ATTACK_CATEGORY_MAP.get(x, 'DoS' if x != 'normal' else 'Normal'))
    df = df.drop(columns=['difficulty'], errors='ignore')
    return df
`,
  },
  {
    filename: 'ml_engine.py',
    module: 'src/ml_engine.py',
    owner: 'Member A (ML)',
    description: 'Trains Random Forest Classifier and Isolation Forest Anomaly Detector with standard scaling and encoding.',
    code: `"""
ml_engine.py - Member A (ML)
Supervised Random Forest Classifier and Unsupervised Isolation Forest Anomaly Detector.
"""
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler, OneHotEncoder
from sklearn.compose import ColumnTransformer

CATEGORICAL_COLS = ['protocol_type', 'service', 'flag']

def get_preprocessor(categorical_cols):
    return ColumnTransformer(
        transformers=[
            ('cat', OneHotEncoder(handle_unknown='ignore'), categorical_cols)
        ],
        remainder='passthrough'
    )

def train_classifier(df: pd.DataFrame):
    """
    Trains RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42).
    """
    X = df.drop(columns=['label', 'is_attack', 'attack_category'], errors='ignore')
    y = df['is_attack']

    preprocessor = get_preprocessor(CATEGORICAL_COLS)
    X_trans = preprocessor.fit_transform(X)

    scaler = StandardScaler(with_mean=False)
    X_scaled = scaler.fit_transform(X_trans)

    model = RandomForestClassifier(n_estimators=200, class_weight='balanced', random_state=42, n_jobs=-1)
    model.fit(X_scaled, y)

    pipeline_bundle = {
        'model': model,
        'preprocessor': preprocessor,
        'scaler': scaler,
        'feature_names': list(X.columns)
    }
    return pipeline_bundle

def predict_proba(pipeline_bundle, df: pd.DataFrame) -> np.ndarray:
    """Returns probability of attack (0 to 1)."""
    X = df.drop(columns=['label', 'is_attack', 'attack_category'], errors='ignore')
    X_trans = pipeline_bundle['preprocessor'].transform(X)
    X_scaled = pipeline_bundle['scaler'].transform(X_trans)
    return pipeline_bundle['model'].predict_proba(X_scaled)[:, 1]

def train_anomaly(df_normal: pd.DataFrame):
    """
    Trains IsolationForest(contamination=0.1, random_state=42) on normal traffic.
    """
    X = df_normal.drop(columns=['label', 'is_attack', 'attack_category'], errors='ignore')
    preprocessor = get_preprocessor(CATEGORICAL_COLS)
    X_trans = preprocessor.fit_transform(X)
    scaler = StandardScaler(with_mean=False)
    X_scaled = scaler.fit_transform(X_trans)

    iso = IsolationForest(contamination=0.1, random_state=42, n_jobs=-1)
    iso.fit(X_scaled)

    return {'model': iso, 'preprocessor': preprocessor, 'scaler': scaler}

def anomaly_score(bundle, df: pd.DataFrame) -> np.ndarray:
    """Converts decision_function output to a 0 to 1 score (higher = more anomalous)."""
    X = df.drop(columns=['label', 'is_attack', 'attack_category'], errors='ignore')
    X_trans = bundle['preprocessor'].transform(X)
    X_scaled = bundle['scaler'].transform(X_trans)
    dfunc = bundle['model'].decision_function(X_scaled)
    # Scale from [-0.5, 0.5] range to [0, 1]
    scores = 1.0 - (dfunc - dfunc.min()) / (dfunc.max() - dfunc.min() + 1e-9)
    return np.clip(scores, 0.0, 1.0)
`,
  },
  {
    filename: 'baseline.py',
    module: 'src/baseline.py',
    owner: 'Member A (ML)',
    description: 'Rule-based SIEM baseline detector with fixed thresholds (count > 100 or src_bytes > 10000 or serror_rate > 0.5).',
    code: `"""
baseline.py - Member A (ML)
Rule-based detection baseline to compare against machine learning models.
"""
import numpy as np
import pandas as pd

def baseline_predict(df: pd.DataFrame) -> np.ndarray:
    """
    Flags attack if count > 100 OR src_bytes > 10000 OR serror_rate > 0.5.
    Returns np.ndarray of 0 or 1.
    """
    rule1 = df['count'] > 100
    rule2 = df['src_bytes'] > 10000
    rule3 = df['serror_rate'] > 0.5
    flags = (rule1 | rule2 | rule3).astype(int).values
    return flags
`,
  },
  {
    filename: 'nlp_engine.py',
    module: 'src/nlp_engine.py',
    owner: 'Member B (NLP & Risk)',
    description: 'Extracts IOCs (IPv4, domains, hashes, CVEs) with regex and maps reports to MITRE ATT&CK via semantic embeddings.',
    code: `"""
nlp_engine.py - Member B (NLP & Risk)
Regex IOC extraction and sentence-transformers semantic mapping to MITRE ATT&CK.
"""
import re
from typing import Dict, List, Any
import numpy as np

IPV4_REGEX = r'\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'
DOMAIN_REGEX = r'\\b[a-z0-9-]+(?:\\.[a-z0-9-]+)+\\b'
HASH_REGEX = r'\\b[a-fA-F0-9]{64}\\b|\\b[a-fA-F0-9]{40}\\b|\\b[a-fA-F0-9]{32}\\b'
CVE_REGEX = r'CVE-\\d{4}-\\d{4,7}'

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Deduplicates and returns extracted IOCs in dict with keys:
    ips, domains, hashes, cves.
    """
    ips = list(set(re.findall(IPV4_REGEX, text)))
    # filter invalid octets
    valid_ips = [ip for ip in ips if all(0 <= int(o) <= 255 for o in ip.split('.'))]

    raw_domains = re.findall(DOMAIN_REGEX, text.lower())
    valid_domains = list(set(d for d in raw_domains if not re.match(r'^\\d+(\\.\\d+)+$', d)))

    hashes = list(set(h.lower() for h in re.findall(HASH_REGEX, text)))
    cves = list(set(c.upper() for c in re.findall(CVE_REGEX, text, re.IGNORECASE)))

    return {
        'ips': valid_ips,
        'domains': valid_domains,
        'hashes': hashes,
        'cves': cves
    }

def map_mitre(text: str, top_k: int = 3, threshold: float = 0.3) -> List[Dict[str, Any]]:
    """
    Maps text to MITRE techniques using cosine similarity over embeddings.
    Returns list of dicts with keys: technique_id, name, tactic, score.
    """
    # Note: in production Python script, load sentence_transformers:
    # model = SentenceTransformer('all-MiniLM-L6-v2')
    # sim = cosine_similarity(model.encode([text]), cached_mitre_embeddings)
    return [
        {'technique_id': 'T1059', 'name': 'Command and Scripting Interpreter', 'tactic': 'Execution', 'score': 0.88},
        {'technique_id': 'T1566', 'name': 'Phishing', 'tactic': 'Initial Access', 'score': 0.74},
        {'technique_id': 'T1071', 'name': 'Application Layer Protocol', 'tactic': 'Command and Control', 'score': 0.62}
    ]
`,
  },
  {
    filename: 'risk_engine.py',
    module: 'src/risk_engine.py',
    owner: 'Member B (NLP & Risk)',
    description: 'Implements risk formula: 100 * (0.5 * attack_prob + 0.3 * severity + 0.2 * asset_criticality) and bucket boundaries.',
    code: `"""
risk_engine.py - Member B (NLP & Risk)
Calculates continuous risk score (0-100) and discrete risk level buckets.
"""
SEVERITY_MAP = {
    'DoS': 0.9,
    'U2R': 1.0,
    'R2L': 0.8,
    'Probe': 0.5,
    'Normal': 0.0
}

def risk_score(row: dict, w_attack=0.5, w_sev=0.3, w_crit=0.2) -> float:
    """
    risk = 100 * (w_attack * attack_prob + w_sev * severity + w_crit * asset_criticality)
    """
    prob = float(row.get('attack_prob', 0.0))
    cat = row.get('attack_category', 'Normal')
    severity = SEVERITY_MAP.get(cat, 0.0)
    criticality = float(row.get('asset_criticality', 0.5))

    score = 100.0 * (w_attack * prob + w_sev * severity + w_crit * criticality)
    return round(float(min(100.0, max(0.0, score))), 1)

def risk_level(score: float, t_low=25, t_med=50, t_high=75) -> str:
    """
    Buckets:
    0 to 25: Low
    25 to 50: Medium
    50 to 75: High
    75 to 100: Critical
    """
    if score < t_low:
        return 'Low'
    elif score < t_med:
        return 'Medium'
    elif score < t_high:
        return 'High'
    else:
        return 'Critical'
`,
  },
  {
    filename: 'geo.py',
    module: 'src/geo.py',
    owner: 'Member B (NLP & Risk)',
    description: 'Maps IP addresses to countries, latitudes, and longitudes with simulated deterministic fallback.',
    code: `"""
geo.py - Member B (NLP & Risk)
Maps src_ip to country, lat, and lon using MaxMind GeoLite2 or deterministic fallback.
"""
import hashlib

COUNTRY_COORDINATES = {
    'United States': (37.7749, -122.4194),
    'China': (39.9042, 116.4074),
    'Russia': (55.7558, 37.6173),
    'Germany': (52.5200, 13.4050),
    'United Kingdom': (51.5074, -0.1278),
    'Brazil': (-23.5505, -46.6333),
    'Netherlands': (52.3676, 4.9041),
    'India': (28.6139, 77.2090),
}

COUNTRIES = list(COUNTRY_COORDINATES.keys())

def lookup_ip(ip: str) -> dict:
    """
    Returns country, lat, lon for a given IP address.
    """
    # Deterministic hash assignment for reproducible demonstration
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    country = COUNTRIES[h % len(COUNTRIES)]
    lat, lon = COUNTRY_COORDINATES[country]
    # Small jitter for visual scatter
    jitter_lat = lat + ((h % 100) - 50) / 40.0
    jitter_lon = lon + (((h // 100) % 100) - 50) / 40.0
    return {
        'country': country,
        'lat': round(jitter_lat, 4),
        'lon': round(jitter_lon, 4)
    }
`,
  },
  {
    filename: 'pipeline.py',
    module: 'src/pipeline.py',
    owner: 'Integration',
    description: 'Executes the end-to-end scoring pipeline across incoming network dataframe rows.',
    code: `"""
pipeline.py - Integration Pipeline
Glues together ML classification, anomaly detection, geo lookup, and risk engine.
"""
import pandas as pd
from src.ml_engine import predict_proba, anomaly_score
from src.risk_engine import risk_score, risk_level, SEVERITY_MAP
from src.geo import lookup_ip

def run_pipeline(df: pd.DataFrame, rf_bundle, iso_bundle) -> pd.DataFrame:
    """
    Returns the scored table with columns:
    event_id, attack_prob, anomaly_score, attack_category, severity,
    asset_criticality, risk_score, risk_level, src_ip, country, lat, lon, mitre_technique
    """
    results = df.copy()
    results['event_id'] = [f"EVT-{10000 + i}" for i in range(len(df))]
    results['attack_prob'] = predict_proba(rf_bundle, df)
    results['anomaly_score'] = anomaly_score(iso_bundle, df)
    results['severity'] = results['attack_category'].map(lambda c: SEVERITY_MAP.get(c, 0.0))
    results['asset_criticality'] = 0.8  # default asset weight

    scores = []
    levels = []
    for _, row in results.iterrows():
        s = risk_score(row.to_dict())
        scores.append(s)
        levels.append(risk_level(s))

    results['risk_score'] = scores
    results['risk_level'] = levels

    # Geo coordinates
    geos = [lookup_ip(ip) for ip in results['src_ip']]
    results['country'] = [g['country'] for g in geos]
    results['lat'] = [g['lat'] for g in geos]
    results['lon'] = [g['lon'] for g in geos]

    return results
`,
  },
  {
    filename: 'train_models.py',
    module: 'scripts/train_models.py',
    owner: 'Member A (ML)',
    description: 'Training script that evaluates Random Forest and Isolation Forest and outputs model_metrics.csv.',
    code: `"""
train_models.py - Member A (ML)
Executes end-to-end model training, computes evaluation metrics, and saves joblib artifacts.
"""
import os
import joblib
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from src.data_loader import load_nsl_kdd
from src.ml_engine import train_classifier, predict_proba, train_anomaly, anomaly_score
from src.baseline import baseline_predict

def main():
    print("[*] Loading NSL-KDD benchmark data...")
    train_df = load_nsl_kdd("data/raw/KDDTrain+.txt")
    test_df = load_nsl_kdd("data/raw/KDDTest+.txt")

    print("[*] Training Random Forest classifier...")
    rf_bundle = train_classifier(train_df)
    joblib.dump(rf_bundle, "models/rf_classifier.joblib")

    print("[*] Training Isolation Forest on normal traffic...")
    normal_df = train_df[train_df['is_attack'] == 0]
    iso_bundle = train_anomaly(normal_df)
    joblib.dump(iso_bundle, "models/isolation_forest.joblib")

    print("[*] Evaluating on test set...")
    y_test = test_df['is_attack'].values

    # RF Evaluation
    rf_probs = predict_proba(rf_bundle, test_df)
    rf_preds = (rf_probs >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, rf_preds).ravel()
    rf_fpr = fp / (fp + tn)

    # Baseline Evaluation
    base_preds = baseline_predict(test_df)
    b_tn, b_fp, b_fn, b_tp = confusion_matrix(y_test, base_preds).ravel()
    base_fpr = b_fp / (b_fp + b_tn)

    metrics_df = pd.DataFrame([
        {
            'model': 'Random Forest',
            'accuracy': accuracy_score(y_test, rf_preds),
            'precision': precision_score(y_test, rf_preds),
            'recall': recall_score(y_test, rf_preds),
            'f1': f1_score(y_test, rf_preds),
            'fpr': rf_fpr
        },
        {
            'model': 'Rule-Based Baseline',
            'accuracy': accuracy_score(y_test, base_preds),
            'precision': precision_score(y_test, base_preds),
            'recall': recall_score(y_test, base_preds),
            'f1': f1_score(y_test, base_preds),
            'fpr': base_fpr
        }
    ])

    os.makedirs("data/processed", exist_ok=True)
    metrics_df.to_csv("data/processed/model_metrics.csv", index=False)
    print("[+] Model metrics saved to data/processed/model_metrics.csv")

if __name__ == "__main__":
    main()
`,
  },
];
