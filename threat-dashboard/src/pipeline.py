"""
pipeline.py - Integration Pipeline
Executes end-to-end scoring pipeline across incoming network dataframe records.
"""
import pandas as pd
import numpy as np
from src.ml_engine import predict_proba, anomaly_score
from src.risk_engine import risk_score, risk_level, SEVERITY_MAP
from src.geo import lookup_ip

def run_pipeline(df: pd.DataFrame, rf_bundle=None, iso_bundle=None) -> pd.DataFrame:
    """
    Returns the scored table with columns:
    event_id, attack_prob, anomaly_score, attack_category, severity,
    asset_criticality, risk_score, risk_level, src_ip, country, lat, lon, mitre_technique
    """
    results = df.copy()
    if 'event_id' not in results.columns:
        results['event_id'] = [f"EVT-{10000 + i}" for i in range(len(df))]

    # Default IP generation if not present in NSL-KDD raw features
    if 'src_ip' not in results.columns:
        results['src_ip'] = [f"198.51.{100 + (i % 50)}.{10 + (i % 240)}" for i in range(len(df))]

    # Model inference
    if rf_bundle is not None:
        results['attack_prob'] = predict_proba(rf_bundle, df)
    elif 'attack_prob' not in results.columns:
        results['attack_prob'] = 0.85

    if iso_bundle is not None:
        results['anomaly_score'] = anomaly_score(iso_bundle, df)
    elif 'anomaly_score' not in results.columns:
        results['anomaly_score'] = 0.75

    if 'attack_category' not in results.columns:
        results['attack_category'] = 'DoS'

    results['severity'] = results['attack_category'].map(lambda c: SEVERITY_MAP.get(c, 0.5))
    if 'asset_criticality' not in results.columns:
        results['asset_criticality'] = 0.85

    # Compute continuous risk and discrete risk level
    scores = []
    levels = []
    for _, row in results.iterrows():
        s = risk_score(row.to_dict())
        scores.append(s)
        levels.append(risk_level(s))

    results['risk_score'] = scores
    results['risk_level'] = levels

    # Geolocation lookup
    geos = [lookup_ip(str(ip)) for ip in results['src_ip']]
    results['country'] = [g['country'] for g in geos]
    results['lat'] = [g['lat'] for g in geos]
    results['lon'] = [g['lon'] for g in geos]

    if 'mitre_technique' not in results.columns:
        category_mitre_map = {
            'DoS': 'T1499 Endpoint Denial of Service',
            'Probe': 'T1046 Network Service Discovery',
            'R2L': 'T1110 Brute Force',
            'U2R': 'T1059 Command and Scripting Interpreter',
            'Normal': 'T1078 Valid Accounts'
        }
        results['mitre_technique'] = results['attack_category'].map(lambda c: category_mitre_map.get(c, 'T1059 Command and Scripting Interpreter'))

    return results
