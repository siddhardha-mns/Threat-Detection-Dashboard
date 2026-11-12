"""
baseline.py - Member A (ML)
Rule-based detection baseline to compare against machine learning models.
"""
from typing import Dict, Any, Tuple

def baseline_predict_single(row: Dict[str, Any]) -> Tuple[int, float]:
    """
    Evaluates a single telemetry dictionary using rule-based heuristics.
    Returns (prediction: 0 or 1, pseudo_probability: float).
    """
    count = float(row.get('count', 0))
    serror_rate = float(row.get('serror_rate', 0.0))
    src_bytes = float(row.get('src_bytes', 0))
    failed_logins = float(row.get('num_failed_logins', 0))

    score = 0.0
    if count > 100:
        score += 0.4
    if serror_rate > 0.5:
        score += 0.4
    if src_bytes > 10000:
        score += 0.2
    if failed_logins > 3:
        score += 0.5

    prob = min(1.0, score)
    pred = 1 if prob >= 0.5 else 0
    return pred, round(prob, 2)

def baseline_predict(df) -> Any:
    """
    Flags attack if count > 100 OR src_bytes > 10000 OR serror_rate > 0.5.
    Returns array of 0 or 1.
    """
    try:
        import numpy as np
        rule1 = df['count'] > 100
        rule2 = df['src_bytes'] > 10000
        rule3 = df['serror_rate'] > 0.5
        flags = (rule1 | rule2 | rule3).astype(int).values
        return flags
    except Exception:
        # Fallback if pandas/numpy not available in standard python
        results = []
        for _, row in df.iterrows():
            pred, _ = baseline_predict_single(dict(row))
            results.append(pred)
        return results
