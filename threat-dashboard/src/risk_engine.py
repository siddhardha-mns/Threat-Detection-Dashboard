"""
risk_engine.py - Member B (NLP & Risk)
Calculates continuous risk score (0-100) and discrete risk level buckets.
Supports dynamic weights configuration and composite SOC evaluation.
"""
from typing import Dict, Any

SEVERITY_MAP = {
    'DoS': 0.9,
    'U2R': 1.0,
    'R2L': 0.8,
    'Probe': 0.5,
    'Normal': 0.0
}

DEFAULT_RISK_CONFIG = {
    "weights": {
        "w_ml": 0.35,
        "w_anom": 0.20,
        "w_asset": 0.20,
        "w_geo": 0.15,
        "w_ti": 0.10
    },
    "thresholds": {
        "critical": 80.0,
        "high": 60.0,
        "medium": 40.0,
        "low": 0.0
    }
}

_active_config = {
    "weights": dict(DEFAULT_RISK_CONFIG["weights"]),
    "thresholds": dict(DEFAULT_RISK_CONFIG["thresholds"])
}

def get_risk_config() -> Dict[str, Any]:
    return _active_config

def update_risk_config(new_config: Dict[str, Any]) -> None:
    if "weights" in new_config:
        _active_config["weights"].update(new_config["weights"])
    if "thresholds" in new_config:
        _active_config["thresholds"].update(new_config["thresholds"])

def risk_score(row: Dict[str, Any], **kwargs) -> float:
    """
    Computes risk score on a 0-100 scale.
    Supports either the 3-factor spec:
      risk = 100 * (w_attack * attack_prob + w_sev * severity + w_crit * asset_criticality)
    or the full 5-factor composite:
      risk = 100 * (w_ml * P_ml + w_anom * S_anom + w_asset * C_asset + w_geo * G_geo + w_ti * T_ti)
    """
    weights = _active_config["weights"]

    # Check which style of inputs is provided
    if "ml_prob" in row or "anomaly_score" in row:
        p_ml = float(row.get("ml_prob", row.get("attack_prob", 0.0)))
        s_anom = float(row.get("anomaly_score", 0.0))
        c_asset = float(row.get("asset_criticality", 0.5))
        g_geo = float(row.get("geo_risk", 0.3))
        t_ti = float(row.get("threat_intel_match", 0.0))

        w_ml = float(kwargs.get("w_ml", weights["w_ml"]))
        w_anom = float(kwargs.get("w_anom", weights["w_anom"]))
        w_asset = float(kwargs.get("w_asset", weights["w_asset"]))
        w_geo = float(kwargs.get("w_geo", weights["w_geo"]))
        w_ti = float(kwargs.get("w_ti", weights["w_ti"]))

        score = 100.0 * (w_ml * p_ml + w_anom * s_anom + w_asset * c_asset + w_geo * g_geo + w_ti * t_ti)
    else:
        prob = float(row.get('attack_prob', 0.0))
        cat = row.get('attack_category', 'Normal')
        severity = SEVERITY_MAP.get(cat, float(row.get('severity', 0.0)))
        criticality = float(row.get('asset_criticality', 0.5))

        w_attack = float(kwargs.get("w_attack", 0.5))
        w_sev = float(kwargs.get("w_sev", 0.3))
        w_crit = float(kwargs.get("w_crit", 0.2))

        score = 100.0 * (w_attack * prob + w_sev * severity + w_crit * criticality)

    return round(float(min(100.0, max(0.0, score))), 1)

def risk_level(score: float, **kwargs) -> str:
    """
    Maps continuous score (0-100) to risk tier.
    """
    thresholds = _active_config["thresholds"]
    t_crit = float(kwargs.get("t_crit", thresholds.get("critical", 80.0)))
    t_high = float(kwargs.get("t_high", thresholds.get("high", 60.0)))
    t_med = float(kwargs.get("t_med", thresholds.get("medium", 40.0)))

    if score >= t_crit:
        return 'CRITICAL'
    elif score >= t_high:
        return 'HIGH'
    elif score >= t_med:
        return 'MEDIUM'
    else:
        return 'LOW'
