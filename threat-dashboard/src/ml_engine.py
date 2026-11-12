"""
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

def get_preprocessor(categorical_cols=CATEGORICAL_COLS):
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
