"""
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
    train_path = "data/raw/KDDTrain+.txt"
    test_path = "data/raw/KDDTest+.txt"

    if not os.path.exists(train_path) or not os.path.exists(test_path):
        print(f"[!] Warning: {train_path} not found. Please download NSL-KDD dataset to data/raw/.")
        print("[*] Generating synthetic benchmark baseline for demo training...")
        os.makedirs("data/raw", exist_ok=True)
        # Create minimal representative dataset if not present
        from sklearn.datasets import make_classification
        X, y = make_classification(n_samples=1000, n_features=41, random_state=42)
        cols = [f"f_{i}" for i in range(41)]
        df_dummy = pd.DataFrame(X, columns=cols)
        df_dummy['protocol_type'] = 'tcp'
        df_dummy['service'] = 'http'
        df_dummy['flag'] = 'SF'
        df_dummy['src_bytes'] = 1200
        df_dummy['dst_bytes'] = 2400
        df_dummy['count'] = 12
        df_dummy['serror_rate'] = 0.05
        df_dummy['is_attack'] = y
        df_dummy['attack_category'] = ['DoS' if yi == 1 else 'Normal' for yi in y]
        train_df = df_dummy
        test_df = df_dummy
    else:
        train_df = load_nsl_kdd(train_path)
        test_df = load_nsl_kdd(test_path)

    os.makedirs("models", exist_ok=True)
    os.makedirs("data/processed", exist_ok=True)

    print("[*] Training Random Forest classifier (n_estimators=200)...")
    rf_bundle = train_classifier(train_df)
    joblib.dump(rf_bundle, "models/rf_classifier.joblib")
    print("[+] Random Forest model saved to models/rf_classifier.joblib")

    print("[*] Training Isolation Forest on normal traffic (contamination=0.1)...")
    normal_df = train_df[train_df['is_attack'] == 0]
    iso_bundle = train_anomaly(normal_df)
    joblib.dump(iso_bundle, "models/isolation_forest.joblib")
    print("[+] Isolation Forest model saved to models/isolation_forest.joblib")

    print("[*] Evaluating on test set...")
    y_test = test_df['is_attack'].values

    # RF Evaluation
    rf_probs = predict_proba(rf_bundle, test_df)
    rf_preds = (rf_probs >= 0.5).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_test, rf_preds).ravel()
    rf_fpr = fp / (fp + tn + 1e-9)

    # Baseline Evaluation
    base_preds = baseline_predict(test_df)
    b_tn, b_fp, b_fn, b_tp = confusion_matrix(y_test, base_preds).ravel()
    base_fpr = b_fp / (b_fp + b_tn + 1e-9)

    metrics_df = pd.DataFrame([
        {
            'model': 'Random Forest',
            'accuracy': round(accuracy_score(y_test, rf_preds), 4),
            'precision': round(precision_score(y_test, rf_preds, zero_division=0), 4),
            'recall': round(recall_score(y_test, rf_preds, zero_division=0), 4),
            'f1': round(f1_score(y_test, rf_preds, zero_division=0), 4),
            'fpr': round(rf_fpr, 4)
        },
        {
            'model': 'Rule-Based Baseline',
            'accuracy': round(accuracy_score(y_test, base_preds), 4),
            'precision': round(precision_score(y_test, base_preds, zero_division=0), 4),
            'recall': round(recall_score(y_test, base_preds, zero_division=0), 4),
            'f1': round(f1_score(y_test, base_preds, zero_division=0), 4),
            'fpr': round(base_fpr, 4)
        }
    ])

    metrics_df.to_csv("data/processed/model_metrics.csv", index=False)
    print("[+] Model metrics saved to data/processed/model_metrics.csv:")
    print(metrics_df)

if __name__ == "__main__":
    main()
