"""
Cross-file evaluation: test each model against a DIFFERENT day's data.
This is the honest generalization test — not the in-sample 80/20 split.
"""
import django, os, json, warnings
warnings.filterwarnings('ignore')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jorise.settings')
django.setup()

import numpy as np
import pandas as pd
import joblib
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report,
)
from training.models import TrainingJob, TrainedModel
from django.conf import settings

MEDIA = settings.MEDIA_ROOT

def load_csv_sample(csv_path, n=30000):
    """Load CIC-IDS2017 CSV, return X (numeric only) and y (binary: 0=BENIGN, 1=ATTACK)."""
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()

    if 'Label' not in df.columns:
        print(f"  WARNING: No 'Label' column in {os.path.basename(csv_path)}")
        return None, None, None

    label_col = df['Label'].str.strip()
    y = (label_col != 'BENIGN').astype(int)

    # Get class distribution
    dist = label_col.value_counts().to_dict()

    # Sample
    if len(df) > n:
        # Stratified sample to preserve class balance
        benign  = df[y == 0].sample(min(int(n*0.7), (y==0).sum()), random_state=42)
        attack  = df[y == 1].sample(min(int(n*0.3), (y==1).sum()), random_state=42)
        df = pd.concat([benign, attack]).sample(frac=1, random_state=42).reset_index(drop=True)
        y  = (df['Label'].str.strip() != 'BENIGN').astype(int)

    # Drop meta cols
    meta = {'Label','label','Destination Port','Flow ID','Source IP','Destination IP',
            'Source Port','Protocol','Timestamp','SimillarHTTP','Fwd Header Length.1'}
    feat_cols = [c for c in df.columns if c not in meta]

    X = df[feat_cols].copy()
    # Replace inf / NaN
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    # Keep only numeric
    X = X.select_dtypes(include=[np.number])

    return X, y, dist


def evaluate_model_on_csv(job_name, csv_path, cross_csv_path=None):
    job = TrainingJob.objects.filter(model_name=job_name, algorithm='random_forest').first()
    if not job:
        print(f"  Job not found: {job_name}")
        return

    tm = getattr(job, 'trained_model', None)
    if not tm:
        try:
            tm = job.trainedmodel
        except Exception:
            pass
    if not tm:
        print(f"  No TrainedModel for {job_name}")
        return

    model_path  = os.path.join(MEDIA, str(tm.model_file))
    scaler_path = os.path.join(MEDIA, str(tm.scaler_file))

    if not os.path.exists(model_path):
        print(f"  Model file missing: {model_path}")
        return

    clf    = joblib.load(model_path)
    scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None

    results = {}
    for label, path in [('IN-SAMPLE (own data)', csv_path), ('CROSS-FILE (other data)', cross_csv_path)]:
        if not path or not os.path.exists(path):
            continue

        X, y, dist = load_csv_sample(path, n=30000)
        if X is None:
            continue

        # Align features
        model_feats = tm.features_json
        for f in model_feats:
            if f not in X.columns:
                X[f] = 0.0
        X = X[model_feats]

        if scaler:
            try:
                X_scaled = scaler.transform(X)
            except Exception:
                X_scaled = X.values
        else:
            X_scaled = X.values

        y_pred = clf.predict(X_scaled)
        # IsolationForest returns +1/-1; RF returns class labels
        if hasattr(clf, 'classes_'):
            # classifier
            pass
        else:
            # anomaly detector: convert +1 (normal) → 0, -1 (anomaly) → 1
            y_pred = (y_pred == -1).astype(int)

        acc  = accuracy_score(y, y_pred)
        prec = precision_score(y, y_pred, zero_division=0)
        rec  = recall_score(y, y_pred, zero_division=0)
        f1   = f1_score(y, y_pred, zero_division=0)

        attack_total  = int(y.sum())
        benign_total  = int((y == 0).sum())
        attack_caught = int(((y_pred == 1) & (y == 1)).sum())
        false_pos     = int(((y_pred == 1) & (y == 0)).sum())
        fp_rate       = false_pos / benign_total if benign_total else 0

        results[label] = dict(
            acc=acc, prec=prec, rec=rec, f1=f1,
            attack_total=attack_total, attack_caught=attack_caught,
            benign_total=benign_total, false_pos=false_pos, fp_rate=fp_rate,
            classes=list(dist.items())[:6],
        )

    return results


# ─── Run ───────────────────────────────────────────────────────────────────────

BASE = os.path.join(MEDIA, 'training/datasets')

PAIRS = [
    # (job_name,  own_csv,  cross_csv)
    ('Friday-DDos-CSV',
     'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
     'Tuesday-WorkingHours.pcap_ISCX.csv'),

    ('Friday-PortScan-CSV',
     'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
     'Wednesday-workingHours.pcap_ISCX.csv'),

    ('Thursday-Morning-CSV',
     'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
     'Friday-WorkingHours-Morning.pcap_ISCX.csv'),

    ('Tuesday-CSV',
     'Tuesday-WorkingHours.pcap_ISCX.csv',
     'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv'),
]

print("\n" + "="*80)
print("REAL EVALUATION REPORT — Jorise ML Models")
print("Tested on binary task: BENIGN (0) vs ATTACK (1)")
print("="*80)

for job_name, own_csv, cross_csv in PAIRS:
    own_path   = os.path.join(BASE, own_csv)
    cross_path = os.path.join(BASE, cross_csv)

    print(f"\n{'─'*80}")
    print(f"MODEL: {job_name}")
    print(f"  Trained on : {own_csv}")
    print(f"  Cross-test : {cross_csv}")

    results = evaluate_model_on_csv(job_name, own_path, cross_path)
    if not results:
        continue

    for label, r in results.items():
        print(f"\n  [{label}]")
        print(f"    Accuracy       : {r['acc']*100:.3f}%")
        print(f"    Precision      : {r['prec']*100:.3f}%  (of flagged alerts, how many real?)")
        print(f"    Recall         : {r['rec']*100:.3f}%  (of attacks, how many caught?)")
        print(f"    F1             : {r['f1']*100:.3f}%")
        print(f"    Attacks total  : {r['attack_total']:,}  →  caught {r['attack_caught']:,}")
        print(f"    False positives: {r['false_pos']:,} / {r['benign_total']:,} benign  ({r['fp_rate']*100:.2f}% FP rate)")
        if r.get('classes'):
            print(f"    Class dist     : {r['classes']}")

print("\n" + "="*80)
print("KEY: FP rate > 1% = alert fatigue. Recall < 70% = dangerous gap.")
print("="*80)
