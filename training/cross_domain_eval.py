"""
FASE 2 — Paso 5: Cross-Domain Evaluator
Tests generalization by training on N-1 days and testing on the held-out day.

Usage:
    from training.cross_domain_eval import run_cross_domain_eval
    results = run_cross_domain_eval(csv_dir, algorithm='xgboost', sample_per_file=15000)
"""
import os
import warnings
import numpy as np
import pandas as pd
import joblib
warnings.filterwarnings('ignore')

from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import f1_score, recall_score, precision_score, accuracy_score

from .unified_dataset import build_unified_dataset, _load_one_csv, DROP_COLS, normalize_label
from .multiclass_trainer import _build_classifier, _compute_fold_metrics, RECALL_TARGET

PASS_F1  = 0.70   # Minimum acceptable cross-domain macro F1


def run_cross_domain_eval(
    csv_dir: str,
    algorithm: str = 'xgboost',
    sample_per_file: int = 12000,
    progress_callback=None,
) -> dict:
    """
    Leave-one-day-out evaluation.
    For each CSV: train on all other CSVs, test on this one.
    Returns per-day metrics and aggregate summary.
    """
    csv_files = sorted([
        os.path.join(csv_dir, f)
        for f in os.listdir(csv_dir)
        if f.lower().endswith('.csv')
    ])
    n = len(csv_files)
    print(f"\n[CrossDomainEval] {n} CSVs, leave-one-out, algorithm={algorithm}")

    # Pre-load all CSVs once
    loaded = {}
    for i, path in enumerate(csv_files):
        fname = os.path.basename(path)
        print(f"  Pre-loading [{i+1}/{n}] {fname} ...", end=' ', flush=True)
        df = _load_one_csv(path, sample_per_file)
        if df is not None:
            loaded[path] = df
            print(f"rows={len(df):,}")
        else:
            print("SKIP")

    if len(loaded) < 2:
        raise RuntimeError("Need at least 2 valid CSVs for cross-domain evaluation.")

    results = {}

    for hold_path in list(loaded.keys()):
        hold_name = os.path.basename(hold_path)
        train_paths = [p for p in loaded if p != hold_path]

        print(f"\n  HOLD-OUT: {hold_name}")
        print(f"  Train on: {len(train_paths)} days")

        # Build train set
        train_frames = [loaded[p] for p in train_paths]
        train_df = pd.concat(train_frames, ignore_index=True)
        hold_df  = loaded[hold_path].copy()

        feat_cols = [c for c in train_df.columns
                     if c not in DROP_COLS and c not in ('_label', 'Label', 'label')]

        X_train = train_df[feat_cols].select_dtypes(include=[np.number])
        X_test  = hold_df[feat_cols].select_dtypes(include=[np.number])

        # Align columns
        for col in X_train.columns:
            if col not in X_test.columns:
                X_test[col] = 0.0
        X_test = X_test[X_train.columns]

        X_train = X_train.replace([np.inf, -np.inf], np.nan).fillna(0)
        X_test  = X_test.replace([np.inf, -np.inf], np.nan).fillna(0)

        y_train = train_df['_label']
        y_test  = hold_df['_label']

        # Encode
        le = LabelEncoder()
        le.fit(pd.concat([y_train, y_test]))
        y_tr_enc   = le.transform(y_train)
        y_test_enc = le.transform(y_test)
        classes    = le.classes_.tolist()

        # Scale
        scaler   = StandardScaler()
        X_tr_s   = scaler.fit_transform(X_train)
        X_test_s = scaler.transform(X_test)

        # Train
        clf = _build_classifier(algorithm, len(classes))
        if algorithm == 'xgboost':
            clf.fit(X_tr_s, y_tr_enc, verbose=False)
        else:
            clf.fit(X_tr_s, y_tr_enc)

        y_pred = clf.predict(X_test_s)
        metrics = _compute_fold_metrics(y_test_enc, y_pred, classes)

        passed = metrics['macro_f1'] >= PASS_F1
        flag   = '✓' if passed else '✗'
        print(f"  {flag} macro-F1={metrics['macro_f1']*100:.1f}%  "
              f"macro-Rec={metrics['macro_recall']*100:.1f}%  "
              f"Acc={metrics['accuracy']*100:.1f}%")

        for cls in classes:
            r = metrics['per_class'].get(cls, {}).get('recall', 0)
            sym = '✓' if r >= RECALL_TARGET else '✗'
            print(f"    {sym} {cls:<20} recall={r*100:.1f}%")

        results[hold_name] = {
            'metrics': metrics,
            'passed': passed,
            'train_days': [os.path.basename(p) for p in train_paths],
        }

        if progress_callback:
            pct = int(list(loaded.keys()).index(hold_path) / len(loaded) * 90)
            progress_callback(pct)

    # Summary
    passed_count = sum(1 for r in results.values() if r['passed'])
    avg_f1 = np.mean([r['metrics']['macro_f1'] for r in results.values()])
    avg_rec = np.mean([r['metrics']['macro_recall'] for r in results.values()])

    print(f"\n{'='*60}")
    print(f"  CROSS-DOMAIN SUMMARY")
    print(f"{'='*60}")
    print(f"  Days passed (F1 ≥ {PASS_F1*100:.0f}%): {passed_count}/{len(results)}")
    print(f"  Average macro F1:    {avg_f1*100:.1f}%")
    print(f"  Average macro Recall: {avg_rec*100:.1f}%")

    overall_verdict = 'GENERALIZES' if passed_count / len(results) >= 0.75 else 'OVERFITTING'
    print(f"  Verdict: {overall_verdict}")

    if progress_callback:
        progress_callback(100)

    return {
        'per_day': results,
        'avg_macro_f1': float(avg_f1),
        'avg_macro_recall': float(avg_rec),
        'pass_rate': passed_count / len(results),
        'overall_verdict': overall_verdict,
        'algorithm': algorithm,
    }
