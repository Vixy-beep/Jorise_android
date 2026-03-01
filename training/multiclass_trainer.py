"""
FASE 1 — Pasos 2, 3, 4: Multiclass Trainer with Stratified K-Fold
+ Paso 4: Feature importance discipline

Trains ONE multiclass model on the unified dataset.
Evaluates with 5-fold stratified CV, reports macro F1 + per-class recall.

Usage:
    from training.multiclass_trainer import train_multiclass_cv
    result = train_multiclass_cv(X, y, algorithm='xgboost', n_splits=5)
"""
import os
import time
import json
import hashlib
import warnings
import numpy as np
import pandas as pd
import joblib
warnings.filterwarnings('ignore')

from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import (
    classification_report, confusion_matrix,
    f1_score, precision_score, recall_score, accuracy_score,
)
from sklearn.pipeline import Pipeline

try:
    from xgboost import XGBClassifier
    HAS_XGB = True
except ImportError:
    HAS_XGB = False
    print("WARNING: xgboost not installed. Only random_forest available.")


# ── Minimum recall target per class ──────────────────────────────────────────
RECALL_TARGET = 0.75
F1_TARGET     = 0.80


def _build_classifier(algorithm: str, n_classes: int, class_weights: dict | None = None):
    """Return an untrained classifier for the given algorithm."""
    if algorithm == 'xgboost':
        if not HAS_XGB:
            raise ImportError("xgboost not installed: pip install xgboost")
        return XGBClassifier(
            n_estimators=400,
            max_depth=8,
            learning_rate=0.08,
            subsample=0.8,
            colsample_bytree=0.8,
            use_label_encoder=False,
            eval_metric='mlogloss',
            random_state=42,
            n_jobs=-1,
            verbosity=0,
        )
    elif algorithm == 'random_forest':
        return RandomForestClassifier(
            n_estimators=300,
            max_depth=20,
            min_samples_leaf=2,
            class_weight='balanced' if class_weights is None else class_weights,
            random_state=42,
            n_jobs=-1,
        )
    else:
        raise ValueError(f"Unknown algorithm: {algorithm}. Use 'xgboost' or 'random_forest'.")


def _compute_fold_metrics(y_true: np.ndarray, y_pred: np.ndarray,
                          classes: list) -> dict:
    """Compute all metrics for one fold."""
    report = classification_report(y_true, y_pred, target_names=classes,
                                   output_dict=True, zero_division=0)
    macro_f1  = f1_score(y_true, y_pred, average='macro',  zero_division=0)
    macro_rec = recall_score(y_true, y_pred, average='macro', zero_division=0)
    macro_pre = precision_score(y_true, y_pred, average='macro', zero_division=0)
    acc       = accuracy_score(y_true, y_pred)

    per_class = {}
    for cls in classes:
        if cls in report:
            per_class[cls] = {
                'precision': report[cls]['precision'],
                'recall':    report[cls]['recall'],
                'f1':        report[cls]['f1-score'],
                'support':   int(report[cls]['support']),
            }

    cm = confusion_matrix(y_true, y_pred).tolist()

    return dict(
        accuracy=acc,
        macro_f1=macro_f1,
        macro_precision=macro_pre,
        macro_recall=macro_rec,
        per_class=per_class,
        confusion_matrix=cm,
    )


def _mean_metrics(fold_metrics: list) -> dict:
    """Average metrics across folds."""
    keys = ('accuracy', 'macro_f1', 'macro_precision', 'macro_recall')
    result = {k: float(np.mean([m[k] for m in fold_metrics])) for k in keys}
    result['std_macro_f1'] = float(np.std([m['macro_f1'] for m in fold_metrics]))

    # Average per-class
    all_classes = fold_metrics[0]['per_class'].keys()
    per_class = {}
    for cls in all_classes:
        per_class[cls] = {
            metric: float(np.mean([
                fm['per_class'].get(cls, {}).get(metric, 0)
                for fm in fold_metrics
            ]))
            for metric in ('precision', 'recall', 'f1')
        }
    result['per_class'] = per_class
    return result


def train_multiclass_cv(
    X: pd.DataFrame,
    y: pd.Series,
    algorithm: str = 'xgboost',
    n_splits: int = 5,
    save_dir: str | None = None,
    model_version: str | None = None,
    progress_callback=None,
) -> dict:
    """
    Stratified K-Fold cross-validation training.

    Returns a result dict with:
        - mean_metrics: averaged across folds
        - fold_metrics: per-fold breakdown
        - feature_importances: {feature: importance} sorted desc
        - best_model_path: path to the saved best-fold model
        - label_encoder: fitted LabelEncoder
        - passes_targets: bool
        - weak_classes: classes below RECALL_TARGET
    """
    start_time = time.time()

    # Encode labels
    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    classes = le.classes_.tolist()
    n_classes = len(classes)

    print(f"\n[MulticlassTrainer] Algorithm={algorithm}  Classes={n_classes}  Splits={n_splits}")
    print(f"  Classes: {classes}")
    print(f"  Samples: {len(X):,}  Features: {len(X.columns)}")

    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    fold_metrics = []
    fold_importances = []
    best_f1  = -1.0
    best_clf = None
    best_scaler = None

    feature_names = X.columns.tolist()
    X_arr = X.values

    for fold_idx, (train_idx, val_idx) in enumerate(skf.split(X_arr, y_enc)):
        fold_num = fold_idx + 1
        print(f"\n  → Fold {fold_num}/{n_splits}  train={len(train_idx):,}  val={len(val_idx):,}")

        X_tr, X_val = X_arr[train_idx], X_arr[val_idx]
        y_tr, y_val = y_enc[train_idx],  y_enc[val_idx]

        # Scale
        scaler = StandardScaler()
        X_tr_s = scaler.fit_transform(X_tr)
        X_val_s = scaler.transform(X_val)

        clf = _build_classifier(algorithm, n_classes)
        if algorithm == 'xgboost':
            clf.fit(X_tr_s, y_tr,
                    eval_set=[(X_val_s, y_val)],
                    verbose=False)
        else:
            clf.fit(X_tr_s, y_tr)

        y_pred = clf.predict(X_val_s)

        metrics = _compute_fold_metrics(y_val, y_pred, classes)
        fold_metrics.append(metrics)

        print(f"     Acc={metrics['accuracy']*100:.2f}%  "
              f"macro-F1={metrics['macro_f1']*100:.2f}%  "
              f"macro-Rec={metrics['macro_recall']*100:.2f}%")

        # Per-class recall
        for cls in classes:
            r = metrics['per_class'].get(cls, {}).get('recall', 0)
            flag = '✓' if r >= RECALL_TARGET else '✗'
            print(f"     {flag}  {cls:<20} recall={r*100:.1f}%")

        # Feature importances
        if hasattr(clf, 'feature_importances_'):
            imps = dict(zip(feature_names, clf.feature_importances_))
            fold_importances.append(imps)

        if metrics['macro_f1'] > best_f1:
            best_f1 = metrics['macro_f1']
            best_clf = clf
            best_scaler = scaler

        if progress_callback:
            progress_callback(50 + int(fold_num / n_splits * 40))

    # Aggregate
    mean_m = _mean_metrics(fold_metrics)

    # Feature importances — average across folds, sort desc
    if fold_importances:
        all_feats = fold_importances[0].keys()
        avg_imp = {
            f: float(np.mean([fi.get(f, 0) for fi in fold_importances]))
            for f in all_feats
        }
        sorted_imp = dict(sorted(avg_imp.items(), key=lambda x: -x[1]))
    else:
        sorted_imp = {}

    # Identify dominant features (top 5 explain > 80% of importance)
    total_imp = sum(sorted_imp.values()) or 1
    cumulative = 0
    dominant_features = []
    for feat, imp in sorted_imp.items():
        cumulative += imp / total_imp
        dominant_features.append(feat)
        if cumulative >= 0.80:
            break

    print(f"\n{'='*60}")
    print(f"  CROSS-VALIDATION SUMMARY ({n_splits} folds)")
    print(f"{'='*60}")
    print(f"  Accuracy      : {mean_m['accuracy']*100:.2f}%")
    print(f"  Macro F1      : {mean_m['macro_f1']*100:.2f}%  ±{mean_m['std_macro_f1']*100:.2f}%")
    print(f"  Macro Recall  : {mean_m['macro_recall']*100:.2f}%")
    print(f"  Macro Precision: {mean_m['macro_precision']*100:.2f}%")
    print(f"\n  Per-class (mean):")
    for cls, cm in mean_m['per_class'].items():
        flag = '✓' if cm['recall'] >= RECALL_TARGET else '✗'
        print(f"  {flag}  {cls:<20}  F1={cm['f1']*100:.1f}%  "
              f"Rec={cm['recall']*100:.1f}%  Pre={cm['precision']*100:.1f}%")

    passes = (
        mean_m['macro_f1'] >= F1_TARGET and
        all(v['recall'] >= RECALL_TARGET for v in mean_m['per_class'].values())
    )
    weak = [
        cls for cls, v in mean_m['per_class'].items()
        if v['recall'] < RECALL_TARGET
    ]

    verdict = '✓ TARGETS MET' if passes else f'✗ TARGETS NOT MET — weak classes: {weak}'
    print(f"\n  Verdict: {verdict}")
    print(f"  Target — Macro F1 ≥ {F1_TARGET*100:.0f}%,  Per-class Recall ≥ {RECALL_TARGET*100:.0f}%")

    elapsed = time.time() - start_time
    print(f"\n  Training time: {elapsed:.1f}s")

    # Save best model
    best_model_path = None
    best_scaler_path = None
    if save_dir and best_clf is not None:
        os.makedirs(save_dir, exist_ok=True)
        version = model_version or f"v{int(time.time())}"
        best_model_path  = os.path.join(save_dir, f'unified_{algorithm}_{version}.pkl')
        best_scaler_path = os.path.join(save_dir, f'unified_{algorithm}_{version}_scaler.pkl')
        le_path          = os.path.join(save_dir, f'unified_{algorithm}_{version}_le.pkl')
        joblib.dump(best_clf, best_model_path, compress=3)
        joblib.dump(best_scaler, best_scaler_path, compress=3)
        joblib.dump(le, le_path, compress=3)
        print(f"\n  Saved: {best_model_path}")
        print(f"  Saved: {best_scaler_path}")

    if progress_callback:
        progress_callback(95)

    return dict(
        algorithm=algorithm,
        n_splits=n_splits,
        classes=classes,
        n_samples=len(X),
        n_features=len(X.columns),
        mean_metrics=mean_m,
        fold_metrics=fold_metrics,
        feature_importances=sorted_imp,
        dominant_features=dominant_features,
        top10_features=list(sorted_imp.keys())[:10],
        best_model_path=best_model_path,
        best_scaler_path=best_scaler_path,
        label_encoder=le,
        passes_targets=passes,
        weak_classes=weak,
        training_time_s=elapsed,
    )


def retrain_without_dominant(
    X: pd.DataFrame,
    y: pd.Series,
    dominant_features: list,
    algorithm: str = 'xgboost',
    n_splits: int = 5,
    save_dir: str | None = None,
    model_version: str | None = None,
    progress_callback=None,
) -> dict:
    """
    FASE 1 — Paso 4: Retrain dropping top dominant features to improve generalization.
    Returns same result dict as train_multiclass_cv.
    """
    drop_top = dominant_features[:min(7, len(dominant_features))]
    print(f"\n[FeatureDiscipline] Dropping {len(drop_top)} dominant features: {drop_top}")
    X_reduced = X.drop(columns=[f for f in drop_top if f in X.columns])
    print(f"  Features: {len(X.columns)} → {len(X_reduced.columns)}")
    return train_multiclass_cv(
        X_reduced, y, algorithm=algorithm, n_splits=n_splits,
        save_dir=save_dir, model_version=model_version,
        progress_callback=progress_callback,
    )
