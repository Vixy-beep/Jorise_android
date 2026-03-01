"""
FASE 2 — Paso 6: Anomaly Layer
Trains IsolationForest ONLY on BENIGN traffic from unified dataset.
Evaluates: detection rate on attacks, FPR on benign traffic.

Paso 7: Ensemble Scorer
Combines classifier probability + anomaly score with calibrated weights.
Weights determined by grid search on validation data.

Usage:
    from training.anomaly_layer import train_anomaly_layer, EnsembleScorer
"""
import os
import warnings
import numpy as np
import pandas as pd
import joblib
warnings.filterwarnings('ignore')

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import f1_score, precision_score, recall_score
from itertools import product


# ── PASO 6: Anomaly Layer ─────────────────────────────────────────────────────

def train_anomaly_layer(
    X: pd.DataFrame,
    y: pd.Series,
    contamination: float = 0.05,
    n_estimators: int = 200,
    save_path: str | None = None,
    progress_callback=None,
) -> dict:
    """
    Train IsolationForest exclusively on BENIGN samples.
    Then evaluate:
      - FPR on held-out BENIGN (how many benign flagged as anomaly)
      - Detection rate on attacks (how many attacks flagged as anomaly)

    Returns:
        model, scaler, metrics, suggested_threshold
    """
    benign_mask  = y == 'BENIGN'
    attack_mask  = ~benign_mask

    n_benign  = int(benign_mask.sum())
    n_attack  = int(attack_mask.sum())
    print(f"\n[AnomalyLayer] BENIGN={n_benign:,}  Attacks={n_attack:,}")

    X_benign = X[benign_mask].values
    X_attack = X[attack_mask].values

    # Hold out 20% of BENIGN for evaluation
    split = int(n_benign * 0.8)
    rng   = np.random.default_rng(42)
    idx   = rng.permutation(n_benign)
    train_idx = idx[:split]
    val_idx   = idx[split:]

    X_train = X_benign[train_idx]
    X_val_b = X_benign[val_idx]

    scaler  = StandardScaler()
    X_tr_s  = scaler.fit_transform(X_train)
    X_vb_s  = scaler.transform(X_val_b)
    X_att_s = scaler.transform(X_attack)

    print(f"  Training IsolationForest (n_estimators={n_estimators}, "
          f"contamination={contamination}) ...")

    iso = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_tr_s)

    if progress_callback:
        progress_callback(60)

    # Anomaly scores: negative = more anomalous
    scores_benign = iso.score_samples(X_vb_s)   # shape (n_benign_val,)
    scores_attack = iso.score_samples(X_att_s)   # shape (n_attack,)

    # Predictions at default threshold: +1 = normal, -1 = anomaly
    pred_benign = iso.predict(X_vb_s)
    pred_attack = iso.predict(X_att_s)

    fp_rate       = float(np.mean(pred_benign == -1))   # benign classified as anomaly
    detection_rate = float(np.mean(pred_attack == -1))   # attacks classified as anomaly

    print(f"\n  Default threshold results:")
    print(f"  FPR  (benign flagged as anomaly): {fp_rate*100:.2f}%  "
          f"{'✓' if fp_rate <= 0.05 else '✗'} (target ≤ 5%)")
    print(f"  DR   (attacks flagged as anomaly): {detection_rate*100:.1f}%  "
          f"{'✓' if detection_rate >= 0.50 else '✗'} (target ≥ 50%)")

    # Find threshold that maximizes F1 for binary anomaly detection
    all_scores = np.concatenate([scores_benign, scores_attack])
    all_labels = np.concatenate([
        np.zeros(len(scores_benign)),   # 0 = benign
        np.ones(len(scores_attack)),    # 1 = attack/anomaly
    ])

    best_f1 = 0
    best_threshold = np.percentile(all_scores, contamination * 100)
    for thresh in np.percentile(all_scores, np.arange(1, 40)):
        preds = (all_scores < thresh).astype(int)
        f1 = f1_score(all_labels, preds, zero_division=0)
        if f1 > best_f1:
            best_f1 = f1
            best_threshold = thresh

    # Re-evaluate at best threshold
    pred_b2 = (scores_benign < best_threshold).astype(int)
    pred_a2 = (scores_attack < best_threshold).astype(int)
    fpr_tuned = float(np.mean(pred_b2))
    dr_tuned  = float(np.mean(pred_a2))

    print(f"\n  Tuned threshold ({best_threshold:.4f}) results:")
    print(f"  FPR  : {fpr_tuned*100:.2f}%   DR: {dr_tuned*100:.1f}%   F1: {best_f1*100:.1f}%")

    # Save
    if save_path:
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        joblib.dump({'model': iso, 'scaler': scaler,
                     'threshold': best_threshold, 'feature_names': X.columns.tolist()},
                    save_path, compress=3)
        print(f"  Saved anomaly model: {save_path}")

    if progress_callback:
        progress_callback(80)

    return {
        'model': iso,
        'scaler': scaler,
        'threshold': best_threshold,
        'feature_names': X.columns.tolist(),
        'default': {'fpr': fp_rate, 'detection_rate': detection_rate},
        'tuned':   {'fpr': fpr_tuned, 'detection_rate': dr_tuned, 'f1': best_f1},
    }


# ── PASO 7: Ensemble Scorer ────────────────────────────────────────────────────

class EnsembleScorer:
    """
    Combines:
      - P(attack) from multiclass classifier (1 - P(BENIGN))
      - Anomaly score from IsolationForest (normalized 0–1)
      - Optional: context score (0–1)

    Final score = w1 * clf_score + w2 * anomaly_score + w3 * context_score
    Weights calibrated via grid search on validation data.
    """

    def __init__(self, clf, clf_scaler, clf_le,
                 iso_model, iso_scaler, iso_threshold,
                 feature_names: list,
                 weights: tuple = (0.6, 0.4, 0.0)):
        self.clf         = clf
        self.clf_scaler  = clf_scaler
        self.clf_le      = clf_le
        self.iso_model   = iso_model
        self.iso_scaler  = iso_scaler
        self.iso_thresh  = iso_threshold
        self.feature_names = feature_names
        self.w1, self.w2, self.w3 = weights

        # Index of BENIGN class in classifier
        self.benign_idx = list(clf_le.classes_).index('BENIGN') if 'BENIGN' in clf_le.classes_ else 0

    def score(self, X: pd.DataFrame, context_scores: np.ndarray | None = None) -> dict:
        """
        Score flows. Returns:
            ensemble_score  — 0..1 (higher = more suspicious)
            clf_class       — predicted class (string)
            clf_prob        — P(attack) from classifier
            anomaly_prob    — anomaly score 0..1
        """
        # Align features
        for f in self.feature_names:
            if f not in X.columns:
                X = X.copy()
                X[f] = 0.0
        X_feat = X[self.feature_names].replace([np.inf, -np.inf], np.nan).fillna(0)

        # Classifier
        X_clf = self.clf_scaler.transform(X_feat)
        proba = self.clf.predict_proba(X_clf)
        p_benign = proba[:, self.benign_idx]
        p_attack = 1.0 - p_benign
        clf_class_idx = np.argmax(proba, axis=1)
        clf_class = self.clf_le.inverse_transform(clf_class_idx)

        # Anomaly
        X_iso = self.iso_scaler.transform(X_feat)
        raw_scores = self.iso_model.score_samples(X_iso)
        # Normalize: lower raw = more anomalous. Map to 0..1 (1 = most anomalous)
        score_min = raw_scores.min() if len(raw_scores) > 1 else raw_scores[0] - 1
        score_max = raw_scores.max() if len(raw_scores) > 1 else raw_scores[0] + 1
        anomaly_norm = 1.0 - (raw_scores - score_min) / (score_max - score_min + 1e-9)

        # Context
        if context_scores is None:
            context_scores = np.zeros(len(X))

        # Ensemble
        ensemble = self.w1 * p_attack + self.w2 * anomaly_norm + self.w3 * context_scores

        return {
            'ensemble_score': ensemble,
            'clf_class':      clf_class,
            'clf_prob_attack': p_attack,
            'anomaly_score':   anomaly_norm,
            'is_threat':       ensemble >= 0.5,
        }

    def calibrate_weights(
        self,
        X_val: pd.DataFrame,
        y_val: pd.Series,
        w1_range=(0.3, 0.4, 0.5, 0.6, 0.7),
        w2_range=(0.0, 0.2, 0.3, 0.4, 0.5),
        progress_callback=None,
    ) -> tuple:
        """
        FASE 2 — Paso 7: Grid search for optimal weights.
        Maximizes macro F1 on validation set.
        Returns best (w1, w2, w3).
        """
        y_binary = (y_val != 'BENIGN').astype(int).values
        best_f1 = 0.0
        best_weights = (self.w1, self.w2, self.w3)
        total = len(w1_range) * len(w2_range)
        checked = 0

        print(f"\n[EnsembleScorer] Calibrating weights... ({total} combinations)")
        for w1, w2 in product(w1_range, w2_range):
            if w1 + w2 > 1.01:
                continue
            w3 = 1.0 - w1 - w2
            if w3 < 0:
                continue

            self.w1, self.w2, self.w3 = w1, w2, w3
            result = self.score(X_val)
            y_pred = result['is_threat'].astype(int)
            f1 = f1_score(y_binary, y_pred, zero_division=0)

            if f1 > best_f1:
                best_f1 = f1
                best_weights = (w1, w2, w3)

            checked += 1
            if progress_callback:
                progress_callback(int(checked / total * 90))

        self.w1, self.w2, self.w3 = best_weights
        print(f"  Best weights: w1(clf)={best_weights[0]:.2f}  "
              f"w2(anomaly)={best_weights[1]:.2f}  w3(ctx)={best_weights[2]:.2f}")
        print(f"  Best F1: {best_f1*100:.2f}%")
        return best_weights

    def save(self, path: str):
        joblib.dump(self, path, compress=3)

    @staticmethod
    def load(path: str) -> 'EnsembleScorer':
        return joblib.load(path)
