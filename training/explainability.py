"""
FASE 3 — Paso 8: SHAP Explainability
Generates top-N feature explanations per prediction using SHAP.

Usage:
    from training.explainability import explain_prediction, batch_explain
"""
import warnings
warnings.filterwarnings('ignore')
import numpy as np
import pandas as pd

try:
    import shap
    HAS_SHAP = True
except ImportError:
    HAS_SHAP = False


def explain_prediction(
    clf,
    X_row: pd.DataFrame,
    feature_names: list,
    top_n: int = 5,
    algorithm: str = 'xgboost',
) -> list[dict]:
    """
    Compute SHAP values for a single prediction row.
    Returns list of {feature, shap_value, direction} sorted by abs magnitude.

    Falls back to feature_importances_ if SHAP not available.
    """
    if not HAS_SHAP:
        # Fallback: use model's global feature importances
        if hasattr(clf, 'feature_importances_'):
            imp = clf.feature_importances_
            idx = np.argsort(imp)[::-1][:top_n]
            vals = X_row.values.flatten()
            return [
                {
                    'feature':    feature_names[i],
                    'shap_value': float(imp[i]),
                    'feature_value': float(vals[i]) if i < len(vals) else 0,
                    'direction':  'increases_risk' if float(vals[i]) > 0 else 'neutral',
                }
                for i in idx
            ]
        return []

    try:
        if algorithm == 'xgboost':
            explainer = shap.TreeExplainer(clf)
        elif algorithm == 'random_forest':
            explainer = shap.TreeExplainer(clf)
        else:
            explainer = shap.Explainer(clf, X_row)

        shap_values = explainer(X_row)   # shape: (1, n_features, n_classes) or (1, n_features)

        # Handle multi-output (multiclass): take max abs SHAP across classes
        sv = shap_values.values
        if sv.ndim == 3:
            # (samples, features, classes) -> take row 0, max abs across classes
            sv_row = sv[0]  # (features, classes)
            max_abs_sv = np.max(np.abs(sv_row), axis=1)  # (features,)
        elif sv.ndim == 2:
            sv_row = sv[0]  # (features,)
            max_abs_sv = np.abs(sv_row)
        else:
            max_abs_sv = np.abs(sv.flatten())

        top_idx = np.argsort(max_abs_sv)[::-1][:top_n]
        feat_vals = X_row.values.flatten()

        return [
            {
                'feature':       feature_names[i] if i < len(feature_names) else f'feat_{i}',
                'shap_value':    float(max_abs_sv[i]),
                'feature_value': float(feat_vals[i]) if i < len(feat_vals) else 0,
                'direction':     'increases_risk' if max_abs_sv[i] > 0 else 'decreases_risk',
            }
            for i in top_idx
        ]
    except Exception as exc:
        return [{'feature': 'shap_error', 'shap_value': 0,
                 'feature_value': 0, 'direction': 'error',
                 'detail': str(exc)}]


def format_explanation_text(top_features: list, predicted_class: str) -> str:
    """Generate a human-readable explanation string for the audit log."""
    if not top_features:
        return f"Predicted: {predicted_class}. No feature explanation available."

    parts = [f"Class: {predicted_class}."]
    parts.append("Top contributing features:")
    for i, feat in enumerate(top_features[:3], 1):
        name = feat.get('feature', '?')
        val  = feat.get('feature_value', 0)
        imp  = feat.get('shap_value', 0)
        parts.append(f"  {i}. {name} = {val:.4g}  (importance: {imp:.4g})")
    return ' '.join(parts)
