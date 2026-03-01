"""
Jorise v2 - Predictor
Carga un TrainedModel desde la BD y ejecuta predicciones sobre:
  - Un archivo PCAP  → extrae flujos → alinea features → predict
  - Un DataFrame     → alinea features → predict
  - Un CSV           → carga con csv_loader → predict

Devuelve siempre una lista de dicts con el flujo + etiqueta predicha.
"""

import logging
import io
import numpy as np
import pandas as pd
import joblib

logger = logging.getLogger(__name__)

# Etiquetas legibles para modelos no supervisados (Isolation Forest)
_IF_LABELS = {1: 'BENIGN', -1: 'ATTACK'}


def _load_artifacts(trained_model) -> tuple:
    """Carga modelo y scaler desde sus FileFields."""
    model_bytes  = trained_model.model_file.read()
    model        = joblib.load(io.BytesIO(model_bytes))

    scaler = None
    if trained_model.scaler_file:
        scaler_bytes = trained_model.scaler_file.read()
        scaler       = joblib.load(io.BytesIO(scaler_bytes))

    return model, scaler


def predict_dataframe(
    df: pd.DataFrame,
    trained_model,
    progress_callback=None,
) -> pd.DataFrame:
    """
    Predice sobre un DataFrame ya construido.

    Args:
        df:            DataFrame con features (puede tener columnas extra).
        trained_model: Instancia de TrainedModel.

    Returns:
        El mismo DataFrame con columnas añadidas:
          - 'prediction'     : 0 = benigno, 1 = ataque  (o 1/-1 en Isolation Forest)
          - 'label'          : 'BENIGN' / 'ATTACK'
          - 'confidence'     : probabilidad de la clase predicha (si disponible)
    """
    from training.pcap_extractor import align_to_model_features

    def _log(msg):
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    features = trained_model.features_json
    _log(f"Alineando {len(df)} filas a {len(features)} features…")
    X = align_to_model_features(df, features)

    model, scaler = _load_artifacts(trained_model)

    if scaler is not None:
        X_scaled = scaler.transform(X)
    else:
        X_scaled = X.values

    _log(f"Ejecutando predicción con {type(model).__name__}…")
    preds = model.predict(X_scaled)

    # Intentar obtener probabilidades
    confidence = np.full(len(preds), 0.5)
    try:
        if hasattr(model, 'predict_proba'):
            proba = model.predict_proba(X_scaled)
            confidence = proba.max(axis=1)
        elif hasattr(model, 'decision_function'):
            scores = model.decision_function(X_scaled)
            # Normalizar a [0,1]
            s_min, s_max = scores.min(), scores.max()
            if s_max > s_min:
                confidence = (scores - s_min) / (s_max - s_min)
    except Exception:
        pass

    result = df.copy()

    # Isolation Forest: 1 = normal, -1 = anomalía → convertir a 0/1
    is_if = (type(model).__name__ == 'IsolationForest')
    if is_if:
        result['prediction'] = np.where(np.array(preds) == -1, 1, 0)
        result['label']      = [_IF_LABELS[p] for p in preds]
    else:
        result['prediction'] = preds
        result['label']      = ['BENIGN' if p == 0 else 'ATTACK' for p in preds]

    result['confidence'] = np.round(confidence, 4)

    n_attack = int(result['prediction'].sum())
    _log(f"Resultado: {n_attack} ataques / {len(result)} flujos ({n_attack/len(result)*100:.1f}%)")
    return result


def predict_pcap(
    pcap_path: str,
    trained_model,
    max_packets: int = 500_000,
    progress_callback=None,
) -> pd.DataFrame:
    """
    End-to-end: PCAP → flujos → alineación → predicción.

    Returns DataFrame con columnas de metadatos (src_ip, dst_ip, etc.) + prediction + label.
    """
    from training.pcap_extractor import extract_features_from_pcap

    def _log(msg):
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    _log(f"Extrayendo flujos de {pcap_path}…")
    df = extract_features_from_pcap(pcap_path, max_packets=max_packets,
                                     progress_callback=progress_callback)
    if df.empty:
        raise ValueError("El PCAP no generó flujos utilizables.")

    return predict_dataframe(df, trained_model, progress_callback)


def predict_csv(
    csv_path: str,
    trained_model,
    progress_callback=None,
) -> pd.DataFrame:
    """
    End-to-end: CSV CIC-IDS2017 → predicción.
    Preserva la columna Label original para comparar con la predicción.
    """
    from training.csv_loader import load_cicids_csv

    def _log(msg):
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    X, y, features = load_cicids_csv(csv_path, progress_callback=progress_callback)

    result = predict_dataframe(X, trained_model, progress_callback)

    if y is not None:
        result['true_label'] = y.values

    return result


def get_prediction_summary(result_df: pd.DataFrame) -> dict:
    """Resumen estadístico de una corrida de predicción."""
    total   = len(result_df)
    attacks = int(result_df['prediction'].sum())
    benign  = total - attacks

    summary = {
        'total_flows':   total,
        'benign':        benign,
        'attacks':       attacks,
        'attack_pct':    round(attacks / total * 100, 2) if total else 0,
        'avg_confidence': round(float(result_df['confidence'].mean()), 4),
    }

    # Si hay etiqueta real, calcular métricas básicas
    if 'true_label' in result_df.columns:
        from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
        y_true = result_df['true_label'].astype(int)
        y_pred = result_df['prediction'].astype(int)
        summary['accuracy'] = round(accuracy_score(y_true, y_pred), 4)
        summary['f1']       = round(f1_score(y_true, y_pred, zero_division=0), 4)
        cm = confusion_matrix(y_true, y_pred).tolist()
        summary['confusion_matrix'] = cm

    return summary
