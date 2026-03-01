"""
Jorise v2 - Evaluator
Evalúa un TrainedModel con métricas exhaustivas sobre un CSV etiquetado o PCAP.

Genera:
  - Accuracy, Precision, Recall, F1 (macro y binario)
  - ROC-AUC
  - Confusion Matrix
  - Métricas por tipo de ataque (multiclase, si el CSV tiene etiquetas detalladas)
  - Reporte serializable a JSON para guardar en TrainingJob.report_json
"""

import logging
import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, confusion_matrix, classification_report,
    average_precision_score,
)

logger = logging.getLogger(__name__)


def evaluate_with_csv(
    csv_path: str,
    trained_model,
    sample_size: int | None = None,
    progress_callback=None,
) -> dict:
    """
    Evalúa el modelo contra un CSV etiquetado (CIC-IDS2017).

    Args:
        csv_path:        Ruta al CSV con columna 'Label'
        trained_model:   Instancia de TrainedModel
        sample_size:     Si se indica, usa solo una muestra aleatoria (ej. 50_000)

    Returns:
        dict con todas las métricas, serializable a JSON.
    """
    from training.csv_loader import load_cicids_csv, get_attack_summary
    from training.predictor import predict_dataframe

    def _log(msg):
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    _log(f"Cargando CSV para evaluación: {csv_path}")
    X, y, features = load_cicids_csv(csv_path, progress_callback=progress_callback)

    if y is None:
        raise ValueError("El CSV no tiene columna 'Label' → no se puede evaluar.")

    if sample_size and len(X) > sample_size:
        _log(f"Usando muestra de {sample_size:,} filas de {len(X):,}")
        idx = np.random.choice(len(X), sample_size, replace=False)
        X = X.iloc[idx].reset_index(drop=True)
        y = y.iloc[idx].reset_index(drop=True)

    _log(f"Ejecutando predicción sobre {len(X):,} muestras…")
    result_df = predict_dataframe(X, trained_model, progress_callback)
    y_pred = result_df['prediction'].astype(int).values
    y_true = y.astype(int).values

    return _build_report(y_true, y_pred, result_df, _log)


def evaluate_with_pcap(
    pcap_path: str,
    trained_model,
    max_packets: int = 500_000,
    progress_callback=None,
) -> dict:
    """
    Evalúa el modelo sobre un PCAP (sin etiquetas → solo métricas de distribución).
    """
    from training.predictor import predict_pcap, get_prediction_summary

    def _log(msg):
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    result_df = predict_pcap(pcap_path, trained_model,
                              max_packets=max_packets,
                              progress_callback=progress_callback)
    summary = get_prediction_summary(result_df)
    _log(f"Evaluación PCAP: {summary['attacks']} ataques / {summary['total_flows']} flujos")
    return {
        'mode':          'unsupervised_pcap',
        'total_flows':   summary['total_flows'],
        'benign':        summary['benign'],
        'attacks':       summary['attacks'],
        'attack_pct':    summary['attack_pct'],
        'avg_confidence': summary['avg_confidence'],
    }


def _build_report(y_true, y_pred, result_df, _log) -> dict:
    """Construye el reporte completo de métricas."""
    acc   = float(accuracy_score(y_true, y_pred))
    prec  = float(precision_score(y_true, y_pred, zero_division=0))
    rec   = float(recall_score(y_true, y_pred, zero_division=0))
    f1    = float(f1_score(y_true, y_pred, zero_division=0))
    f1mac = float(f1_score(y_true, y_pred, average='macro', zero_division=0))

    _log(f"Accuracy: {acc:.4f} | Precision: {prec:.4f} | Recall: {rec:.4f} | F1: {f1:.4f}")

    # ROC-AUC (solo si hay probabilidades)
    roc_auc = None
    if 'confidence' in result_df.columns:
        try:
            roc_auc = float(roc_auc_score(y_true, result_df['confidence'].values))
        except Exception:
            pass

    # Confusion matrix
    cm = confusion_matrix(y_true, y_pred)
    tn, fp, fn, tp = (cm.ravel() if cm.size == 4 else (0, 0, 0, 0))

    # False positive / negative rates
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    _log(f"TP:{tp}  FP:{fp}  TN:{tn}  FN:{fn}  FPR:{fpr:.4f}  FNR:{fnr:.4f}")

    # Reporte por clase
    clf_report = classification_report(
        y_true, y_pred,
        target_names=['BENIGN', 'ATTACK'],
        output_dict=True,
        zero_division=0,
    )

    report = {
        'mode':            'supervised',
        'n_samples':       int(len(y_true)),
        'accuracy':        round(acc, 6),
        'precision':       round(prec, 6),
        'recall':          round(rec, 6),
        'f1_binary':       round(f1, 6),
        'f1_macro':        round(f1mac, 6),
        'roc_auc':         round(roc_auc, 6) if roc_auc is not None else None,
        'true_positives':  int(tp),
        'false_positives': int(fp),
        'true_negatives':  int(tn),
        'false_negatives': int(fn),
        'false_positive_rate': round(fpr, 6),
        'false_negative_rate': round(fnr, 6),
        'confusion_matrix': cm.tolist(),
        'classification_report': clf_report,
    }

    return report


def save_evaluation_to_job(job, report: dict):
    """Persiste los resultados de evaluación en un TrainingJob existente."""
    job.accuracy    = report.get('accuracy')
    job.precision   = report.get('precision')
    job.recall      = report.get('recall')
    job.f1_score    = report.get('f1_binary')
    job.report_json = report
    job.save(update_fields=['accuracy', 'precision', 'recall', 'f1_score', 'report_json'])
