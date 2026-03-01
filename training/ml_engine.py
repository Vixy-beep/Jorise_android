"""
Jorise v2 - Motor de Entrenamiento ML
Soporta archivos PCAP y CSV.

Flujo PCAP:
    PCAP → pcap_extractor → DataFrame de flujos sin etiqueta
    → Isolation Forest (detección de anomalías no supervisada)

Flujo CSV:
    CSV → pandas → selección de columnas numéricas
    → modelo supervisado (Random Forest, Gradient Boost, etc.)
      si hay columna de etiqueta, o Isolation Forest si no.

El modelo entrenado se serializa con joblib y se guarda como FileField.
"""

import io
import os
import logging
import tempfile
import threading
from datetime import datetime, timezone

import numpy as np
import pandas as pd
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import (
    RandomForestClassifier,
    GradientBoostingClassifier,
    IsolationForest,
    RandomForestRegressor,
)
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report,
)

logger = logging.getLogger(__name__)

# Columnas que NUNCA se usan como features (metadatos)
META_COLS = {'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'label', 'Label',
             'Attack', 'attack', 'class', 'Class', 'target', 'Target', 'category', 'Category'}


# ─────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────

def _build_classifier(algorithm: str, hyperparams: dict):
    """Instancia el clasificador sklearn según el algoritmo elegido."""
    hp = hyperparams or {}
    if algorithm == 'random_forest':
        return RandomForestClassifier(
            n_estimators=hp.get('n_estimators', 100),
            max_depth=hp.get('max_depth', None),
            random_state=42,
            n_jobs=-1,
        )
    if algorithm == 'gradient_boost':
        return GradientBoostingClassifier(
            n_estimators=hp.get('n_estimators', 100),
            learning_rate=hp.get('learning_rate', 0.1),
            max_depth=hp.get('max_depth', 3),
            random_state=42,
        )
    if algorithm == 'isolation_forest':
        return IsolationForest(
            n_estimators=hp.get('n_estimators', 100),
            contamination=hp.get('contamination', 'auto'),
            random_state=42,
            n_jobs=-1,
        )
    if algorithm == 'svm':
        return SVC(
            C=hp.get('C', 1.0),
            kernel=hp.get('kernel', 'rbf'),
            probability=True,
            random_state=42,
        )
    if algorithm == 'logistic':
        return LogisticRegression(
            C=hp.get('C', 1.0),
            max_iter=hp.get('max_iter', 1000),
            random_state=42,
            n_jobs=-1,
        )
    if algorithm == 'neural_net':
        hidden = tuple(hp.get('hidden_layer_sizes', [100, 50]))
        return MLPClassifier(
            hidden_layer_sizes=hidden,
            max_iter=hp.get('max_iter', 300),
            random_state=42,
        )
    raise ValueError(f"Algoritmo desconocido: {algorithm}")


def _select_features(df: pd.DataFrame, label_col: str | None) -> tuple[pd.DataFrame, pd.Series | None]:
    """
    Separa features (X) de etiqueta (y).
    Elimina columnas no numéricas y metadatos.
    """
    drop_cols = set(df.columns) & META_COLS
    if label_col and label_col in df.columns:
        drop_cols.discard(label_col)
        y_raw = df[label_col].astype(str).str.strip()
        # Normalizar etiquetas: todo lo que no sea 'BENIGN'/'normal'/'0' → 1
        y = y_raw.apply(lambda v: 0 if v.upper() in ('BENIGN', 'NORMAL', '0', 'LEGITIMATE') else 1)
        X = df.drop(columns=list(drop_cols | {label_col}))
    else:
        y = None
        X = df.drop(columns=list(drop_cols), errors='ignore')

    # Solo columnas numéricas
    X = X.select_dtypes(include=[np.number])
    # Rellenar NaN con 0
    X = X.fillna(0).replace([np.inf, -np.inf], 0)
    return X, y


def _detect_label_column(df: pd.DataFrame) -> str | None:
    """Busca automáticamente la columna de etiqueta en el CSV."""
    candidates = ['label', 'Label', 'Attack', 'attack', 'class', 'Class',
                  'target', 'Target', 'category', 'Category']
    for c in candidates:
        if c in df.columns:
            return c
    return None


def _compute_metrics(y_true, y_pred, is_anomaly=False) -> dict:
    """Calcula métricas de clasificación."""
    if is_anomaly:
        # Isolation Forest devuelve 1 (normal) y -1 (anomalía) → convertir a 0/1
        y_pred_bin = np.where(np.array(y_pred) == -1, 1, 0)
    else:
        y_pred_bin = np.array(y_pred)

    if y_true is None:
        return {'note': 'unsupervised', 'n_anomalies': int(np.sum(y_pred_bin == 1))}

    acc  = accuracy_score(y_true, y_pred_bin)
    prec = precision_score(y_true, y_pred_bin, zero_division=0)
    rec  = recall_score(y_true, y_pred_bin, zero_division=0)
    f1   = f1_score(y_true, y_pred_bin, zero_division=0)
    report = classification_report(y_true, y_pred_bin, output_dict=True, zero_division=0)
    return dict(accuracy=acc, precision=prec, recall=rec, f1=f1, report=report)


# ─────────────────────────────────────────────────────────
# Función principal de entrenamiento con PCAP
# ─────────────────────────────────────────────────────────

def train_from_pcap(job_id: str, pcap_path: str, algorithm: str = 'isolation_forest',
                    hyperparams: dict | None = None, progress_callback=None) -> dict:
    """
    Entrena un modelo de detección de anomalías sobre un archivo PCAP.

    Returns dict con claves:
        model_bytes, scaler_bytes, features, metrics, n_samples
    """
    from training.pcap_extractor import extract_features_from_pcap, get_feature_columns

    def _log(msg):
        logger.info(f"[Job {job_id}] {msg}")
        if progress_callback:
            progress_callback(msg)

    _log("Extrayendo features del PCAP…")
    df = extract_features_from_pcap(pcap_path, progress_callback=progress_callback)

    if df.empty:
        raise ValueError("El PCAP no generó ningún flujo utilizable.")

    feature_cols = [c for c in get_feature_columns() if c in df.columns]
    X = df[feature_cols].fillna(0).replace([np.inf, -np.inf], 0)

    _log(f"Dataset: {len(X):,} flujos × {len(feature_cols)} features")
    _log("Escalando features…")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # PCAP no tiene etiquetas → forzar Isolation Forest
    if algorithm not in ('isolation_forest',):
        _log(f"PCAP sin etiquetas → usando Isolation Forest (ignorando '{algorithm}')")
        algorithm = 'isolation_forest'

    _log(f"Entrenando {algorithm}…")
    model = _build_classifier(algorithm, hyperparams or {})
    model.fit(X_scaled)
    preds = model.predict(X_scaled)

    metrics = _compute_metrics(None, preds, is_anomaly=True)
    _log(f"Anomalías detectadas: {metrics['n_anomalies']:,} / {len(X):,}")

    # Serializar
    model_buf  = io.BytesIO(); joblib.dump(model, model_buf);  model_buf.seek(0)
    scaler_buf = io.BytesIO(); joblib.dump(scaler, scaler_buf); scaler_buf.seek(0)

    _log("Entrenamiento PCAP completado.")
    return {
        'model_bytes':  model_buf.read(),
        'scaler_bytes': scaler_buf.read(),
        'features':     feature_cols,
        'metrics':      metrics,
        'n_samples':    len(X),
        'n_normal':     int(np.sum(np.array(preds) == 1)),
        'n_attack':     int(np.sum(np.array(preds) == -1)),
    }


# ─────────────────────────────────────────────────────────
# Función principal de entrenamiento con CSV (CIC-IDS2017)
# ─────────────────────────────────────────────────────────

def train_from_csv(job_id: str, csv_path: str, algorithm: str = 'random_forest',
                   hyperparams: dict | None = None, label_col: str | None = None,
                   progress_callback=None) -> dict:
    """
    Entrena un modelo sobre un CSV del CIC-IDS2017 (o compatible).
    Usa csv_loader para manejar las ~80 features pre-calculadas y la
    columna 'Label' con tipos de ataque.

    Returns dict igual que train_from_pcap.
    """
    from training.csv_loader import load_cicids_csv

    def _log(msg):
        logger.info(f"[Job {job_id}] {msg}")
        if progress_callback:
            progress_callback(msg)

    X, y, feature_cols = load_cicids_csv(csv_path, progress_callback=progress_callback)

    if X.empty:
        raise ValueError("No se encontraron features numéricas en el CSV.")

    # Escalar
    _log("Escalando features…")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    metrics = {}
    if y is not None:
        # CSV etiquetado → entrenamiento supervisado
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        _log(f"Train: {len(X_train):,} | Test: {len(X_test):,}")
        model = _build_classifier(algorithm, hyperparams or {})
        _log(f"Entrenando {algorithm}…")
        model.fit(X_train, y_train)
        preds = model.predict(X_test)
        metrics = _compute_metrics(y_test, preds)
        _log(f"Accuracy: {metrics['accuracy']:.4f} | F1: {metrics['f1']:.4f}")
        n_normal = int(np.sum(y == 0))
        n_attack = int(np.sum(y == 1))
        used_label = 'Label'
    else:
        # Sin etiqueta → Isolation Forest
        if algorithm not in ('isolation_forest',):
            _log("Sin columna Label → forzando Isolation Forest")
            algorithm = 'isolation_forest'
        model = _build_classifier(algorithm, hyperparams or {})
        _log(f"Entrenando {algorithm}…")
        model.fit(X_scaled)
        preds = model.predict(X_scaled)
        metrics = _compute_metrics(None, preds, is_anomaly=True)
        n_normal = int(np.sum(np.array(preds) == 1))
        n_attack = int(np.sum(np.array(preds) == -1))
        used_label = ''
        _log(f"Anomalías: {n_attack:,} / {len(X):,}")

    # Serializar
    model_buf  = io.BytesIO(); joblib.dump(model, model_buf);  model_buf.seek(0)
    scaler_buf = io.BytesIO(); joblib.dump(scaler, scaler_buf); scaler_buf.seek(0)

    _log("Entrenamiento CSV completado.")
    return {
        'model_bytes':  model_buf.read(),
        'scaler_bytes': scaler_buf.read(),
        'features':     feature_cols,
        'metrics':      metrics,
        'n_samples':    len(X),
        'n_normal':     n_normal,
        'n_attack':     n_attack,
        'label_col':    used_label,
        'columns':      feature_cols,
    }


# ─────────────────────────────────────────────────────────
# Runner asíncrono que actualiza el modelo Django
# ─────────────────────────────────────────────────────────

def run_training_job(job_pk: str):
    """
    Ejecuta un TrainingJob en un hilo aparte.
    Actualiza el objeto TrainingJob y crea TrainedModel al finalizar.
    """
    import django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jorise.settings')

    from training.models import TrainingJob, TrainedModel, TrainingDataset
    from django.core.files.base import ContentFile

    try:
        job = TrainingJob.objects.select_related('dataset').get(pk=job_pk)
    except TrainingJob.DoesNotExist:
        logger.error(f"TrainingJob {job_pk} no existe.")
        return

    job.status = 'running'
    job.started_at = datetime.now(timezone.utc)
    job.save(update_fields=['status', 'started_at'])

    logs = []
    def _progress(msg):
        logs.append(msg)
        logger.info(msg)

    try:
        dataset = job.dataset
        file_path = dataset.file.path
        algo = job.algorithm
        hp   = job.hyperparams or {}

        if dataset.file_type == 'pcap':
            result = train_from_pcap(str(job.pk), file_path, algo, hp, _progress)
        else:
            result = train_from_csv(str(job.pk), file_path, algo, hp,
                                    progress_callback=_progress)

        # Actualizar dataset con estadísticas
        dataset.total_samples  = result['n_samples']
        dataset.normal_samples = result.get('n_normal', 0)
        dataset.attack_samples = result.get('n_attack', 0)
        dataset.feature_count  = len(result['features'])
        dataset.label_column   = result.get('label_col', '')
        dataset.columns_json   = result.get('columns', result['features'])
        dataset.status = 'ready'
        dataset.save()

        # Guardar métricas en el job
        m = result['metrics']
        job.accuracy  = m.get('accuracy')
        job.precision = m.get('precision')
        job.recall    = m.get('recall')
        job.f1_score  = m.get('f1')
        job.report_json = m
        job.status = 'done'
        job.finished_at = datetime.now(timezone.utc)
        job.save()

        # Crear TrainedModel
        model_filename  = f"{job.pk}_model.pkl"
        scaler_filename = f"{job.pk}_scaler.pkl"

        tm = TrainedModel(
            job=job,
            name=job.model_name,
            module='network',
            features_json=result['features'],
        )
        tm.model_file.save(model_filename,  ContentFile(result['model_bytes']),  save=False)
        tm.scaler_file.save(scaler_filename, ContentFile(result['scaler_bytes']), save=False)
        tm.save()

        _progress(f"Modelo guardado: {tm.pk}")

    except Exception as exc:
        logger.exception(f"Error en job {job_pk}: {exc}")
        job.status = 'failed'
        job.error_msg = str(exc)
        job.finished_at = datetime.now(timezone.utc)
        job.save(update_fields=['status', 'error_msg', 'finished_at'])
        dataset = job.dataset
        dataset.status = 'error'
        dataset.error_msg = str(exc)
        dataset.save(update_fields=['status', 'error_msg'])


def start_training_thread(job_pk: str):
    """Lanza run_training_job en un hilo daemon (válido sin Celery)."""
    t = threading.Thread(target=run_training_job, args=(job_pk,), daemon=True)
    t.start()
    return t
