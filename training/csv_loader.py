"""
Jorise v2 - Loader para CSVs del dataset CIC-IDS2017
Los CSV ya tienen ~80 features pre-calculadas por CICFlowMeter.
No necesitamos extracción manual: cargamos, limpiamos y entrenamos.
"""

import logging
import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

LABEL_COLUMN = ' Label'

# Features numéricas del CIC-IDS2017 que usaremos
CICIDS_FEATURES = [
    ' Flow Duration',
    ' Total Fwd Packets', ' Total Backward Packets',
    ' Total Length of Fwd Packets', ' Total Length of Bwd Packets',
    ' Fwd Packet Length Max', ' Fwd Packet Length Min',
    ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
    ' Bwd Packet Length Max', ' Bwd Packet Length Min',
    ' Bwd Packet Length Mean', ' Bwd Packet Length Std',
    ' Flow Bytes/s', ' Flow Packets/s',
    ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min',
    ' Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std', ' Fwd IAT Max', ' Fwd IAT Min',
    ' Bwd IAT Total', ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min',
    ' Fwd PSH Flags', ' Bwd PSH Flags',
    ' Fwd Header Length', ' Bwd Header Length',
    ' Fwd Packets/s', ' Bwd Packets/s',
    ' Min Packet Length', ' Max Packet Length',
    ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
    ' FIN Flag Count', ' SYN Flag Count', ' RST Flag Count',
    ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count', ' CWE Flag Count',
    ' ECE Flag Count', ' Down/Up Ratio',
    ' Average Packet Size', ' Avg Fwd Segment Size', ' Avg Bwd Segment Size',
    ' Fwd Header Length.1',
    ' Subflow Fwd Packets', ' Subflow Fwd Bytes',
    ' Subflow Bwd Packets', ' Subflow Bwd Bytes',
    'Init_Win_bytes_forward', 'Init_Win_bytes_backward',
    ' act_data_pkt_fwd', ' min_seg_size_forward',
    'Active Mean', 'Active Std', 'Active Max', 'Active Min',
    'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min',
]

# Etiquetas que consideramos BENIGNAS en el CIC-IDS2017
BENIGN_LABELS = {'benign', 'normal', '0', 'legitimate'}


def load_cicids_csv(
    csv_path: str,
    progress_callback=None,
) -> tuple[pd.DataFrame, pd.Series | None, list[str]]:
    """
    Carga un CSV del CIC-IDS2017 y devuelve (X, y, feature_cols).

    - X:            DataFrame limpio con features numéricas
    - y:            Serie binaria (0=benigno, 1=ataque), o None si no hay Label
    - feature_cols: lista de columnas usadas como features
    """
    def _log(msg):
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    _log(f"Cargando CSV: {csv_path}")
    df = pd.read_csv(csv_path, low_memory=False)
    # Normalizar espacios en nombres de columna
    df.columns = [c.strip() for c in df.columns]
    _log(f"CSV cargado: {df.shape[0]:,} filas × {df.shape[1]} columnas")

    # ── Etiquetas ──────────────────────────────────────────
    label_col_raw = next(
        (c for c in df.columns if c.lower() == 'label'), None
    )
    y = None
    if label_col_raw:
        raw_labels = df[label_col_raw].astype(str).str.strip()
        label_counts = raw_labels.value_counts().to_dict()
        _log(f"Distribución de etiquetas: {label_counts}")

        y = raw_labels.apply(
            lambda v: 0 if v.lower() in BENIGN_LABELS else 1
        ).astype(int)
        n_benign = int((y == 0).sum())
        n_attack = int((y == 1).sum())
        _log(f"Binario → Benigno: {n_benign:,}  |  Ataque: {n_attack:,}")
    else:
        _log("No se encontró columna 'Label' → modo no supervisado")

    # ── Features ───────────────────────────────────────────
    # Normalizar nombres (el CSV puede tener espacios al inicio)
    cicids_stripped = [c.strip() for c in CICIDS_FEATURES]
    available = [c for c in df.columns if c.strip() in cicids_stripped and c != label_col_raw]

    # Si no coincide ninguna feature conocida, usar todas las numéricas
    if not available:
        _log("No se reconocieron features CIC-IDS2017 → usando todas las columnas numéricas")
        available = [
            c for c in df.columns
            if c != label_col_raw and pd.api.types.is_numeric_dtype(df[c])
        ]

    _log(f"Features seleccionadas: {len(available)}")

    X = df[available].copy()

    # ── Limpieza ───────────────────────────────────────────
    # El CIC-IDS2017 tiene Infinity y NaN frecuentemente
    X.replace([np.inf, -np.inf], np.nan, inplace=True)
    for col in X.columns:
        X[col] = pd.to_numeric(X[col], errors='coerce')
    X.fillna(0, inplace=True)

    _log(f"Dataset limpio: {X.shape[0]:,} muestras × {X.shape[1]} features")
    return X, y, list(X.columns)


def get_attack_summary(y_raw: pd.Series) -> dict:
    """Devuelve conteo por tipo de ataque para estadísticas."""
    counts = y_raw.value_counts().to_dict()
    return {
        'counts':       counts,
        'n_classes':    len(counts),
        'attack_types': [k for k in counts if k.lower() not in BENIGN_LABELS],
    }
