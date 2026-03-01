"""
FASE 1 — Paso 1: Unified Dataset Builder
Combines all CIC-IDS2017 CSVs into a single clean dataset with canonical labels.

Usage:
    from training.unified_dataset import build_unified_dataset
    X, y, meta = build_unified_dataset(csv_dir, sample_per_file=15000)
"""
import os
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

# ── Canonical label map ───────────────────────────────────────────────────────
# Normalizes all CIC-IDS2017 label variants to 7 canonical classes.
# Keys are lowercased stripped variants found in the raw CSVs.

CANONICAL_LABELS = {
    # Benign
    'benign': 'BENIGN',

    # DDoS family
    'ddos': 'DDoS',
    'ddos attacks-loic-http': 'DDoS',
    'dos hulk': 'DoS',
    'dos goldeneye': 'DoS',
    'dos slowloris': 'DoS',
    'dos slowhttptest': 'DoS',
    'heartbleed': 'DoS',

    # PortScan
    'portscan': 'PortScan',
    'port scan': 'PortScan',

    # Brute Force
    'ftp-patator': 'BruteForce',
    'ssh-patator': 'BruteForce',
    'brute force': 'BruteForce',

    # Web attacks
    'web attack \x96 brute force': 'WebAttack',
    'web attack – brute force': 'WebAttack',
    'web attack brute force': 'WebAttack',
    'web attack \x96 xss': 'WebAttack',
    'web attack – xss': 'WebAttack',
    'web attack xss': 'WebAttack',
    'web attack \x96 sql injection': 'WebAttack',
    'web attack – sql injection': 'WebAttack',
    'web attack sql injection': 'WebAttack',

    # Infiltration
    'infiltration': 'Infiltration',

    # Bot
    'bot': 'Bot',
}

# Columns to always drop — identifiers and timestamps that leak or are useless
DROP_COLS = {
    'Flow ID', 'Source IP', 'Destination IP', 'Source Port',
    'Destination Port', 'Protocol', 'Timestamp',
    'SimillarHTTP', 'Fwd Header Length.1',
    'Label', 'label',
}

def normalize_label(raw: str) -> str:
    """Map a raw CIC-IDS2017 label to its canonical class."""
    key = str(raw).strip().lower()
    # Try exact match
    if key in CANONICAL_LABELS:
        return CANONICAL_LABELS[key]
    # Try partial match (handles encoding variants)
    for k, v in CANONICAL_LABELS.items():
        if k in key or key in k:
            return v
    # Unknown attack — treat as generic attack class
    return 'Other'


def _load_one_csv(path: str, n: int) -> pd.DataFrame | None:
    """Load one CIC-IDS2017 CSV, normalize labels, return raw DataFrame."""
    try:
        df = pd.read_csv(path, low_memory=False)
    except Exception as exc:
        print(f"    ERROR reading {os.path.basename(path)}: {exc}")
        return None

    df.columns = df.columns.str.strip()

    label_col = None
    for candidate in ('Label', 'label'):
        if candidate in df.columns:
            label_col = candidate
            break
    if label_col is None:
        print(f"    SKIP {os.path.basename(path)}: no Label column")
        return None

    df['_label'] = df[label_col].apply(normalize_label)

    # Stratified sample: preserve class distribution
    if len(df) > n:
        groups = []
        for cls, grp in df.groupby('_label'):
            frac = len(grp) / len(df)
            want = max(1, int(frac * n))
            groups.append(grp.sample(min(want, len(grp)), random_state=42))
        df = pd.concat(groups).sample(frac=1, random_state=42).reset_index(drop=True)

    return df


def build_unified_dataset(
    csv_dir: str,
    sample_per_file: int = 15000,
    drop_rare_threshold: int = 50,
    progress_callback=None,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """
    Load all CIC-IDS2017 CSVs, combine, clean, return unified dataset.

    Returns:
        X          — numeric feature DataFrame, NaN/Inf cleaned, no meta cols
        y          — canonical label Series (string class names)
        meta       — dict with: feature_names, label_counts, dropped_cols, n_samples
    """
    csv_files = sorted([
        os.path.join(csv_dir, f)
        for f in os.listdir(csv_dir)
        if f.lower().endswith('.csv')
    ])
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in {csv_dir}")

    print(f"\n[UnifiedDataset] Loading {len(csv_files)} CSVs from {csv_dir}")
    print(f"  Sample per file: {sample_per_file:,}")

    frames = []
    for i, path in enumerate(csv_files):
        fname = os.path.basename(path)
        print(f"  [{i+1}/{len(csv_files)}] {fname} ...", end=' ', flush=True)

        df = _load_one_csv(path, sample_per_file)
        if df is not None:
            print(f"rows={len(df):,}  classes={df['_label'].value_counts().to_dict()}")
            frames.append(df)

        if progress_callback:
            progress_callback(int((i + 1) / len(csv_files) * 40))

    if not frames:
        raise RuntimeError("No valid CSV files could be loaded.")

    combined = pd.concat(frames, ignore_index=True)
    print(f"\n  Combined: {len(combined):,} rows")

    # Extract labels before dropping columns
    y = combined['_label'].copy()

    # Build feature matrix
    drop_actual = DROP_COLS | {'_label'}
    feat_cols = [c for c in combined.columns if c not in drop_actual]
    X = combined[feat_cols].copy()

    # Keep only numeric columns
    X = X.select_dtypes(include=[np.number])

    # Replace Inf / NaN
    X = X.replace([np.inf, -np.inf], np.nan)
    nan_cols = X.columns[X.isna().any()].tolist()
    X = X.fillna(0)

    # Drop rare classes
    label_counts = y.value_counts()
    rare = label_counts[label_counts < drop_rare_threshold].index.tolist()
    if rare:
        print(f"  Dropping rare classes (< {drop_rare_threshold} samples): {rare}")
        mask = ~y.isin(rare)
        X = X[mask].reset_index(drop=True)
        y = y[mask].reset_index(drop=True)

    label_counts = y.value_counts().to_dict()

    print(f"\n  Final dataset: {len(X):,} rows × {len(X.columns)} features")
    print(f"  Class distribution:")
    for cls, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
        pct = cnt / len(X) * 100
        print(f"    {cls:<20} {cnt:>7,}  ({pct:.1f}%)")

    if progress_callback:
        progress_callback(50)

    meta = {
        'feature_names': X.columns.tolist(),
        'label_counts': label_counts,
        'n_samples': len(X),
        'n_features': len(X.columns),
        'classes': y.unique().tolist(),
        'nan_cols_filled': nan_cols,
    }
    return X, y, meta
