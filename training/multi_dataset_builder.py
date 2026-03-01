"""
Multi-Source Dataset Builder
Loads data from multiple public dataset directories using their adapters,
combines into a single unified DataFrame with UNIVERSAL_FEATURES.

Cross-dataset evaluation: train on dataset A, test on dataset B.
This is the honest generalization test across different data sources.

Usage:
    from training.multi_dataset_builder import build_multisource_dataset, cross_dataset_eval
"""
import os
import warnings
import numpy as np
import pandas as pd
warnings.filterwarnings('ignore')

from .dataset_adapters import (
    ADAPTERS, UNIVERSAL_FEATURES, get_adapter, _stratified_sample, normalize_label
)

# ── Expected directory structure ──────────────────────────────────────────────
# media/training/datasets/            ← CIC-IDS2017 (flat)
# media/training/datasets/unsw/       ← UNSW-NB15 CSVs
# media/training/datasets/ctu13/      ← CTU-13 binetflow CSVs
# media/training/datasets/ciciot2023/ ← CICIOT2023 part files
# media/training/datasets/jorise_lab/ ← your own captures

SUBDIR_MAP = {
    'cicids2017': '',           # flat in datasets/
    'unsw':       'unsw',
    'ctu13':      'ctu13',
    'ciciot2023': 'ciciot2023',
    'jorise_lab': 'jorise_lab',
}


def _find_csvs(base_dir: str, subdir: str) -> list[str]:
    target = os.path.join(base_dir, subdir) if subdir else base_dir
    if not os.path.isdir(target):
        return []
    return [
        os.path.join(target, f)
        for f in sorted(os.listdir(target))
        if f.lower().endswith('.csv') and os.path.isfile(os.path.join(target, f))
    ]


def build_multisource_dataset(
    base_csv_dir: str,
    sources: list[str] | None = None,
    sample_per_source: int = 20000,
    drop_rare_threshold: int = 50,
    progress_callback=None,
) -> tuple[pd.DataFrame, pd.Series, dict]:
    """
    Load data from all available sources, combine on UNIVERSAL_FEATURES.

    Args:
        base_csv_dir       : root of media/training/datasets/
        sources            : list of adapter keys to use (None = auto-detect available)
        sample_per_source  : max rows per source dataset
        drop_rare_threshold: drop classes with fewer than N samples

    Returns:
        X    — pd.DataFrame with UNIVERSAL_FEATURES columns
        y    — pd.Series of canonical label strings
        meta — dict with source breakdown, class distribution, etc.
    """
    if sources is None:
        sources = list(ADAPTERS.keys())

    frames = []
    source_meta = {}

    print(f"\n[MultiSourceBuilder] Sources to try: {sources}")
    print(f"  Sample per source: {sample_per_source:,}")
    print(f"  Universal features: {len(UNIVERSAL_FEATURES)}")

    for i, src_key in enumerate(sources):
        csvs = _find_csvs(base_csv_dir, SUBDIR_MAP.get(src_key, src_key))
        if not csvs:
            print(f"\n  [{src_key}] No CSV files found — SKIP  "
                  f"(run: python train_multisource.py --download-info for instructions)")
            continue

        adapter = get_adapter(src_key)
        print(f"\n  [{src_key}] {len(csvs)} files found")

        src_frames = []
        src_per_file = max(1000, sample_per_source // max(len(csvs), 1))

        for csv_path in csvs:
            fname = os.path.basename(csv_path)
            print(f"    Loading {fname} ...", end=' ', flush=True)
            try:
                X_part, y_part = adapter.load(csv_path, n=src_per_file)
                src_frames.append((X_part, y_part))
                dist = y_part.value_counts().to_dict()
                print(f"rows={len(X_part):,}  {dist}")
            except Exception as exc:
                print(f"ERROR: {exc}")
                continue

        if not src_frames:
            continue

        X_src = pd.concat([x for x, _ in src_frames], ignore_index=True)
        y_src = pd.concat([y for _, y in src_frames], ignore_index=True)

        # Tag the source for cross-dataset eval
        X_src['_source'] = src_key

        # Final sample from this source
        if len(X_src) > sample_per_source:
            X_src, y_src = _stratified_sample(X_src.drop(columns=['_source']), y_src, sample_per_source)
            X_src['_source'] = src_key
        else:
            # Ensure column order
            pass

        frames.append((X_src, y_src))
        source_meta[src_key] = {
            'n_rows': len(X_src),
            'classes': y_src.value_counts().to_dict(),
        }
        print(f"    → {src_key}: {len(X_src):,} rows total")

        if progress_callback:
            progress_callback(int((i + 1) / len(sources) * 40))

    if not frames:
        raise RuntimeError(
            "No data loaded from any source. "
            "Run: python train_multisource.py --download-info"
        )

    # Combine
    X_all = pd.concat([x for x, _ in frames], ignore_index=True)
    y_all = pd.concat([y for _, y in frames], ignore_index=True)

    source_col = X_all['_source'].copy()
    X_feat = X_all[UNIVERSAL_FEATURES].copy()

    # Clean
    X_feat = X_feat.replace([np.inf, -np.inf], np.nan).fillna(0)
    for col in X_feat.columns:
        X_feat[col] = X_feat[col].clip(lower=0)

    # Drop rare classes
    label_counts = y_all.value_counts()
    rare = label_counts[label_counts < drop_rare_threshold].index.tolist()
    if rare:
        print(f"\n  Dropping rare classes (< {drop_rare_threshold} samples): {rare}")
        mask = ~y_all.isin(rare)
        X_feat   = X_feat[mask].reset_index(drop=True)
        y_all    = y_all[mask].reset_index(drop=True)
        source_col = source_col[mask].reset_index(drop=True)

    label_counts = y_all.value_counts().to_dict()

    print(f"\n  COMBINED: {len(X_feat):,} rows × {len(X_feat.columns)} features")
    print(f"  Class distribution:")
    for cls, cnt in sorted(label_counts.items(), key=lambda x: -x[1]):
        pct = cnt / len(X_feat) * 100
        print(f"    {cls:<20} {cnt:>7,}  ({pct:.1f}%)")

    meta = {
        'feature_names':   UNIVERSAL_FEATURES,
        'sources':         source_meta,
        'source_col':      source_col,
        'label_counts':    label_counts,
        'n_samples':       len(X_feat),
        'n_features':      len(X_feat.columns),
        'classes':         y_all.unique().tolist(),
        'available_sources': list(source_meta.keys()),
    }

    if progress_callback:
        progress_callback(50)

    return X_feat, y_all, meta


def cross_dataset_eval(
    base_csv_dir: str,
    train_source: str,
    test_source: str,
    algorithm: str = 'xgboost',
    sample_per_source: int = 15000,
) -> dict:
    """
    The real generalization test:
    Train exclusively on `train_source`, evaluate on `test_source`.

    If F1 stays ≥ 0.70, the universal feature space generalizes.
    If it collapses, the features aren't universal enough.
    """
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    from .multiclass_trainer import _build_classifier, _compute_fold_metrics

    print(f"\n[CrossDatasetEval]  TRAIN={train_source}  →  TEST={test_source}")

    # Load train
    X_train, y_train, _ = build_multisource_dataset(
        base_csv_dir, sources=[train_source], sample_per_source=sample_per_source
    )
    # Load test
    X_test, y_test, _ = build_multisource_dataset(
        base_csv_dir, sources=[test_source], sample_per_source=sample_per_source
    )

    if len(X_train) == 0 or len(X_test) == 0:
        return {'error': f'Insufficient data for {train_source} or {test_source}'}

    # Encode labels — fit ONLY on train so XGBoost gets contiguous 0..N-1 classes.
    # For test, restrict to known train classes (generalization to shared classes).
    le = LabelEncoder()
    le.fit(y_train)
    train_classes = set(le.classes_.tolist())

    y_tr_enc = le.transform(y_train)

    # Filter test to shared classes only
    shared_mask = y_test.isin(train_classes)
    if shared_mask.sum() == 0:
        return {'error': f'No shared classes between {train_source} and {test_source}'}
    X_test   = X_test[shared_mask].reset_index(drop=True)
    y_test   = y_test[shared_mask].reset_index(drop=True)
    y_test_enc = le.transform(y_test)
    classes = le.classes_.tolist()

    scaler   = StandardScaler()
    X_tr_s   = scaler.fit_transform(X_train)
    X_test_s = scaler.transform(X_test)

    clf = _build_classifier(algorithm, len(classes))
    if algorithm == 'xgboost':
        clf.fit(X_tr_s, y_tr_enc, verbose=False)
    else:
        clf.fit(X_tr_s, y_tr_enc)

    y_pred = clf.predict(X_test_s)

    # Restrict metrics to labels actually present in the test set
    active_idx     = sorted(set(np.unique(y_test_enc)) | set(np.unique(y_pred)))
    active_classes = [classes[i] for i in active_idx]
    metrics = _compute_fold_metrics(
        np.array([active_idx.index(v) for v in y_test_enc]),
        np.array([active_idx.index(v) for v in y_pred]),
        active_classes,
    )
    metrics['tested_on_classes'] = active_classes

    passed = metrics['macro_f1'] >= 0.70
    print(f"  {'✓' if passed else '✗'} macro-F1={metrics['macro_f1']*100:.1f}%  "
          f"macro-Rec={metrics['macro_recall']*100:.1f}%")
    for cls in classes:
        r = metrics['per_class'].get(cls, {}).get('recall', 0)
        print(f"    {'✓' if r >= 0.70 else '✗'} {cls:<20} recall={r*100:.1f}%")

    return {
        'train_source': train_source,
        'test_source':  test_source,
        'metrics':      metrics,
        'passed':       passed,
        'classes':      classes,
    }
