"""
Jorise — Unified Training Runner
Executes all phases: dataset build → CV training → feature discipline →
cross-domain eval → anomaly layer → ensemble calibration → save to DB.

Usage:
    .venv\Scripts\python.exe train_unified.py [--algorithm xgboost|random_forest]
                                              [--splits 5]
                                              [--sample 15000]
                                              [--skip-cross-domain]
                                              [--skip-anomaly]
                                              [--dry-run]
"""
import django, os, sys, argparse, json, time
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jorise.settings')
django.setup()

import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
from django.conf import settings
from django.utils import timezone

from training.unified_dataset import build_unified_dataset
from training.multiclass_trainer import train_multiclass_cv, retrain_without_dominant
from training.anomaly_layer import train_anomaly_layer, EnsembleScorer
from training.models import UnifiedModelVersion

MEDIA       = settings.MEDIA_ROOT
CSV_DIR     = os.path.join(MEDIA, 'training/datasets')
MODELS_DIR  = os.path.join(MEDIA, 'training/unified')


# ─────────────────────────────────────────────────────────────────────────────

def next_version() -> str:
    """Generate next semantic version (1.0.0, 1.1.0, etc.)."""
    last = UnifiedModelVersion.objects.order_by('-created_at').first()
    if not last:
        return '1.0.0'
    try:
        parts = last.version.split('.')
        minor = int(parts[1]) + 1
        return f"{parts[0]}.{minor}.0"
    except Exception:
        return f"1.{int(time.time())}.0"


def print_header(title: str):
    print(f"\n{'='*68}")
    print(f"  {title}")
    print(f"{'='*68}")


def main():
    parser = argparse.ArgumentParser(description='Jorise Unified ML Training')
    parser.add_argument('--algorithm',        default='xgboost',
                        choices=['xgboost', 'random_forest'])
    parser.add_argument('--splits',           type=int, default=5)
    parser.add_argument('--sample',           type=int, default=15000)
    parser.add_argument('--skip-cross-domain',action='store_true')
    parser.add_argument('--skip-anomaly',     action='store_true')
    parser.add_argument('--dry-run',          action='store_true',
                        help="Do not save to DB or disk")
    parser.add_argument('--version',          default=None,
                        help="Override version string (e.g. 2.0.0)")
    args = parser.parse_args()

    version = args.version or next_version()
    t_start = time.time()

    print_header(f"JORISE UNIFIED TRAINING  v{version}")
    print(f"  Algorithm : {args.algorithm}")
    print(f"  K-Folds   : {args.splits}")
    print(f"  Sample/CSV: {args.sample:,}")
    print(f"  Save to DB: {not args.dry_run}")

    # ── Create DB record ────────────────────────────────────────────────────
    record = None
    if not args.dry_run:
        record = UnifiedModelVersion.objects.create(
            version    = version,
            algorithm  = args.algorithm,
            status     = 'training',
            n_splits   = args.splits,
            sample_per_file = args.sample,
        )
        print(f"  DB record : {record.id}")

    # ── FASE 1 — Paso 1: Unified Dataset ───────────────────────────────────
    print_header("FASE 1 — Paso 1: Building Unified Dataset")
    X, y, meta = build_unified_dataset(CSV_DIR, sample_per_file=args.sample)

    if record:
        record.n_samples_total = meta['n_samples']
        record.n_features      = meta['n_features']
        record.classes         = meta['classes']
        record.feature_names   = meta['feature_names']
        record.save()

    # ── FASE 1 — Pasos 2-3: Stratified K-Fold Multiclass Training ──────────
    print_header(f"FASE 1 — Pasos 2-3: Multiclass {args.splits}-Fold CV")
    os.makedirs(MODELS_DIR, exist_ok=True)

    result = train_multiclass_cv(
        X, y,
        algorithm    = args.algorithm,
        n_splits     = args.splits,
        save_dir     = MODELS_DIR,
        model_version= version,
    )

    if record:
        mm = result['mean_metrics']
        record.cv_accuracy        = mm['accuracy']
        record.cv_macro_f1        = mm['macro_f1']
        record.cv_macro_precision = mm['macro_precision']
        record.cv_macro_recall    = mm['macro_recall']
        record.cv_std_f1          = mm['std_macro_f1']
        record.cv_per_class_json  = mm['per_class']
        record.cv_fold_metrics    = result['fold_metrics']
        record.feature_importances= dict(list(result['feature_importances'].items())[:50])
        record.dominant_features  = result['dominant_features']
        record.top10_features     = result['top10_features']
        record.passes_targets     = result['passes_targets']
        record.weak_classes       = result['weak_classes']
        record.training_time      = result['training_time_s']
        record.model_file         = result['best_model_path'] or ''
        record.scaler_file        = result['best_scaler_path'] or ''
        record.status             = 'evaluating'
        record.save()

    # ── FASE 1 — Paso 4: Feature Discipline ────────────────────────────────
    if result['dominant_features'] and not result['passes_targets']:
        print_header("FASE 1 — Paso 4: Feature Discipline (drop dominant)")
        result2 = retrain_without_dominant(
            X, y,
            dominant_features = result['dominant_features'],
            algorithm         = args.algorithm,
            n_splits          = args.splits,
            save_dir          = MODELS_DIR,
            model_version     = f"{version}-fd",
        )
        # Use the better result
        if result2['mean_metrics']['macro_f1'] > result['mean_metrics']['macro_f1']:
            print(f"\n  Feature discipline IMPROVED: "
                  f"{result['mean_metrics']['macro_f1']*100:.1f}% → "
                  f"{result2['mean_metrics']['macro_f1']*100:.1f}%")
            result = result2
        else:
            print(f"\n  Feature discipline did NOT improve. Keeping full feature set.")

    # Final model to use
    best_model_path  = result['best_model_path']
    best_scaler_path = result['best_scaler_path']
    le               = result['label_encoder']

    # ── FASE 2 — Paso 5: Cross-Domain Eval ─────────────────────────────────
    cross_domain_result = None
    if not args.skip_cross_domain:
        print_header("FASE 2 — Paso 5: Cross-Domain Leave-One-Out Evaluation")
        try:
            from training.cross_domain_eval import run_cross_domain_eval
            cross_domain_result = run_cross_domain_eval(
                CSV_DIR,
                algorithm      = args.algorithm,
                sample_per_file= max(8000, args.sample // 2),
            )
            if record:
                record.cross_domain_avg_f1    = cross_domain_result['avg_macro_f1']
                record.cross_domain_pass_rate = cross_domain_result['pass_rate']
                record.cross_domain_verdict   = cross_domain_result['overall_verdict']
                record.cross_domain_detail    = {
                    k: {
                        'macro_f1': v['metrics']['macro_f1'],
                        'macro_recall': v['metrics']['macro_recall'],
                        'passed': v['passed'],
                    }
                    for k, v in cross_domain_result['per_day'].items()
                }
                record.save()
        except Exception as exc:
            print(f"  WARNING: Cross-domain eval failed: {exc}")
    else:
        print("\n  [SKIPPED] Cross-domain evaluation")

    # ── FASE 2 — Paso 6: Anomaly Layer ─────────────────────────────────────
    anomaly_result = None
    if not args.skip_anomaly and best_model_path:
        print_header("FASE 2 — Paso 6: Anomaly Layer (IsolationForest on BENIGN)")
        anomaly_save = os.path.join(MODELS_DIR, f'anomaly_{version}.pkl')
        try:
            anomaly_result = train_anomaly_layer(
                X, y,
                contamination = 0.05,
                n_estimators  = 200,
                save_path     = anomaly_save,
            )
            if record:
                record.anomaly_fpr  = anomaly_result['tuned']['fpr']
                record.anomaly_dr   = anomaly_result['tuned']['detection_rate']
                record.anomaly_f1   = anomaly_result['tuned']['f1']
                record.anomaly_file = anomaly_save
                record.save()
        except Exception as exc:
            print(f"  WARNING: Anomaly layer failed: {exc}")
    else:
        print("\n  [SKIPPED] Anomaly layer")

    # ── FASE 2 — Paso 7: Ensemble Calibration ──────────────────────────────
    if best_model_path and anomaly_result and os.path.exists(best_model_path):
        print_header("FASE 2 — Paso 7: Ensemble Weight Calibration")
        try:
            import joblib
            clf_loaded    = joblib.load(best_model_path)
            scaler_loaded = joblib.load(best_scaler_path)
            iso_data      = anomaly_result

            ensemble = EnsembleScorer(
                clf          = clf_loaded,
                clf_scaler   = scaler_loaded,
                clf_le       = le,
                iso_model    = iso_data['model'],
                iso_scaler   = iso_data['scaler'],
                iso_threshold= iso_data['threshold'],
                feature_names= result['label_encoder'].classes_.tolist()
                               if hasattr(result['label_encoder'], 'classes_') else meta['feature_names'],
                weights      = (0.6, 0.4, 0.0),
            )

            # Calibrate on a fresh sample
            X_cal, y_cal = X.sample(min(5000, len(X)), random_state=99), y.sample(min(5000, len(y)), random_state=99)
            best_w = ensemble.calibrate_weights(
                X_cal.reset_index(drop=True),
                y_cal.reset_index(drop=True),
            )

            ensemble_path = os.path.join(MODELS_DIR, f'ensemble_{version}.pkl')
            if not args.dry_run:
                ensemble.save(ensemble_path)
                if record:
                    record.ensemble_w_clf     = best_w[0]
                    record.ensemble_w_anomaly = best_w[1]
                    record.ensemble_w_context = best_w[2]
                    record.ensemble_file      = ensemble_path
                    record.save()
        except Exception as exc:
            print(f"  WARNING: Ensemble calibration failed: {exc}")
    else:
        print("\n  [SKIPPED] Ensemble calibration (no anomaly layer)")

    # ── Finalize ────────────────────────────────────────────────────────────
    total_time = time.time() - t_start
    if record and not args.dry_run:
        record.status       = 'active' if result['passes_targets'] else 'active'
        record.training_time = total_time
        record.save()
        if result['passes_targets']:
            record.activate()

    print_header("TRAINING COMPLETE")
    print(f"  Version     : v{version}")
    print(f"  Algorithm   : {args.algorithm}")
    print(f"  CV macro-F1 : {result['mean_metrics']['macro_f1']*100:.2f}%  "
          f"±{result['mean_metrics']['std_macro_f1']*100:.2f}%")
    print(f"  CV macro-Rec: {result['mean_metrics']['macro_recall']*100:.2f}%")
    print(f"  Targets met : {'YES ✓' if result['passes_targets'] else 'NO ✗'}")
    if result['weak_classes']:
        print(f"  Weak classes: {result['weak_classes']}")
    if cross_domain_result:
        print(f"  Cross-domain: avg F1={cross_domain_result['avg_macro_f1']*100:.1f}%  "
              f"verdict={cross_domain_result['overall_verdict']}")
    print(f"  Total time  : {total_time:.0f}s")
    print(f"  Model saved : {best_model_path or 'dry-run'}")
    if record:
        print(f"  DB record   : /training/model-versions/{record.id}/")
    print()

    return result

if __name__ == '__main__':
    main()
