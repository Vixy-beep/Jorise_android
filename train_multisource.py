"""
Multi-Source Training Runner
Trains ONE unified multiclass model across all available public datasets.

Usage:
    # Show download instructions
    python train_multisource.py --download-info

    # Train on all available datasets
    python train_multisource.py --algorithm xgboost

    # Train + run cross-dataset generalization test
    python train_multisource.py --algorithm xgboost --cross-eval

    # Train on specific sources only
    python train_multisource.py --sources cicids2017 unsw

    # After downloading UNSW-NB15:
    python train_multisource.py --sources cicids2017 unsw --cross-eval --algorithm xgboost
"""
import django, os, sys, argparse, time, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jorise.settings')
django.setup()

import warnings
warnings.filterwarnings('ignore')

import numpy as np
import pandas as pd
from django.conf import settings

from training.dataset_adapters import print_all_download_info, ADAPTERS, UNIVERSAL_FEATURES
from training.multi_dataset_builder import build_multisource_dataset, cross_dataset_eval
from training.multiclass_trainer import train_multiclass_cv

MEDIA      = settings.MEDIA_ROOT
CSV_DIR    = os.path.join(MEDIA, 'training/datasets')
MODELS_DIR = os.path.join(MEDIA, 'training/unified')


def print_header(title: str):
    print(f"\n{'='*68}")
    print(f"  {title}")
    print(f"{'='*68}")


def main():
    parser = argparse.ArgumentParser(description='Jorise Multi-Source Training')
    parser.add_argument('--algorithm',     default='xgboost',
                        choices=['xgboost', 'random_forest'])
    parser.add_argument('--splits',        type=int, default=5)
    parser.add_argument('--sample',        type=int, default=20000,
                        help='Rows to sample per source dataset')
    parser.add_argument('--sources',       nargs='+', default=None,
                        choices=list(ADAPTERS.keys()),
                        help='Which dataset sources to include')
    parser.add_argument('--cross-eval',    action='store_true',
                        help='Run cross-dataset generalization tests after training')
    parser.add_argument('--download-info', action='store_true',
                        help='Print download instructions for all datasets and exit')
    parser.add_argument('--dry-run',       action='store_true',
                        help='Do not save model to disk or DB')
    args = parser.parse_args()

    if args.download_info:
        print_all_download_info()
        return

    t_start = time.time()

    # ── Build combined dataset ──────────────────────────────────────────────
    print_header("Multi-Source Dataset Build")
    print(f"  Base dir  : {CSV_DIR}")
    print(f"  Sources   : {args.sources or 'auto-detect'}")

    X, y, meta = build_multisource_dataset(
        CSV_DIR,
        sources=args.sources,
        sample_per_source=args.sample,
    )

    available = meta['available_sources']
    print(f"\n  Sources loaded: {available}")

    if len(available) == 0:
        print("\n  No data found. Run with --download-info to see how to get datasets.")
        sys.exit(1)

    if len(available) == 1:
        print(f"\n  WARNING: Only one source available ({available[0]}).")
        print(f"  Cross-dataset generalization cannot be measured.")
        print(f"  Download UNSW-NB15 for a real test.\n")

    # ── Train ───────────────────────────────────────────────────────────────
    print_header(f"Multiclass K-Fold CV  ({args.algorithm}, k={args.splits})")
    print(f"  Dataset size : {meta['n_samples']:,} rows")
    print(f"  Features     : {meta['n_features']} (universal feature set)")
    print(f"  Classes      : {meta['classes']}")

    save_dir = None if args.dry_run else MODELS_DIR
    version  = f"multi-{int(time.time())}"

    result = train_multiclass_cv(
        X, y,
        algorithm    = args.algorithm,
        n_splits     = args.splits,
        save_dir     = save_dir,
        model_version= version,
    )

    # ── Cross-dataset generalization eval ───────────────────────────────────
    cross_results = []
    if args.cross_eval and len(available) >= 2:
        print_header("Cross-Dataset Generalization Tests")
        pairs = [
            (available[i], available[j])
            for i in range(len(available))
            for j in range(len(available))
            if i != j
        ]
        for train_src, test_src in pairs:
            r = cross_dataset_eval(
                CSV_DIR, train_src, test_src,
                algorithm=args.algorithm,
                sample_per_source=min(args.sample, 10000),
            )
            cross_results.append(r)

    # ── Summary ─────────────────────────────────────────────────────────────
    print_header("TRAINING COMPLETE")
    mm = result['mean_metrics']
    print(f"  Sources used   : {available}")
    print(f"  Total samples  : {meta['n_samples']:,}")
    print(f"  Features       : {len(UNIVERSAL_FEATURES)} universal")
    print(f"  CV Macro F1    : {mm['macro_f1']*100:.2f}%  ±{mm['std_macro_f1']*100:.2f}%")
    print(f"  CV Macro Recall: {mm['macro_recall']*100:.2f}%")
    print(f"  Targets met    : {'YES ✓' if result['passes_targets'] else 'NO ✗'}")
    if result['weak_classes']:
        print(f"  Weak classes   : {result['weak_classes']}")

    if cross_results:
        print(f"\n  Cross-Dataset Results:")
        passed = sum(1 for r in cross_results if r.get('passed', False))
        print(f"  Passed ({'>='} 70% F1): {passed}/{len(cross_results)} pairs")
        for r in cross_results:
            if 'error' not in r:
                flag = '✓' if r['passed'] else '✗'
                print(f"    {flag} {r['train_source']:<15} → {r['test_source']:<15}  "
                      f"F1={r['metrics']['macro_f1']*100:.1f}%")

    print(f"\n  Elapsed: {time.time()-t_start:.0f}s")
    if result['best_model_path']:
        print(f"  Model  : {result['best_model_path']}")
    print()

    # Persist cross-dataset results as JSON for the dashboard
    if cross_results and not args.dry_run:
        out_path = os.path.join(MODELS_DIR, f'cross_dataset_{version}.json')
        os.makedirs(MODELS_DIR, exist_ok=True)
        with open(out_path, 'w') as f:
            safe = [
                {k: v for k, v in r.items() if k != 'metrics'} | {
                    'macro_f1': r['metrics']['macro_f1'] if 'metrics' in r else 0,
                    'macro_recall': r['metrics'].get('macro_recall', 0) if 'metrics' in r else 0,
                }
                for r in cross_results if 'error' not in r
            ]
            json.dump(safe, f, indent=2)
        print(f"  Cross-dataset results saved: {out_path}")


if __name__ == '__main__':
    main()
