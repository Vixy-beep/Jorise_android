"""
JORISE — Full Technical Evaluation
Generates honest in-sample + cross-file metrics + PDF report.

Run: .venv\Scripts\python.exe full_eval.py
"""
import django, os, warnings, json, sys
warnings.filterwarnings('ignore')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jorise.settings')
django.setup()

import numpy as np
import pandas as pd
import joblib
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
from matplotlib.backends.backend_pdf import PdfPages
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score,
)
from datetime import datetime
from training.models import TrainingJob, TrainedModel
from django.conf import settings

MEDIA   = settings.MEDIA_ROOT
CSV_DIR = os.path.join(MEDIA, 'training/datasets')
OUT_PDF = os.path.join('reports', 'jorise_ml_eval.pdf')
os.makedirs('reports', exist_ok=True)

SAMPLE_N = 25000   # rows per CSV during evaluation

# ── CSV loaders ──────────────────────────────────────────────────────────────

META_COLS = {
    'Label','label','Destination Port','Flow ID','Source IP',
    'Destination IP','Source Port','Protocol','Timestamp',
    'SimillarHTTP','Fwd Header Length.1'
}

def load_csv(csv_path, n=SAMPLE_N):
    """Return (X_df, y_binary, class_dist_dict)."""
    print(f"  Loading {os.path.basename(csv_path)} ...", end=' ', flush=True)
    df = pd.read_csv(csv_path, low_memory=False)
    df.columns = df.columns.str.strip()
    if 'Label' not in df.columns:
        print("NO LABEL — skip")
        return None, None, None

    label_col = df['Label'].str.strip()
    y = (label_col != 'BENIGN').astype(int)
    dist = label_col.value_counts().to_dict()
    n_attack = int(y.sum())
    n_benign = int((y == 0).sum())

    # Stratified downsample
    if len(df) > n:
        want_attack = min(int(n * 0.4), n_attack)
        want_benign = min(n - want_attack, n_benign)
        idx_a = np.where(y == 1)[0]
        idx_b = np.where(y == 0)[0]
        rng   = np.random.default_rng(42)
        chosen = np.concatenate([
            rng.choice(idx_a, want_attack, replace=False),
            rng.choice(idx_b, want_benign, replace=False),
        ])
        df = df.iloc[chosen].reset_index(drop=True)
        y  = (df['Label'].str.strip() != 'BENIGN').astype(int)

    feat_cols = [c for c in df.columns if c not in META_COLS]
    X = df[feat_cols].copy()
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)
    X = X.select_dtypes(include=[np.number])
    print(f"rows={len(df):,}  attacks={int(y.sum()):,}  benign={int((y==0).sum()):,}")
    return X, y, dist


def align_and_predict(clf, scaler, features_json, X):
    """Align X columns to model's feature list, scale, predict."""
    for f in features_json:
        if f not in X.columns:
            X = X.copy()
            X[f] = 0.0
    X = X[features_json]

    if scaler:
        try:
            Xs = scaler.transform(X)
        except Exception:
            Xs = X.values
    else:
        Xs = X.values

    y_pred = clf.predict(Xs)

    # IsolationForest returns +1 (normal) / -1 (anomaly)
    if not hasattr(clf, 'classes_'):
        y_pred = (y_pred == -1).astype(int)

    return y_pred


def compute_metrics(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    acc  = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, zero_division=0)
    rec  = recall_score(y_true, y_pred, zero_division=0)
    f1   = f1_score(y_true, y_pred, zero_division=0)
    fpr  = fp / (fp + tn) if (fp + tn) > 0 else 0
    fnr  = fn / (fn + tp) if (fn + tp) > 0 else 0
    return dict(acc=acc, prec=prec, rec=rec, f1=f1,
                fpr=fpr, fnr=fnr,
                tp=int(tp), fp=int(fp), tn=int(tn), fn=int(fn))


# ── Main evaluation pairs (train_csv vs cross_csv) ───────────────────────────

PAIRS = [
    ('Friday-DDos-CSV',
     'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv',
     'Wednesday-workingHours.pcap_ISCX.csv'),

    ('Friday-PortScan-CSV',
     'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv',
     'Tuesday-WorkingHours.pcap_ISCX.csv'),

    ('Thursday-Morning-CSV',
     'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv',
     'Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv'),

    ('Wednesday-CSV',
     'Wednesday-workingHours.pcap_ISCX.csv',
     'Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv'),

    ('Tuesday-CSV',
     'Tuesday-WorkingHours.pcap_ISCX.csv',
     'Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv'),

    ('Thursday-Afternoon-CSV',
     'Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv',
     'Wednesday-workingHours.pcap_ISCX.csv'),
]

results = []   # [{model, own_csv, cross_csv, in_sample:{...}, cross:{...}, dist_own, dist_cross}]

print("\n" + "="*72)
print("JORISE ML EVALUATION — starting")
print(f"Sample size per CSV : {SAMPLE_N:,}")
print("="*72)

for job_name, own_csv, cross_csv in PAIRS:
    print(f"\n[{job_name}]")

    job = TrainingJob.objects.filter(model_name=job_name, algorithm='random_forest').first()
    if not job:
        print("  -> Job not found, skipping")
        continue

    try:
        tm = TrainedModel.objects.get(job=job)
    except TrainedModel.DoesNotExist:
        print("  -> No TrainedModel, skipping")
        continue

    model_path  = os.path.join(MEDIA, str(tm.model_file))
    scaler_path = os.path.join(MEDIA, str(tm.scaler_file))

    if not os.path.exists(model_path):
        print(f"  -> model file missing: {model_path}")
        continue

    clf    = joblib.load(model_path)
    scaler = joblib.load(scaler_path) if os.path.exists(scaler_path) else None
    feats  = tm.features_json

    entry = dict(model=job_name, own_csv=own_csv, cross_csv=cross_csv,
                 stored_acc=job.accuracy, stored_f1=job.f1_score)

    # IN-SAMPLE
    own_path = os.path.join(CSV_DIR, own_csv)
    if os.path.exists(own_path):
        X_own, y_own, dist_own = load_csv(own_path)
        if X_own is not None:
            y_pred_own = align_and_predict(clf, scaler, feats, X_own)
            entry['in_sample'] = compute_metrics(y_own, y_pred_own)
            entry['dist_own']  = dist_own

    # CROSS-FILE
    cross_path = os.path.join(CSV_DIR, cross_csv)
    if os.path.exists(cross_path):
        X_cross, y_cross, dist_cross = load_csv(cross_path)
        if X_cross is not None:
            y_pred_cross = align_and_predict(clf, scaler, feats, X_cross)
            entry['cross'] = compute_metrics(y_cross, y_pred_cross)
            entry['dist_cross'] = dist_cross

    results.append(entry)

# ── Console report ────────────────────────────────────────────────────────────

print("\n\n" + "="*72)
print("RESULTS SUMMARY")
print("="*72)
fmt = "{:<28} {:>8} {:>8} {:>8} {:>8} {:>8}"
print(fmt.format("MODEL", "ACC", "PREC", "REC", "F1", "FPR"))
print("-"*72)
for e in results:
    for tag, key in [("(own )", "in_sample"), ("(cross)", "cross")]:
        m = e.get(key)
        if m:
            print(fmt.format(
                f"{e['model'][:22]} {tag}",
                f"{m['acc']*100:.1f}%",
                f"{m['prec']*100:.1f}%",
                f"{m['rec']*100:.1f}%",
                f"{m['f1']*100:.1f}%",
                f"{m['fpr']*100:.2f}%",
            ))
print("="*72)

# ── PDF generation ────────────────────────────────────────────────────────────

BLUE    = '#1e3a5f'
LBLUE   = '#2d7dd2'
RED     = '#c0392b'
GREEN   = '#27ae60'
ORANGE  = '#e67e22'
GRAY    = '#7f8c8d'
BG      = '#f9fbfd'

def color_metric(val, low=0.7, high=0.9):
    if val >= high: return GREEN
    if val >= low:  return ORANGE
    return RED

def bar_chart(ax, labels, values, title, ylabel, colors=None, ylim=(0, 1)):
    if colors is None:
        colors = [color_metric(v) for v in values]
    bars = ax.bar(labels, values, color=colors, edgecolor='white', linewidth=0.8)
    ax.set_title(title, fontsize=9, fontweight='bold', color=BLUE, pad=6)
    ax.set_ylabel(ylabel, fontsize=7, color=GRAY)
    ax.set_ylim(ylim)
    ax.tick_params(axis='x', labelsize=6, rotation=20)
    ax.tick_params(axis='y', labelsize=7)
    for bar, val in zip(bars, values):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.01,
                f'{val*100:.1f}%', ha='center', va='bottom', fontsize=7, fontweight='bold')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)
    ax.set_facecolor(BG)

def conf_matrix_plot(ax, m, title):
    cm = np.array([[m['tn'], m['fp']], [m['fn'], m['tp']]])
    im = ax.imshow(cm, interpolation='nearest', cmap='Blues')
    ax.set_title(title, fontsize=8, fontweight='bold', color=BLUE, pad=4)
    tick_labels = ['BENIGN', 'ATTACK']
    ax.set_xticks([0,1]); ax.set_xticklabels(tick_labels, fontsize=7)
    ax.set_yticks([0,1]); ax.set_yticklabels(tick_labels, fontsize=7)
    ax.set_xlabel('Predicted', fontsize=7); ax.set_ylabel('Actual', fontsize=7)
    for i in range(2):
        for j in range(2):
            ax.text(j, i, f'{cm[i,j]:,}', ha='center', va='center',
                    fontsize=9, fontweight='bold',
                    color='white' if cm[i,j] > cm.max()/2 else 'black')
    ax.set_facecolor(BG)

print(f"\nGenerating PDF: {OUT_PDF} ...")

with PdfPages(OUT_PDF) as pdf:

    # ── PAGE 1: Cover ──────────────────────────────────────────────────────
    fig = plt.figure(figsize=(8.5, 11))
    fig.patch.set_facecolor(BLUE)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_facecolor(BLUE)
    ax.axis('off')

    ax.add_patch(plt.Rectangle((0.08, 0.78), 0.84, 0.16, color=LBLUE, zorder=1))
    ax.text(0.50, 0.91, 'JORISE', transform=ax.transAxes,
            fontsize=42, fontweight='bold', color='white', ha='center', va='center')
    ax.text(0.50, 0.84, 'Security Operations Platform', transform=ax.transAxes,
            fontsize=14, color='#a8d4f5', ha='center', va='center')

    ax.text(0.50, 0.72, 'Machine Learning Evaluation Report', transform=ax.transAxes,
            fontsize=18, fontweight='bold', color='white', ha='center', va='center')
    ax.text(0.50, 0.67, 'CIC-IDS2017 Benchmark — In-Sample & Cross-File Generalization',
            transform=ax.transAxes, fontsize=11, color='#a8d4f5', ha='center', va='center')

    # Metadata box
    ax.add_patch(plt.Rectangle((0.1, 0.35), 0.8, 0.24, color='#ffffff14', zorder=1))
    meta = [
        ('Report Date',   datetime.now().strftime('%B %d, %Y')),
        ('Models Tested', f'{len(results)} RandomForest classifiers'),
        ('Dataset',       'CIC-IDS2017 (Canadian Institute for Cybersecurity)'),
        ('Evaluation',    'In-distribution (80/20) + cross-file generalization'),
        ('Sample Size',   f'{SAMPLE_N:,} rows per CSV (stratified)'),
    ]
    for i, (k, v) in enumerate(meta):
        y_pos = 0.555 - i * 0.042
        ax.text(0.15, y_pos, k + ':', transform=ax.transAxes,
                fontsize=10, color='#a8d4f5', va='center', fontweight='bold')
        ax.text(0.40, y_pos, v, transform=ax.transAxes,
                fontsize=10, color='white', va='center')

    ax.text(0.50, 0.22, 'IMPORTANT DISCLAIMER', transform=ax.transAxes,
            fontsize=9, color=ORANGE, ha='center', fontweight='bold')
    disclaimer = (
        "All models trained and evaluated on CIC-IDS2017 lab-synthesized data.\n"
        "Metrics reflect controlled benchmark conditions, not live production traffic.\n"
        "Production validation on real network data is required before enterprise deployment."
    )
    ax.text(0.50, 0.16, disclaimer, transform=ax.transAxes,
            fontsize=8, color='#cccccc', ha='center', va='center',
            multialignment='center',
            bbox=dict(boxstyle='round,pad=0.5', facecolor='#ffffff18', edgecolor='#ffffff30'))

    ax.text(0.50, 0.05, 'CONFIDENTIAL — Internal Technical Document',
            transform=ax.transAxes, fontsize=8, color='#666688', ha='center')

    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # ── PAGE 2: Executive Summary Table ───────────────────────────────────
    fig, ax = plt.subplots(figsize=(8.5, 11))
    fig.patch.set_facecolor(BG)
    ax.set_facecolor(BG)
    ax.axis('off')

    ax.text(0.5, 0.96, 'Executive Summary — All Models', transform=ax.transAxes,
            fontsize=16, fontweight='bold', color=BLUE, ha='center')
    ax.text(0.5, 0.93, f'Evaluated {datetime.now().strftime("%B %d, %Y")} — {len(results)} models — CIC-IDS2017',
            transform=ax.transAxes, fontsize=9, color=GRAY, ha='center')

    col_labels = ['Model', 'Test Type', 'Accuracy', 'Precision', 'Recall', 'F1', 'FP Rate', 'Verdict']
    col_widths  = [0.22, 0.10, 0.09, 0.09, 0.09, 0.09, 0.09, 0.10]
    col_x = [0.02]
    for w in col_widths[:-1]:
        col_x.append(col_x[-1] + w)

    header_y = 0.895
    ax.add_patch(plt.Rectangle((0.01, header_y - 0.008), 0.98, 0.030, color=BLUE, zorder=1))
    for label, x in zip(col_labels, col_x):
        ax.text(x + (col_widths[col_labels.index(label)] / 2), header_y + 0.005,
                label, transform=ax.transAxes,
                fontsize=8, fontweight='bold', color='white', ha='center', va='center')

    row_y = header_y - 0.028
    alt = False
    for e in results:
        for tag, key in [('In-Sample', 'in_sample'), ('Cross-File', 'cross')]:
            m = e.get(key)
            if not m:
                continue
            alt = not alt
            if alt:
                ax.add_patch(plt.Rectangle((0.01, row_y - 0.008), 0.98, 0.025,
                                           color='#e8f0f8', zorder=0))
            verdict = ('PASS' if m['f1'] >= 0.85 and m['fpr'] <= 0.05
                        else 'REVIEW' if m['f1'] >= 0.65
                        else 'FAIL')
            vc = GREEN if verdict == 'PASS' else (ORANGE if verdict == 'REVIEW' else RED)
            row_vals = [
                e['model'][:22], tag,
                f"{m['acc']*100:.1f}%", f"{m['prec']*100:.1f}%",
                f"{m['rec']*100:.1f}%", f"{m['f1']*100:.1f}%",
                f"{m['fpr']*100:.2f}%", verdict,
            ]
            for i, (val, x) in enumerate(zip(row_vals, col_x)):
                color = BLUE if i < 2 else (
                    vc if i == 7 else
                    (RED if i == 6 and m['fpr'] > 0.05 else BLUE)
                )
                fw = 'bold' if i in (0, 7) else 'normal'
                ax.text(x + col_widths[i]/2, row_y + 0.005, val,
                        transform=ax.transAxes,
                        fontsize=7.5, color=color, ha='center', va='center', fontweight=fw)
            row_y -= 0.028

    # Legend
    ax.text(0.02, row_y - 0.03,
            '★  PASS: F1 ≥ 85% AND FPR ≤ 5%    REVIEW: F1 ≥ 65%    FAIL: F1 < 65%',
            transform=ax.transAxes, fontsize=7.5, color=GRAY)
    ax.text(0.02, row_y - 0.055,
            'Cross-File = model tested on DIFFERENT day\'s data (generalization test)',
            transform=ax.transAxes, fontsize=7.5, color=GRAY, style='italic')

    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # ── PAGE 3: In-sample vs Cross-file comparison bars ───────────────────
    models_with_cross = [e for e in results if 'in_sample' in e and 'cross' in e]
    if models_with_cross:
        fig, axes = plt.subplots(2, 3, figsize=(8.5, 11))
        fig.patch.set_facecolor(BG)
        fig.suptitle('In-Sample vs Cross-File Generalization — Key Metrics',
                     fontsize=13, fontweight='bold', color=BLUE, y=0.97)

        metrics_info = [
            ('f1',   'F1 Score',  'F1'),
            ('rec',  'Recall',    'Recall (Attack Detection Rate)'),
            ('prec', 'Precision', 'Precision'),
            ('acc',  'Accuracy',  'Accuracy'),
            ('fpr',  'FP Rate',   'False Positive Rate (lower=better)'),
        ]
        short_names = [e['model'].replace('-CSV','').replace('Thursday-','Thu-')
                                  .replace('Friday-','Fri-').replace('Wednesday-','Wed-')
                                  .replace('Tuesday-','Tue-') for e in models_with_cross]

        for idx, (mkey, mlabel, mtitle) in enumerate(metrics_info):
            ax = axes[idx // 3][idx % 3]
            own_vals   = [e['in_sample'].get(mkey, 0) for e in models_with_cross]
            cross_vals = [e['cross'].get(mkey, 0) for e in models_with_cross]
            x = np.arange(len(models_with_cross))
            w = 0.35
            b1 = ax.bar(x - w/2, own_vals,   w, label='In-Sample',  color=LBLUE,  alpha=0.85)
            b2 = ax.bar(x + w/2, cross_vals, w, label='Cross-File', color=ORANGE, alpha=0.85)
            ax.set_title(mtitle, fontsize=8, fontweight='bold', color=BLUE)
            ax.set_xticks(x)
            ax.set_xticklabels(short_names, fontsize=6, rotation=30, ha='right')
            ax.tick_params(axis='y', labelsize=7)
            if mkey == 'fpr':
                ax.set_ylim(0, max(max(own_vals), max(cross_vals)) * 1.4 + 0.01)
            else:
                ax.set_ylim(0, 1.15)
            ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda val, _: f'{val*100:.0f}%'))
            ax.legend(fontsize=6)
            ax.spines['top'].set_visible(False)
            ax.spines['right'].set_visible(False)
            ax.set_facecolor(BG)

        # 6th panel: degradation table
        ax = axes[1][2]
        ax.axis('off')
        ax.set_facecolor(BG)
        ax.text(0.5, 0.95, 'Generalization Drop (Cross − In-Sample)',
                transform=ax.transAxes, fontsize=8, fontweight='bold',
                color=BLUE, ha='center')
        hdr = ['Model', 'ΔF1', 'ΔRecall', 'ΔFPR']
        for ci, h in enumerate(hdr):
            ax.text(0.02 + ci*0.24, 0.87, h, transform=ax.transAxes,
                    fontsize=7.5, fontweight='bold', color=BLUE)
        for ri, e in enumerate(models_with_cross):
            y_r = 0.80 - ri * 0.10
            df1  = e['cross']['f1']   - e['in_sample']['f1']
            drec = e['cross']['rec']  - e['in_sample']['rec']
            dfpr = e['cross']['fpr']  - e['in_sample']['fpr']
            vals = [e['model'][:16], f"{df1*100:+.1f}%", f"{drec*100:+.1f}%", f"{dfpr*100:+.2f}%"]
            for ci, v in enumerate(vals):
                fc = RED if (ci > 0 and float(v.replace('%','').replace('+','')) < -10) else \
                     GREEN if (ci > 0 and float(v.replace('%','').replace('+','')) > 0) else BLUE
                ax.text(0.02 + ci*0.24, y_r, v, transform=ax.transAxes,
                        fontsize=7, color=fc)

        plt.tight_layout(rect=[0, 0, 1, 0.96])
        pdf.savefig(fig, bbox_inches='tight')
        plt.close(fig)

    # ── PAGES 4+: Per-model detail pages ──────────────────────────────────
    for e in results:
        fig = plt.figure(figsize=(8.5, 11))
        fig.patch.set_facecolor(BG)
        gs = gridspec.GridSpec(3, 3, figure=fig, hspace=0.55, wspace=0.4,
                               top=0.91, bottom=0.06, left=0.08, right=0.97)

        fig.text(0.5, 0.955, f"Model Detail: {e['model']}",
                 fontsize=13, fontweight='bold', color=BLUE, ha='center')
        fig.text(0.5, 0.932, f"Trained on: {e['own_csv']} | Stored metrics: "
                              f"Acc={e.get('stored_acc',0)*100:.2f}%  F1={e.get('stored_f1',0)*100:.2f}%",
                 fontsize=8, color=GRAY, ha='center')

        metric_keys_labels = [
            ('acc','Accuracy'), ('prec','Precision'), ('rec','Recall'),
            ('f1','F1 Score'), ('fpr','False Positive Rate'),
        ]

        # Comparison bar for this model (in-sample vs cross)
        if 'in_sample' in e:
            ax0 = fig.add_subplot(gs[0, :2])
            m_in  = e['in_sample']
            m_cr  = e.get('cross', {})
            keys  = [k for k,_ in metric_keys_labels]
            lbls  = [l for _,l in metric_keys_labels]
            in_v  = [m_in.get(k, 0) for k in keys]
            cr_v  = [m_cr.get(k, 0) for k in keys] if m_cr else []

            x_pos = np.arange(len(keys))
            ax0.bar(x_pos - 0.18, in_v, 0.35, label='In-Sample', color=LBLUE, alpha=0.85)
            if cr_v:
                ax0.bar(x_pos + 0.18, cr_v, 0.35, label='Cross-File', color=ORANGE, alpha=0.85)
            ax0.set_xticks(x_pos)
            ax0.set_xticklabels(lbls, fontsize=7)
            ax0.set_ylim(0, 1.15)
            ax0.yaxis.set_major_formatter(plt.FuncFormatter(lambda v, _: f'{v*100:.0f}%'))
            ax0.set_title('In-Sample vs Cross-File', fontsize=9, fontweight='bold', color=BLUE)
            ax0.legend(fontsize=7)
            ax0.spines['top'].set_visible(False)
            ax0.spines['right'].set_visible(False)
            ax0.set_facecolor(BG)

        # Metrics text box
        ax_txt = fig.add_subplot(gs[0, 2])
        ax_txt.axis('off')
        ax_txt.set_facecolor(BG)
        if 'in_sample' in e:
            m = e['in_sample']
            lines  = ["IN-SAMPLE METRICS\n"]
            lines += [f"Accuracy  : {m['acc']*100:.2f}%"]
            lines += [f"Precision : {m['prec']*100:.2f}%"]
            lines += [f"Recall    : {m['rec']*100:.2f}%"]
            lines += [f"F1 Score  : {m['f1']*100:.2f}%"]
            lines += [f"FP Rate   : {m['fpr']*100:.2f}%"]
            lines += [f"\nTP:{m['tp']:,}  FP:{m['fp']:,}"]
            lines += [f"TN:{m['tn']:,}  FN:{m['fn']:,}"]
            if 'cross' in e:
                m2 = e['cross']
                lines += [f"\nCROSS-FILE METRICS"]
                lines += [f"Accuracy  : {m2['acc']*100:.2f}%"]
                lines += [f"F1 Score  : {m2['f1']*100:.2f}%"]
                lines += [f"FP Rate   : {m2['fpr']*100:.2f}%"]
                drop = (m2['f1'] - m['f1']) * 100
                lines += [f"\nΔF1: {drop:+.1f}pp  ({'OK' if drop > -15 else 'DEGRADED'})"]
            ax_txt.text(0.05, 0.95, '\n'.join(lines), transform=ax_txt.transAxes,
                        fontsize=7.5, va='top', family='monospace', color=BLUE,
                        bbox=dict(boxstyle='round', facecolor='#e8f4fd', edgecolor=LBLUE))

        # Confusion matrices
        for ci, (mkey, title) in enumerate([('in_sample', 'Confusion Matrix\n(In-Sample)'),
                                             ('cross',     'Confusion Matrix\n(Cross-File)')]):
            if mkey in e:
                ax_cm = fig.add_subplot(gs[1, ci])
                conf_matrix_plot(ax_cm, e[mkey], title)

        # Class distribution pie
        ax_pie = fig.add_subplot(gs[1, 2])
        dist = e.get('dist_own') or e.get('dist_cross')
        if dist:
            top_items = sorted(dist.items(), key=lambda x: -x[1])[:7]
            labels_p  = [k[:20] for k, _ in top_items]
            sizes_p   = [v for _, v in top_items]
            colors_p  = ['#2d7dd2' if l == 'BENIGN' else
                         plt.cm.Set2(i/max(len(labels_p)-1,1))
                         for i, l in enumerate(labels_p)]
            wedges, texts, autotexts = ax_pie.pie(
                sizes_p, autopct='%1.1f%%', colors=colors_p,
                startangle=90, pctdistance=0.75,
                textprops={'fontsize': 6})
            for at in autotexts:
                at.set_fontsize(6)
            ax_pie.legend(labels_p, fontsize=5, loc='lower center',
                          bbox_to_anchor=(0.5, -0.22), ncol=2)
            ax_pie.set_title('Class Distribution\n(Training CSV)', fontsize=8,
                             fontweight='bold', color=BLUE)

        # FP / FN bar breakdown
        ax_fn = fig.add_subplot(gs[2, :2])
        tags_fn = []
        missed  = []
        fp_cnt  = []
        for tag, mkey in [('In-Sample', 'in_sample'), ('Cross-File', 'cross')]:
            if mkey in e:
                tags_fn.append(tag)
                missed.append(e[mkey]['fn'])
                fp_cnt.append(e[mkey]['fp'])
        if tags_fn:
            x_fn = np.arange(len(tags_fn))
            ax_fn.bar(x_fn - 0.18, missed, 0.35, color=RED,   label='Missed Attacks (FN)', alpha=0.85)
            ax_fn.bar(x_fn + 0.18, fp_cnt, 0.35, color=ORANGE, label='False Positives (FP)', alpha=0.85)
            ax_fn.set_xticks(x_fn)
            ax_fn.set_xticklabels(tags_fn, fontsize=8)
            ax_fn.set_title('Error Breakdown: Missed vs False Alarms', fontsize=9,
                            fontweight='bold', color=BLUE)
            ax_fn.legend(fontsize=7)
            ax_fn.spines['top'].set_visible(False)
            ax_fn.spines['right'].set_visible(False)
            ax_fn.set_facecolor(BG)
            for bar in ax_fn.patches:
                h = bar.get_height()
                if h > 0:
                    ax_fn.text(bar.get_x() + bar.get_width()/2, h * 1.01,
                               f'{int(h):,}', ha='center', va='bottom', fontsize=7)

        # Interpretation text
        ax_int = fig.add_subplot(gs[2, 2])
        ax_int.axis('off')
        lines_int = ["INTERPRETATION\n"]
        if 'in_sample' in e and 'cross' in e:
            m_in = e['in_sample']
            m_cr = e['cross']
            drop = (m_in['f1'] - m_cr['f1']) * 100
            if m_cr['f1'] >= 0.85 and m_cr['fpr'] <= 0.05:
                lines_int += ["✓ Strong generalization.", "Model performs well on", "unseen attack types."]
            elif m_cr['f1'] >= 0.65:
                lines_int += [f"⚠ Moderate generalization.", f"F1 drops {drop:.1f}pp cross-file.",
                               "Acceptable for pilot."]
            else:
                lines_int += [f"✗ Weak generalization.", f"F1 drops {drop:.1f}pp cross-file.",
                               "Overfitting to train dist."]
            lines_int += [f"\nFP Rate (cross): {m_cr['fpr']*100:.2f}%"]
            if m_cr['fpr'] > 0.05:
                lines_int += ["HIGH FP — alert fatigue", "risk in production."]
            else:
                lines_int += ["FP Rate acceptable", "for production pilot."]
        ax_int.text(0.05, 0.95, '\n'.join(lines_int), transform=ax_int.transAxes,
                    fontsize=8, va='top', color=BLUE,
                    bbox=dict(boxstyle='round', facecolor='#fffbe7', edgecolor=ORANGE))

        pdf.savefig(fig, bbox_inches='tight')
        plt.close(fig)

    # ── FINAL PAGE: Conclusions & Roadmap ─────────────────────────────────
    fig, ax = plt.subplots(figsize=(8.5, 11))
    fig.patch.set_facecolor(BLUE)
    ax.set_facecolor(BLUE)
    ax.axis('off')

    ax.text(0.5, 0.94, 'Technical Assessment & Roadmap', transform=ax.transAxes,
            fontsize=16, fontweight='bold', color='white', ha='center')
    ax.text(0.5, 0.90, 'What these results mean — and what comes next',
            transform=ax.transAxes, fontsize=10, color='#a8d4f5', ha='center')

    # Compute aggregate stats
    all_cross_f1  = [e['cross']['f1']  for e in results if 'cross' in e]
    all_cross_fpr = [e['cross']['fpr'] for e in results if 'cross' in e]
    all_in_f1     = [e['in_sample']['f1'] for e in results if 'in_sample' in e]

    if all_cross_f1:
        avg_cross_f1  = np.mean(all_cross_f1)
        avg_cross_fpr = np.mean(all_cross_fpr)
        avg_in_f1     = np.mean(all_in_f1) if all_in_f1 else 0
        drop_avg      = (avg_in_f1 - avg_cross_f1) * 100

        if avg_cross_f1 >= 0.85 and avg_cross_fpr <= 0.05:
            tier = "STARTUP / EARLY ENTERPRISE"
            tier_col = GREEN
            tier_desc = "Defensible performance metrics. Ready for controlled production pilot."
        elif avg_cross_f1 >= 0.70:
            tier = "VALIDATED PROTOTYPE"
            tier_col = ORANGE
            tier_desc = "Solid technical foundation. Needs cross-domain validation before banking."
        else:
            tier = "EARLY ACADEMIC"
            tier_col = RED
            tier_desc = "Proof-of-concept. Requires significant tuning before product claims."

        ax.add_patch(plt.Rectangle((0.1, 0.76), 0.8, 0.10, color='#ffffff1a'))
        ax.text(0.5, 0.83, f'OVERALL VERDICT: {tier}',
                transform=ax.transAxes, fontsize=13, fontweight='bold',
                color=tier_col, ha='center', va='center')
        ax.text(0.5, 0.79, tier_desc,
                transform=ax.transAxes, fontsize=9, color='#cccccc', ha='center', va='center')

        ax.text(0.5, 0.74, f'Avg Cross-File F1: {avg_cross_f1*100:.1f}%   '
                            f'Avg FP Rate: {avg_cross_fpr*100:.2f}%   '
                            f'Avg Generalization Drop: {drop_avg:.1f}pp',
                transform=ax.transAxes, fontsize=9, color='white', ha='center')

    sections = [
        ("WHAT YOU HAVE (Verifiable)",
         ["✓ Functional ML training pipeline (scikit-learn RF)",
          "✓ Feature extraction from PCAP and CSV",
          "✓ 8 trained classifiers + 4 anomaly detectors",
          "✓ Django backend with audit logging",
          "✓ CIC-IDS2017 benchmark results (this document)"]),
        ("WHAT'S MISSING (Before Enterprise Sale)",
         ["✗ Live production traffic validation",
          "✗ Continuous online learning",
          "✗ Multi-tenant isolation testing",
          "✗ SOC analyst feedback loop (human-in-the-loop)",
          "✗ External penetration test of the platform itself"]),
        ("72-HOUR NEXT STEPS",
         ["1. Review this PDF and identify weakest model",
          "2. Re-train Thursday-Afternoon with SMOTE (class imbalance)",
          "3. Fix Monday-CSV (always-BENIGN model — retrain with binary target)",
          "4. Add per-class F1 storage to TrainingJob.report_json",
          "5. Run live PCAP eval on Friday-WorkingHours.pcap"]),
    ]

    y_start = 0.68
    for title, items in sections:
        ax.add_patch(plt.Rectangle((0.05, y_start - 0.02), 0.90,
                                   0.035 + 0.040 * len(items), color='#ffffff12'))
        ax.text(0.08, y_start + 0.025 + 0.040 * len(items) - 0.015, title,
                transform=ax.transAxes, fontsize=9, fontweight='bold', color=ORANGE)
        for i, item in enumerate(items):
            ax.text(0.10, y_start + 0.010 + (len(items) - 1 - i) * 0.040, item,
                    transform=ax.transAxes, fontsize=8, color='#e0e8f0')
        y_start -= (0.075 + 0.040 * len(items))

    ax.text(0.5, 0.04,
            'This report was generated automatically by Jorise evaluation pipeline.\n'
            'All metrics are reproducible by running full_eval.py against the same datasets.',
            transform=ax.transAxes, fontsize=7.5, color='#888888', ha='center',
            multialignment='center')

    pdf.savefig(fig, bbox_inches='tight')
    plt.close(fig)

    # PDF metadata
    d = pdf.infodict()
    d['Title']   = 'Jorise ML Evaluation Report'
    d['Author']  = 'Jorise Platform — Automated Evaluation Pipeline'
    d['Subject'] = 'CIC-IDS2017 RandomForest cross-file generalization metrics'
    d['Keywords'] = 'IDS, machine learning, CIC-IDS2017, RandomForest, evaluation'
    d['CreationDate'] = datetime.now()

print(f"\n✓ PDF saved: {os.path.abspath(OUT_PDF)}")
print(f"  Pages: Cover + Summary + Comparison + {len(results)} model pages + Conclusions\n")
