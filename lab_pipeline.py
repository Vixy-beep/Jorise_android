"""
Jorise — Lab Pipeline (Enterprise MLOps v2)
============================================
Gestión del ciclo de vida del dataset jorise_lab y los modelos entrenados.

COMANDOS:
    python lab_pipeline.py status           # Health metrics formales del dataset
    python lab_pipeline.py history          # Versiones y modelos con métricas completas
    python lab_pipeline.py schema           # Generar / verificar feature_schema.json
    python lab_pipeline.py version          # Snapshot versionado del dataset
    python lab_pipeline.py version --tag v1.2-ddos-extended
    python lab_pipeline.py retrain          # Entrenar + evaluar + registrar (sin promover)
    python lab_pipeline.py retrain --sources cicids2017 unsw jorise_lab --sample 30000
    python lab_pipeline.py promote          # Gate matemático → promover si cumple criterios
    python lab_pipeline.py promote --model xgb_20260301_153000 --force
    python lab_pipeline.py redteam --label DDoS --pcap mi_captura.pcap
                                            # Evalúa modelo activo contra tráfico adversarial

FILOSOFIA ENTERPRISE:
    1. Nunca reentrenar sin versionado previo del dataset
    2. La promoción es un gate matemático, no una decisión emocional
    3. Cada modelo tiene trazabilidad completa: datos -> hiperparámetros -> métricas -> hash
    4. Red team mensual documenta degradación antes de que llegue a producción
    5. Feature schema freezeado — cambios silenciosos son un bug crítico

PROMOTION CRITERIA (no negociables):
    macro_f1 >= modelo_activo.macro_f1
    recall_min_class >= 0.75
    false_positive_rate <= 0.05
    no clase con recall == 0.0

ESTRUCTURA EN DISCO:
    media/training/datasets/jorise_lab/
        manifest.jsonl              <- sesiones de captura
        version_history.jsonl       <- versiones del dataset
        feature_schema.json         <- schema freezeado de features
        versions/
            v_20260301_153000/
                *.csv  + snapshot_meta.json + dataset_hash.txt
    media/training/models/
        registry.jsonl              <- todos los modelos entrenados
        active/
            model.pkl + scaler.pkl + model_meta.json
        archive/
            xgb_20260301_*.pkl + _meta.json
    media/training/redteam/
        redteam_log.jsonl           <- resultados del red team loop
"""
import django, os, sys, argparse, subprocess, json, shutil, glob, hashlib
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jorise.settings')
django.setup()

import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
from datetime import datetime
from django.conf import settings

# ── Rutas ────────────────────────────────────────────────────────────────────

MEDIA          = settings.MEDIA_ROOT
LAB_DIR        = os.path.join(MEDIA, 'training/datasets/jorise_lab')
VERSIONS_DIR   = os.path.join(LAB_DIR, 'versions')
MANIFEST       = os.path.join(LAB_DIR, 'manifest.jsonl')
VERSION_HIST   = os.path.join(LAB_DIR, 'version_history.jsonl')
SCHEMA_PATH    = os.path.join(LAB_DIR, 'feature_schema.json')

MODELS_DIR     = os.path.join(MEDIA, 'training/models')
ACTIVE_DIR     = os.path.join(MODELS_DIR, 'active')
ARCHIVE_DIR    = os.path.join(MODELS_DIR, 'archive')
REGISTRY       = os.path.join(MODELS_DIR, 'registry.jsonl')

UNIFIED_DIR    = os.path.join(MEDIA, 'training/unified')
REDTEAM_DIR    = os.path.join(MEDIA, 'training/redteam')
REDTEAM_LOG    = os.path.join(REDTEAM_DIR, 'redteam_log.jsonl')

# ── Promotion Criteria (enterprise policy — no negociables) ───────────────────
PROMO_MIN_RECALL_CLASS = 0.75   # every class must hit this
PROMO_MAX_FPR          = 0.05   # false positive rate <= 5%
PROMO_NO_ZERO_RECALL   = True   # any class at 0% recall = hard block

# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_jsonl(path: str) -> list:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


def _append_jsonl(path: str, record: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'a', encoding='utf-8') as f:
        f.write(json.dumps(record, ensure_ascii=False) + '\n')


def _rewrite_jsonl(path: str, records: list):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')


def _print_header(title: str):
    print(f"\n{'='*68}")
    print(f"  {title}")
    print(f"{'='*68}")


def _hash_dataset(lab_dir: str) -> str:
    """
    SHA-256 del shape + primeras 1000 filas de todos los CSVs ordenados.
    Fingerprint auditable del estado del dataset en un momento dado.
    """
    h = hashlib.sha256()
    csv_files = sorted(f for f in os.listdir(lab_dir) if f.endswith('.csv')) if os.path.isdir(lab_dir) else []
    for fn in csv_files:
        h.update(fn.encode())
        fpath = os.path.join(lab_dir, fn)
        try:
            df = pd.read_csv(fpath, nrows=1000)
            h.update(str(df.shape).encode())
            h.update(df.to_csv(index=False)[:4096].encode())
        except Exception:
            h.update(b'ERROR')
    return h.hexdigest()[:16]


def _read_lab_distribution(lab_dir: str):
    dist = {}
    total = 0
    if not os.path.isdir(lab_dir):
        return 0, {}
    for fn in os.listdir(lab_dir):
        if not fn.endswith('.csv'):
            continue
        try:
            tmp = pd.read_csv(os.path.join(lab_dir, fn), usecols=['Label'])
            for lbl, cnt in tmp['Label'].value_counts().items():
                dist[lbl] = dist.get(lbl, 0) + int(cnt)
                total += int(cnt)
        except Exception:
            pass
    return total, dist


def _class_entropy(dist: dict) -> float:
    """
    Shannon entropy normalizada [0.0, 1.0].
    1.0 = distribución uniforme perfecta entre todas las clases.
    0.0 = una sola clase dominante.
    """
    if len(dist) <= 1:
        return 0.0
    counts = np.array(list(dist.values()), dtype=float)
    probs = counts / counts.sum()
    e = float(np.sum(-probs * np.log2(probs + 1e-12)))
    return round(e / np.log2(len(probs)), 4)


def _load_active_meta():
    path = os.path.join(ACTIVE_DIR, 'model_meta.json')
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


# ── Paso 1: cmd_status con health metrics enterprise ─────────────────────────

def cmd_status():
    _print_header("JORISE LAB — Dataset Health Report")

    sessions  = _read_jsonl(MANIFEST)
    total_rows, dist = _read_lab_distribution(LAB_DIR)
    versions  = _read_jsonl(VERSION_HIST)
    registry  = _read_jsonl(REGISTRY)
    active    = _load_active_meta()

    # ── Sesiones ──────────────────────────────────────────────────────────────
    print(f"\n  {'─'*60}")
    print(f"  SESIONES DE CAPTURA  ({len(sessions)} total)")
    print(f"  {'─'*60}")

    if sessions:
        label_sess = {}
        tools_used = {}
        contexts   = {}
        intens     = {}
        for s in sessions:
            label_sess[s['label']] = label_sess.get(s['label'], 0) + 1
            t = s.get('tool', 'unknown')
            tools_used[t] = tools_used.get(t, 0) + 1
            c = s.get('context', 'unknown')
            contexts[c] = contexts.get(c, 0) + 1
            iv = s.get('intensity', 'unknown')
            intens[iv] = intens.get(iv, 0) + 1

        print(f"\n  Etiquetas en sesiones:")
        for lbl, n in sorted(label_sess.items(), key=lambda x: -x[1]):
            print(f"    {lbl:<16} {n:>3} sesion(es)")

        print(f"\n  Distribucion por intensidad:")
        for iv, n in sorted(intens.items(), key=lambda x: -x[1]):
            bar = 'x' * n
            print(f"    {iv:<10} {n:>3}  {bar}")

        print(f"\n  Cobertura de herramientas (tool diversity):")
        tools_clean = {k: v for k, v in tools_used.items() if k not in ('unknown',)}
        if tools_clean:
            for tool, n in sorted(tools_clean.items(), key=lambda x: -x[1]):
                print(f"    {tool:<20} {n} sesion(es)")
        else:
            print(f"    WARNING: Ninguna sesion tiene --tool especificado.")
            print(f"       Sin trazabilidad de herramienta -> no es audit-ready.")

        print(f"\n  Contextos operacionales:")
        for ctx, n in sorted(contexts.items(), key=lambda x: -x[1]):
            print(f"    {ctx:<20} {n} sesion(es)")

    # ── Health Metrics Formales ───────────────────────────────────────────────
    print(f"\n  {'─'*60}")
    print(f"  HEALTH METRICS FORMALES  ({total_rows:,} flujos totales)")
    print(f"  {'─'*60}")

    if dist:
        # 1. Entropia de clases
        entropy = _class_entropy(dist)
        if entropy >= 0.80:
            entropy_status = "BUENA"
        elif entropy >= 0.55:
            entropy_status = "MODERADA"
        else:
            entropy_status = "BAJA — dataset sesgado"
        print(f"\n  Entropia de clases     : {entropy:.4f}  ({entropy_status})")
        print(f"  [0=una clase, 1=uniforme perfecta]")

        # 2. Ratio benign/attack
        benign_cnt = dist.get('BENIGN', 0)
        attack_cnt = total_rows - benign_cnt
        ratio = benign_cnt / max(attack_cnt, 1)
        if 1.0 <= ratio <= 4.0:
            ratio_status = "RAZONABLE (ideal 1:1 - 4:1)"
        elif ratio > 4.0:
            ratio_status = "ALTO — exceso de benign"
        else:
            ratio_status = "BAJO — exceso de ataques"
        print(f"\n  Ratio BENIGN / ATTACK  : {ratio:.2f}:1  ({ratio_status})")
        print(f"    BENIGN   {benign_cnt:>8,}  ({benign_cnt/max(total_rows,1)*100:.1f}%)")
        print(f"    Attacks  {attack_cnt:>8,}  ({attack_cnt/max(total_rows,1)*100:.1f}%)")

        # 3. Distribucion por clase con umbrales enterprise
        print(f"\n  Distribucion por clase   [umbral: >=10% para clases de ataque]:")
        ALERT_PCT = 10.0
        alerts = []
        for lbl, cnt in sorted(dist.items(), key=lambda x: -x[1]):
            pct = cnt / max(total_rows, 1) * 100
            bar = '#' * int(pct / 4)
            flags = []
            if lbl != 'BENIGN' and pct < ALERT_PCT:
                flags.append(f"<{ALERT_PCT:.0f}%")
            if cnt < 200:
                flags.append("<200 flujos")
            flag_str = ' | '.join(flags)
            if flags:
                alerts.append(lbl)
            marker = f"  <- {flag_str}" if flags else ''
            print(f"    {lbl:<16} {cnt:>7,}  ({pct:5.1f}%) {bar}{marker}")

        if alerts:
            print(f"\n  ALERTA: Clases con datos insuficientes: {alerts}")
            print(f"     Recall bajo garantizado para estas clases en el proximo modelo.")

        # 4. Cobertura de vectores de ataque esperados
        expected_attacks = {'DDoS', 'PortScan', 'BruteForce', 'DoS', 'Bot', 'WebAttack', 'Infiltration'}
        present_attacks = set(dist.keys()) - {'BENIGN'}
        missing = expected_attacks - present_attacks
        if missing:
            coverage = len(present_attacks) / len(expected_attacks)
            print(f"\n  Cobertura de vectores de ataque: {len(present_attacks)}/{len(expected_attacks)} ({coverage*100:.0f}%)")
            print(f"    Cubiertos  : {sorted(present_attacks)}")
            print(f"    Sin datos  : {sorted(missing)}")
    else:
        print(f"\n  Sin datos en jorise_lab. Captura trafico primero.")

    # ── Estado de produccion ──────────────────────────────────────────────────
    print(f"\n  {'─'*60}")
    print(f"  ESTADO DE PRODUCCION")
    print(f"  {'─'*60}")
    print(f"\n  Versiones del dataset : {len(versions)}")
    print(f"  Modelos en registro   : {len(registry)}")

    if active:
        print(f"  Modelo activo         : {active.get('model_id', '?')}")
        print(f"    Accuracy     : {active.get('accuracy', 0)*100:.2f}%")
        print(f"    Macro F1     : {active.get('macro_f1', 0)*100:.2f}%")
        fpr = active.get('fpr', None)
        print(f"    FPR          : {f'{fpr*100:.2f}%' if fpr is not None else 'N/A'}")
        print(f"    Dataset hash : {active.get('dataset_hash', 'N/A')}")
        print(f"    Promovido el : {active.get('promoted_at', '?')[:19]}")

        per_class = active.get('per_class_recall', {})
        if per_class:
            print(f"\n  Recall por clase (modelo activo):")
            for cls, rec in sorted(per_class.items(), key=lambda x: x[1]):
                flag = 'WARN' if rec < PROMO_MIN_RECALL_CLASS else 'OK'
                bar = '#' * int(rec * 20)
                print(f"    [{flag}] {cls:<16} {rec*100:5.1f}%  {bar}")
    else:
        print(f"  Modelo activo         : (ninguno aun)")

    _print_header("Recomendacion")
    _print_recommendation(sessions, dist, total_rows, versions, registry)


def _print_recommendation(sessions, dist, total_rows, versions, registry):
    n_sess = len(sessions)
    entropy = _class_entropy(dist) if dist else 0.0

    if n_sess < 5:
        print(f"  Pocas sesiones ({n_sess}). Acumula variedad:")
        print(f"    - Distintas intensidades (low/medium/high)")
        print(f"    - Distintas herramientas por tipo de ataque")
        print(f"    - Distintos contextos (workday vs night)")
    elif entropy < 0.5:
        print(f"  Entropia baja ({entropy:.3f}). Dataset muy sesgado.")
        print(f"  Captura clases criticas: {[k for k,v in dist.items() if v < total_rows*0.1]}")
    elif not versions:
        print(f"  Dataset viable. Crea version antes de entrenar:")
        print(f"     python lab_pipeline.py version --tag v1.0-baseline")
    elif not registry:
        print(f"  Version existente. Entrena el primer modelo:")
        print(f"     python lab_pipeline.py retrain")
    else:
        last_reg = registry[-1]
        f1 = last_reg.get('macro_f1', 0)
        print(f"  Pipeline activo. Ultimo modelo: F1={f1*100:.1f}%")
        if f1 < 0.80:
            print(f"  F1 < 80%. Necesita mas datos o mejor variedad.")
        print(f"\n  Proximos pasos:")
        print(f"     python lab_pipeline.py retrain   # si tienes datos nuevos")
        print(f"     python lab_pipeline.py redteam   # evaluacion adversarial mensual")


# ── Paso 3: Feature Schema Freeze ─────────────────────────────────────────────

def cmd_schema(force: bool = False):
    _print_header("JORISE LAB — Feature Schema")

    from capture_session import UNIVERSAL_COLS

    if os.path.exists(SCHEMA_PATH) and not force:
        # Modo verificacion
        with open(SCHEMA_PATH, encoding='utf-8') as f:
            saved = json.load(f)

        print(f"\n  Schema cargado  : {SCHEMA_PATH}")
        print(f"  Version schema  : {saved.get('schema_version', '?')}")
        print(f"  Creado el       : {saved.get('created_at', '?')[:19]}")
        print(f"  Filas al crear  : {saved.get('source_rows', 'N/A'):,}" if saved.get('source_rows') else "  Filas al crear  : N/A")
        print(f"  Dataset hash    : {saved.get('dataset_hash', 'N/A')}")

        saved_features = [f['name'] for f in saved.get('features', [])]
        current_features = list(UNIVERSAL_COLS)

        added   = [f for f in current_features if f not in saved_features]
        removed = [f for f in saved_features if f not in current_features]
        reorder = (current_features != saved_features) and not added and not removed

        if not added and not removed and not reorder:
            print(f"\n  Feature space ESTABLE — {len(current_features)} features, sin cambios")
        else:
            print(f"\n  DRIFT DETECTADO EN FEATURE SPACE:")
            if added:
                print(f"     Anadidas   : {added}")
            if removed:
                print(f"     Eliminadas : {removed}")
            if reorder:
                print(f"     Orden cambio (afecta prediccion si el modelo asume orden fijo)")
            print(f"\n  Enterprise no acepta cambios silenciosos en feature space.")
            print(f"  Si el cambio es intencional:")
            print(f"     python lab_pipeline.py schema --force")

        print(f"\n  Features freezeadas ({len(current_features)}):")
        features_map = {x['name']: x for x in saved.get('features', [])}
        for i, name in enumerate(current_features, 1):
            info = features_map.get(name, {})
            p05 = info.get('range_p05', 'N/A')
            p95 = info.get('range_p95', 'N/A')
            dtype = info.get('dtype', 'float64')
            drift = '' if name in saved_features else '  <- NUEVA'
            print(f"    {i:2}. {name:<22} {dtype:<10} p5={p05}  p95={p95}{drift}")
        return

    # Modo generacion
    print(f"\n  Generando feature schema...")

    total_rows, _ = _read_lab_distribution(LAB_DIR)

    # Cargar muestra representativa para calcular rangos
    sample_df = None
    if os.path.isdir(LAB_DIR):
        frames = []
        for fn in sorted(os.listdir(LAB_DIR)):
            if fn.endswith('.csv'):
                try:
                    frames.append(pd.read_csv(os.path.join(LAB_DIR, fn), nrows=2000))
                except Exception:
                    pass
        if frames:
            sample_df = pd.concat(frames, ignore_index=True)

    features_schema = []
    for col in UNIVERSAL_COLS:
        entry = {
            'name':        col,
            'position':    UNIVERSAL_COLS.index(col),
            'dtype':       'float64',
            'description': _feature_description(col),
        }
        if sample_df is not None and col in sample_df.columns:
            series = pd.to_numeric(sample_df[col], errors='coerce').dropna()
            if len(series) > 0:
                entry['range_min'] = round(float(series.min()), 6)
                entry['range_max'] = round(float(series.max()), 6)
                entry['range_p05'] = round(float(series.quantile(0.05)), 6)
                entry['range_p95'] = round(float(series.quantile(0.95)), 6)
                entry['mean']      = round(float(series.mean()), 6)
                entry['std']       = round(float(series.std()), 6)
        features_schema.append(entry)

    schema = {
        'schema_version':  'v1',
        'created_at':      datetime.now().isoformat(),
        'feature_count':   len(UNIVERSAL_COLS),
        'source_rows':     total_rows,
        'dataset_hash':    _hash_dataset(LAB_DIR),
        'features':        features_schema,
        'policy': {
            'on_drift':           'BLOCK — run schema --force if intentional',
            'on_missing_feature': 'FILL_ZERO',
            'on_extra_feature':   'IGNORE',
        }
    }

    os.makedirs(os.path.dirname(SCHEMA_PATH), exist_ok=True)
    with open(SCHEMA_PATH, 'w', encoding='utf-8') as f:
        json.dump(schema, f, indent=2, ensure_ascii=False)

    print(f"\n  Schema generado : {SCHEMA_PATH}")
    print(f"  Features        : {len(UNIVERSAL_COLS)}")
    print(f"  Dataset hash    : {schema['dataset_hash']}")

    print(f"\n  Features freezeadas:")
    for i, feat in enumerate(features_schema, 1):
        r_str = f"[{feat.get('range_p05','N/A')}, {feat.get('range_p95','N/A')}]" if 'range_p05' in feat else "[N/A — sin datos]"
        print(f"    {i:2}. {feat['name']:<22} {r_str}  {feat['description']}")

    print(f"\n  El schema se verificara en cada retrain.")
    print(f"  Cualquier cambio en features bloqueara el pipeline hasta hacer --force.")


def _feature_description(col: str) -> str:
    desc = {
        'duration':          'Flow duration in seconds',
        'total_fwd_pkts':    'Total packets in forward direction',
        'total_bwd_pkts':    'Total packets in backward direction',
        'total_fwd_bytes':   'Total bytes in forward direction',
        'total_bwd_bytes':   'Total bytes in backward direction',
        'bytes_per_pkt':     'Average bytes per packet (both directions)',
        'pkts_per_sec':      'Flow packet rate (pkts/s)',
        'bytes_per_sec':     'Flow byte rate (bytes/s)',
        'fwd_bwd_pkt_ratio': 'Forward/backward packet count ratio',
        'fwd_bwd_byte_ratio':'Forward/backward byte count ratio',
        'avg_pkt_size':      'Mean packet size across all packets',
        'flow_iat_mean':     'Mean inter-arrival time across all packets (us)',
        'flow_iat_std':      'Std dev of inter-arrival times',
        'fwd_iat_mean':      'Mean IAT in forward direction',
        'bwd_iat_mean':      'Mean IAT in backward direction',
        'fin_flag_cnt':      'Count of packets with FIN flag set',
        'syn_flag_cnt':      'Count of packets with SYN flag set',
        'rst_flag_cnt':      'Count of packets with RST flag set',
        'ack_flag_cnt':      'Count of packets with ACK flag set',
        'psh_flag_cnt':      'Count of packets with PSH flag set',
        'urg_flag_cnt':      'Count of packets with URG flag set',
        'fwd_psh_flags':     'PSH flag count in forward direction',
        'bwd_psh_flags':     'PSH flag count in backward direction',
        'ttl_fwd':           'Mean TTL value in forward direction',
        'proto_encoded':     'Protocol encoded (6=TCP, 17=UDP, 1=ICMP)',
    }
    return desc.get(col, 'Network flow feature')


# ── history ───────────────────────────────────────────────────────────────────

def cmd_history():
    _print_header("JORISE LAB — Historial Completo")

    versions = _read_jsonl(VERSION_HIST)
    registry = _read_jsonl(REGISTRY)

    print(f"\n  VERSIONES DEL DATASET ({len(versions)})")
    if versions:
        for v in versions:
            h = v.get('dataset_hash', 'N/A')
            e = v.get('entropy', 0.0)
            print(f"    [{v['tag']:<28}]  {v['timestamp'][:19]}  "
                  f"{v.get('total_rows', 0):>7,} flujos  entropy={e:.3f}  hash={h[:8]}...")
    else:
        print("    (ninguna)")

    print(f"\n  MODELOS ENTRENADOS ({len(registry)})")
    if registry:
        for m in registry:
            acc    = m.get('accuracy', 0) * 100
            f1     = m.get('macro_f1', 0) * 100
            fpr    = m.get('fpr', None)
            fpr_s  = f"FPR={fpr*100:.1f}%" if fpr is not None else "FPR=N/A"
            h      = (m.get('dataset_hash') or 'N/A')[:8]
            dv     = m.get('dataset_version') or 'N/A'
            active = ' <- ACTIVO' if m.get('is_active') else ''
            print(f"    [{m['model_id']:>28}]  {m['trained_at'][:19]}  "
                  f"Acc={acc:.1f}%  F1={f1:.1f}%  {fpr_s}  "
                  f"ds={dv}  hash={h}...{active}")

        active_entries = [m for m in registry if m.get('is_active')]
        if active_entries:
            am = active_entries[-1]
            per_class = am.get('per_class_recall', {})
            if per_class:
                print(f"\n  Recall por clase (modelo activo {am['model_id']}):")
                for cls, rec in sorted(per_class.items(), key=lambda x: x[1]):
                    flag = 'WARN' if rec < PROMO_MIN_RECALL_CLASS else 'OK  '
                    bar = '#' * int(rec * 20)
                    print(f"    [{flag}] {cls:<16} {rec*100:5.1f}%  {bar}")

            gate = am.get('promotion_gate', {})
            if gate.get('violations'):
                print(f"\n  Violaciones al promover (--force usado):")
                for v in gate['violations']:
                    print(f"    - {v}")
    else:
        print("    (ninguno)")

    redteam = _read_jsonl(REDTEAM_LOG)
    print(f"\n  RED TEAM EVALUATIONS ({len(redteam)})")
    if redteam:
        for rt in redteam[-5:]:
            status = 'PASS' if rt.get('passed') else 'FAIL'
            deg = rt.get('degradation', 0) * 100
            print(f"    [{rt.get('run_id','?')}]  {rt.get('timestamp','?')[:19]}  "
                  f"label={rt.get('label','?'):<12}  F1={rt.get('f1',0)*100:.1f}%  "
                  f"degradacion={deg:.1f}%  [{status}]")
    else:
        print("    (ninguno — ejecuta mensualmente: python lab_pipeline.py redteam)")


# ── version ───────────────────────────────────────────────────────────────────

def cmd_version(tag=None):
    _print_header("JORISE LAB — Crear Version del Dataset")

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    if not tag:
        tag = f'v_{ts}'
    else:
        tag = tag.replace(' ', '_').replace('/', '-')
        if not tag.startswith('v'):
            tag = f'v_{tag}'

    csv_files = [f for f in os.listdir(LAB_DIR) if f.endswith('.csv')] if os.path.isdir(LAB_DIR) else []
    if not csv_files:
        print(f"\n  ERROR: no hay CSVs en {LAB_DIR}")
        sys.exit(1)

    versions = _read_jsonl(VERSION_HIST)
    if tag in {v['tag'] for v in versions}:
        print(f"\n  ERROR: el tag '{tag}' ya existe.")
        sys.exit(1)

    version_dir = os.path.join(VERSIONS_DIR, tag)
    os.makedirs(version_dir, exist_ok=True)

    total_rows = 0
    dist = {}
    for fn in csv_files:
        src = os.path.join(LAB_DIR, fn)
        shutil.copy2(src, os.path.join(version_dir, fn))
        try:
            tmp = pd.read_csv(src, usecols=['Label'])
            for lbl, cnt in tmp['Label'].value_counts().items():
                dist[lbl] = dist.get(lbl, 0) + int(cnt)
                total_rows += int(cnt)
        except Exception:
            pass

    if os.path.exists(MANIFEST):
        shutil.copy2(MANIFEST, os.path.join(version_dir, 'manifest.jsonl'))

    dataset_hash = _hash_dataset(LAB_DIR)
    entropy = _class_entropy(dist)

    with open(os.path.join(version_dir, 'dataset_hash.txt'), 'w') as f:
        f.write(f"{dataset_hash}\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n")
        f.write(f"Files: {sorted(csv_files)}\n")

    sessions = _read_jsonl(MANIFEST)
    snap_meta = {
        'tag':          tag,
        'timestamp':    datetime.now().isoformat(),
        'n_files':      len(csv_files),
        'total_rows':   total_rows,
        'distribution': dist,
        'n_sessions':   len(sessions),
        'dataset_hash': dataset_hash,
        'entropy':      entropy,
        'version_dir':  version_dir,
    }
    with open(os.path.join(version_dir, 'snapshot_meta.json'), 'w') as f:
        json.dump(snap_meta, f, indent=2)

    _append_jsonl(VERSION_HIST, snap_meta)

    print(f"\n  Version       : {tag}")
    print(f"  Dataset hash  : {dataset_hash}  <- audit fingerprint")
    print(f"  Total flujos  : {total_rows:,}")
    print(f"  Entropia      : {entropy:.4f}")
    print(f"  Distribucion  :")
    for lbl, cnt in sorted(dist.items(), key=lambda x: -x[1]):
        pct = cnt / max(total_rows, 1) * 100
        print(f"    {lbl:<16} {cnt:>7,}  ({pct:.1f}%)")
    print(f"\n  Snapshot guardado. Entrena con:")
    print(f"     python lab_pipeline.py retrain")


# ── Paso 4: retrain con registry formal ──────────────────────────────────────

def cmd_retrain(sources: list, sample: int, algorithm: str):
    _print_header("JORISE LAB — Retrain Pipeline")

    # 1. Verificar feature schema freeze
    if os.path.exists(SCHEMA_PATH):
        print(f"  Verificando feature schema...", end=' ')
        from capture_session import UNIVERSAL_COLS
        with open(SCHEMA_PATH) as f:
            saved_schema = json.load(f)
        saved_names = [x['name'] for x in saved_schema.get('features', [])]
        current_names = list(UNIVERSAL_COLS)
        if saved_names != current_names:
            drift = {
                'added':   [n for n in current_names if n not in saved_names],
                'removed': [n for n in saved_names if n not in current_names],
            }
            print(f"DRIFT DETECTADO")
            print(f"\n  Feature space cambio desde el ultimo schema freeze:")
            print(f"     {drift}")
            print(f"  Si el cambio es intencional: python lab_pipeline.py schema --force")
            sys.exit(1)
        else:
            print(f"OK ({len(current_names)} features estables)")
    else:
        print(f"  INFO: sin schema freeze. Considera: python lab_pipeline.py schema")

    # 2. Verificar versionado previo
    versions = _read_jsonl(VERSION_HIST)
    sessions = _read_jsonl(MANIFEST)

    if not versions:
        print(f"\n  ALERTA: sin version del dataset.")
        ans = input("  Continuar sin versionar? (s/N): ").strip().lower()
        if ans != 's':
            sys.exit(0)
    else:
        last_v = versions[-1]
        new_since = [s for s in sessions if s.get('timestamp', '') > last_v['timestamp']]
        if new_since:
            print(f"\n  INFO: {len(new_since)} sesion(es) sin versionar desde '{last_v['tag']}'.")
            ans = input("  Crear version automatica antes de entrenar? (S/n): ").strip().lower()
            if ans != 'n':
                cmd_version(f"v_pre_retrain_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    # 3. Verificar balance
    total_rows, dist = _read_lab_distribution(LAB_DIR)
    if total_rows > 0:
        maj_pct = max(dist.values()) / total_rows * 100
        if maj_pct > 90:
            maj_lbl = max(dist, key=dist.get)
            print(f"\n  ALERTA: '{maj_lbl}' domina el {maj_pct:.0f}% de jorise_lab.")
            ans = input("  Continuar? (s/N): ").strip().lower()
            if ans != 's':
                sys.exit(0)

    if 'jorise_lab' not in sources:
        sources = sources + ['jorise_lab']

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    model_id = f"xgb_{ts}"
    log_path = os.path.join(MEDIA, f'training/retrain_{ts}.log')
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    dataset_hash = _hash_dataset(LAB_DIR)

    print(f"\n  Fuentes      : {sources}")
    print(f"  Sample/fuente: {sample}")
    print(f"  Algoritmo    : {algorithm}")
    print(f"  Dataset hash : {dataset_hash}")
    print(f"  Model ID     : {model_id}")

    cmd = [
        sys.executable, 'train_multisource.py',
        '--sources', *sources,
        '--algorithm', algorithm,
        '--sample', str(sample),
        '--cross-eval',
    ]
    print(f"\n  Iniciando entrenamiento...\n")

    env = os.environ.copy()
    env['PYTHONUTF8'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'

    with open(log_path, 'w', encoding='utf-8') as logf:
        result = subprocess.run(cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = result.stdout.decode('utf-8', errors='replace')
        logf.write(output)
        print(output[-5000:] if len(output) > 5000 else output)

    _print_header("Extrayendo metricas del modelo")

    metrics_json_path = None
    json_candidates = sorted(
        glob.glob(os.path.join(UNIFIED_DIR, '*.json')),
        key=os.path.getmtime, reverse=True
    )
    if json_candidates:
        metrics_json_path = json_candidates[0]

    accuracy, macro_f1, macro_recall = 0.0, 0.0, 0.0
    per_class_recall = {}

    for line in output.split('\n'):
        lower = line.lower().strip()
        if 'accuracy' in lower and ':' in line:
            try:
                val = float(line.split(':')[-1].strip().rstrip('%'))
                if 0 < val <= 100:
                    accuracy = val / 100 if val > 1 else val
            except Exception:
                pass
        if ('macro f1' in lower or 'cv macro f1' in lower) and ':' in line:
            try:
                val = float(line.split(':')[-1].strip().split()[0].rstrip('%+/-'))
                if 0 < val <= 100:
                    macro_f1 = val / 100 if val > 1 else val
            except Exception:
                pass
        if 'macro recall' in lower and ':' in line:
            try:
                val = float(line.split(':')[-1].strip().rstrip('%'))
                if 0 < val <= 100:
                    macro_recall = val / 100 if val > 1 else val
            except Exception:
                pass
        if 'recall=' in lower:
            for cls in ['BENIGN', 'DDoS', 'PortScan', 'BruteForce', 'DoS', 'Bot', 'WebAttack', 'Infiltration']:
                if cls.lower() in lower:
                    try:
                        val = float(lower.split('recall=')[-1].rstrip('%'))
                        per_class_recall[cls] = val / 100 if val > 1 else val
                    except Exception:
                        pass

    fpr = _estimate_fpr_from_log(output)

    hyperparams = {
        'algorithm':         algorithm,
        'n_splits':          5,
        'sample_per_source': sample,
        'sources':           sources,
    }

    model_files = sorted(
        [f for f in glob.glob(os.path.join(UNIFIED_DIR, '*.pkl')) if '_scaler' not in f],
        key=os.path.getmtime, reverse=True
    )
    if not model_files:
        print(f"  ERROR: no se encontro modelo en {UNIFIED_DIR}")
        sys.exit(1)

    latest_model = model_files[0]
    scaler_file  = latest_model.replace('.pkl', '_scaler.pkl')

    active = _load_active_meta()
    prev_f1 = active.get('macro_f1', 0.0) if active else 0.0

    _print_header("Resultado del entrenamiento")
    print(f"  Modelo ID     : {model_id}")
    print(f"  Accuracy      : {accuracy*100:.2f}%")
    delta_s = f"  (+{(macro_f1-prev_f1)*100:.2f}%)" if active else ''
    print(f"  Macro F1      : {macro_f1*100:.2f}%{delta_s}")
    print(f"  Macro Recall  : {macro_recall*100:.2f}%")
    print(f"  FPR estimado  : {fpr*100:.2f}%")
    print(f"  Dataset hash  : {dataset_hash}")

    if per_class_recall:
        print(f"\n  Recall por clase:")
        for cls, rec in sorted(per_class_recall.items(), key=lambda x: x[1]):
            flag = 'OK  ' if rec >= PROMO_MIN_RECALL_CLASS else 'WARN'
            print(f"    [{flag}] {cls:<16} {rec*100:5.1f}%")

    _print_header("Gate de Promocion (preview)")
    gate_result = _check_promotion_criteria(macro_f1, per_class_recall, fpr, prev_f1, active)
    for msg in gate_result['messages']:
        print(f"  {msg}")

    if gate_result['can_promote']:
        print(f"\n  MODELO APTO PARA PROMOCION")
        print(f"     python lab_pipeline.py promote --model {model_id}")
    else:
        print(f"\n  MODELO NO CUMPLE CRITERIOS DE PROMOCION")
        print(f"     Captura mas datos variados y vuelve a reentrenar.")

    versions = _read_jsonl(VERSION_HIST)
    reg_entry = {
        'model_id':           model_id,
        'trained_at':         datetime.now().isoformat(),
        'sources':            sources,
        'sample':             sample,
        'algorithm':          algorithm,
        'hyperparams':        hyperparams,
        'accuracy':           accuracy,
        'macro_f1':           macro_f1,
        'macro_recall':       macro_recall,
        'fpr':                fpr,
        'per_class_recall':   per_class_recall,
        'dataset_hash':       dataset_hash,
        'dataset_version':    versions[-1]['tag'] if versions else None,
        'schema_version':     json.load(open(SCHEMA_PATH))['schema_version'] if os.path.exists(SCHEMA_PATH) else None,
        'model_path':         latest_model,
        'scaler_path':        scaler_file if os.path.exists(scaler_file) else None,
        'log_path':           log_path,
        'metrics_json':       metrics_json_path,
        'is_active':          False,
        'promotion_gate':     gate_result,
    }
    _append_jsonl(REGISTRY, reg_entry)
    print(f"\n  Registrado en : {REGISTRY}")
    print(f"  Log completo  : {log_path}")


def _estimate_fpr_from_log(output: str) -> float:
    """
    Estima FPR = 1 - precision(BENIGN).
    Si no encuentra el valor en el log, retorna 0.05 (estimacion conservadora).
    """
    benign_precision = None
    for line in output.split('\n'):
        lower = line.lower()
        if 'benign' in lower and 'precision' in lower:
            try:
                val = float(line.split('=')[-1].strip().rstrip('%'))
                benign_precision = val / 100 if val > 1 else val
            except Exception:
                pass
    if benign_precision is not None:
        return round(1.0 - benign_precision, 4)
    return 0.05


def _check_promotion_criteria(macro_f1, per_class_recall, fpr, prev_f1, active_meta):
    """
    Aplica los 4 criterios enterprise de promocion.
    Retorna dict con can_promote, violations y messages.
    """
    violations = []
    messages   = []

    # Criterio 1: macro_f1 >= modelo activo
    if active_meta:
        if macro_f1 < prev_f1:
            violations.append(f"regresion F1: {macro_f1*100:.2f}% < activo {prev_f1*100:.2f}%")
            messages.append(f"[FAIL] Macro F1: {macro_f1*100:.2f}% < activo {prev_f1*100:.2f}%")
        else:
            delta = (macro_f1 - prev_f1) * 100
            messages.append(f"[PASS] Macro F1: {macro_f1*100:.2f}% >= activo {prev_f1*100:.2f}% (+{delta:.2f}%)")
    else:
        messages.append(f"[INFO] Macro F1: {macro_f1*100:.2f}% (sin activo previo)")

    # Criterio 2: recall minimo por clase >= 0.75
    if per_class_recall:
        worst_cls = min(per_class_recall, key=per_class_recall.get)
        worst_rec = per_class_recall[worst_cls]
        if worst_rec < PROMO_MIN_RECALL_CLASS:
            violations.append(f"recall insuficiente: {worst_cls}={worst_rec*100:.1f}% < {PROMO_MIN_RECALL_CLASS*100:.0f}%")
            messages.append(f"[FAIL] Recall minimo: {worst_cls}={worst_rec*100:.1f}% < {PROMO_MIN_RECALL_CLASS*100:.0f}%")
        else:
            messages.append(f"[PASS] Recall minimo: {worst_cls}={worst_rec*100:.1f}% >= {PROMO_MIN_RECALL_CLASS*100:.0f}%")

        # Criterio 3: sin clases con recall==0 (hard block)
        zero_classes = [c for c, r in per_class_recall.items() if r == 0.0]
        if zero_classes and PROMO_NO_ZERO_RECALL:
            violations.append(f"recall=0 en: {zero_classes}")
            messages.append(f"[HARD BLOCK] Recall=0 en clases: {zero_classes}")
        elif not zero_classes:
            messages.append(f"[PASS] Sin clases con recall=0")
    else:
        messages.append(f"[INFO] Per-class recall no disponible")

    # Criterio 4: FPR <= 5%
    if fpr > PROMO_MAX_FPR:
        violations.append(f"FPR={fpr*100:.2f}% > {PROMO_MAX_FPR*100:.0f}%")
        messages.append(f"[FAIL] FPR: {fpr*100:.2f}% > {PROMO_MAX_FPR*100:.0f}%")
    else:
        messages.append(f"[PASS] FPR: {fpr*100:.2f}% <= {PROMO_MAX_FPR*100:.0f}%")

    return {
        'can_promote':  len(violations) == 0,
        'violations':   violations,
        'messages':     messages,
        'checked_at':   datetime.now().isoformat(),
    }


# ── Paso 4: promote con gate matematico ──────────────────────────────────────

def cmd_promote(model_id_arg=None, force: bool = False):
    _print_header("JORISE LAB — Promotion Gate")

    registry = _read_jsonl(REGISTRY)
    if not registry:
        print("\n  ERROR: no hay modelos registrados. Ejecuta: python lab_pipeline.py retrain")
        sys.exit(1)

    if not model_id_arg or model_id_arg == 'latest':
        entry = registry[-1]
    else:
        matching = [e for e in registry if e['model_id'] == model_id_arg]
        if not matching:
            print(f"\n  ERROR: modelo '{model_id_arg}' no encontrado.")
            print(f"  IDs disponibles: {[e['model_id'] for e in registry]}")
            sys.exit(1)
        entry = matching[-1]

    model_id = entry['model_id']
    print(f"\n  Modelo candidato  : {model_id}")
    print(f"  Entrenado el      : {entry.get('trained_at','?')[:19]}")
    print(f"  Dataset version   : {entry.get('dataset_version','N/A')}")
    print(f"  Schema version    : {entry.get('schema_version','N/A')}")
    print(f"  Dataset hash      : {entry.get('dataset_hash','N/A')}")

    active = _load_active_meta()
    prev_f1 = active.get('macro_f1', 0.0) if active else 0.0

    print(f"\n  {'─'*60}")
    print(f"  CRITERIOS DE PROMOCION ENTERPRISE")
    print(f"  {'─'*60}")

    gate = _check_promotion_criteria(
        macro_f1         = entry.get('macro_f1', 0.0),
        per_class_recall = entry.get('per_class_recall', {}),
        fpr              = entry.get('fpr', 0.0),
        prev_f1          = prev_f1,
        active_meta      = active,
    )
    for msg in gate['messages']:
        print(f"  {msg}")

    if not gate['can_promote'] and not force:
        print(f"\n  BLOQUEADO: el modelo no cumple los criterios enterprise.")
        print(f"\n  Violaciones:")
        for v in gate['violations']:
            print(f"    - {v}")
        print(f"\n  Opciones:")
        print(f"    1. Captura mas datos variados y vuelve a reentrenar")
        print(f"    2. python lab_pipeline.py promote --force  (omite gate — NO recomendado)")
        sys.exit(2)

    if not gate['can_promote'] and force:
        print(f"\n  FORZADO: omitiendo criterios de promocion.")
        print(f"  Rastro de auditoria guardado en el registro.")

    print(f"\n  Accuracy : {entry.get('accuracy',0)*100:.2f}%")
    print(f"  Macro F1 : {entry.get('macro_f1',0)*100:.2f}%")
    print(f"  FPR      : {entry.get('fpr',0)*100:.2f}%")
    print()
    ans = input("  Confirmar promocion? (s/N): ").strip().lower()
    if ans != 's':
        print("  Abortado. El modelo anterior sigue activo.")
        sys.exit(0)

    os.makedirs(ACTIVE_DIR, exist_ok=True)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)

    active_model   = os.path.join(ACTIVE_DIR, 'model.pkl')
    active_scaler  = os.path.join(ACTIVE_DIR, 'scaler.pkl')
    active_meta_p  = os.path.join(ACTIVE_DIR, 'model_meta.json')

    if os.path.exists(active_model) and active:
        old_id = active.get('model_id', 'unknown')
        print(f"\n  Archivando modelo anterior: {old_id}")
        shutil.copy2(active_model, os.path.join(ARCHIVE_DIR, f'{old_id}.pkl'))
        if os.path.exists(active_scaler):
            shutil.copy2(active_scaler, os.path.join(ARCHIVE_DIR, f'{old_id}_scaler.pkl'))
        if os.path.exists(active_meta_p):
            shutil.copy2(active_meta_p, os.path.join(ARCHIVE_DIR, f'{old_id}_meta.json'))
        updated = [dict(r, is_active=False) if r.get('is_active') else r for r in registry]
        _rewrite_jsonl(REGISTRY, updated)

    model_path  = entry.get('model_path', '')
    scaler_path = entry.get('scaler_path', '')

    if not os.path.exists(model_path):
        print(f"\n  ERROR: modelo no encontrado: {model_path}")
        sys.exit(1)

    shutil.copy2(model_path, active_model)
    if scaler_path and os.path.exists(scaler_path):
        shutil.copy2(scaler_path, active_scaler)

    promotion_ts = datetime.now().isoformat()
    new_meta = {
        **entry,
        'is_active':   True,
        'promoted_at': promotion_ts,
        'forced':      force and not gate['can_promote'],
        'gate_result': gate,
    }
    with open(active_meta_p, 'w') as f:
        json.dump(new_meta, f, indent=2)

    registry_all = _read_jsonl(REGISTRY)
    updated = []
    for r in registry_all:
        r = dict(r)
        if r['model_id'] == model_id:
            r['is_active'] = True
            r['promoted_at'] = promotion_ts
        updated.append(r)
    _rewrite_jsonl(REGISTRY, updated)

    print(f"\n  Modelo '{model_id}' promovido a ACTIVO.")
    print(f"    {active_model}")
    if gate['violations']:
        print(f"\n  Promovido con violaciones (--force). Audit log actualizado.")


# ── Paso 5: Red Team Loop ─────────────────────────────────────────────────────

def cmd_redteam(pcap, label: str, expected_min_f1: float, notes: str):
    _print_header("JORISE LAB — Red Team Evaluation")

    active = _load_active_meta()
    if not active:
        print("\n  ERROR: no hay modelo activo. Promueve un modelo primero.")
        sys.exit(1)

    active_model_path  = os.path.join(ACTIVE_DIR, 'model.pkl')
    active_scaler_path = os.path.join(ACTIVE_DIR, 'scaler.pkl')

    if not os.path.exists(active_model_path):
        print(f"\n  ERROR: modelo activo no encontrado: {active_model_path}")
        sys.exit(1)

    run_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    print(f"\n  Red Team Run     : {run_id}")
    print(f"  Modelo activo    : {active.get('model_id','?')}")
    print(f"  Promovido el     : {active.get('promoted_at','?')[:19]}")
    print(f"  F1 al promover   : {active.get('macro_f1',0)*100:.2f}%")
    print(f"  Tipo de trafico  : {label}")
    print(f"  F1 umbral        : {expected_min_f1*100:.1f}%")
    if notes:
        print(f"  Notas            : {notes}")

    # Cargar modelo
    import pickle
    from capture_session import UNIVERSAL_COLS, pcap_to_universal_csv

    print(f"\n  Cargando modelo activo...")
    with open(active_model_path, 'rb') as f:
        model = pickle.load(f)
    scaler = None
    if os.path.exists(active_scaler_path):
        with open(active_scaler_path, 'rb') as f:
            scaler = pickle.load(f)

    # Preparar datos de test
    if pcap:
        if not os.path.exists(pcap):
            print(f"  ERROR: PCAP no encontrado: {pcap}")
            sys.exit(1)
        print(f"\n  Usando PCAP: {pcap}  ({os.path.getsize(pcap)/1024/1024:.1f} MB)")
        df_test = pcap_to_universal_csv(pcap, label)
        if df_test is None or len(df_test) == 0:
            print("  ERROR: no se obtuvieron flujos del PCAP.")
            sys.exit(1)
    else:
        print(f"\n  Sin PCAP. Usando jorise_lab/ como testset adversarial.")
        frames = []
        if os.path.isdir(LAB_DIR):
            for fn in os.listdir(LAB_DIR):
                if fn.endswith('.csv'):
                    try:
                        frames.append(pd.read_csv(os.path.join(LAB_DIR, fn)))
                    except Exception:
                        pass
        if not frames:
            print("  ERROR: jorise_lab vacio. Usa --pcap para especificar datos.")
            sys.exit(1)
        df_test = pd.concat(frames, ignore_index=True)

    print(f"  Flujos de test: {len(df_test):,}")

    # Prediccion
    from sklearn.metrics import f1_score, classification_report

    X_test = pd.DataFrame()
    for col in UNIVERSAL_COLS:
        if col in df_test.columns:
            X_test[col] = pd.to_numeric(df_test[col], errors='coerce').fillna(0)
        else:
            X_test[col] = 0.0
    X_test = X_test[UNIVERSAL_COLS].replace([np.inf, -np.inf], 0)

    X_arr = scaler.transform(X_test) if scaler else X_test.values
    y_true_raw = list(df_test.get('Label', pd.Series([label] * len(df_test))))
    y_pred_raw = model.predict(X_arr)

    # Decodificar si el modelo usa integers
    try:
        if hasattr(model, 'classes_'):
            y_pred_labels = [model.classes_[p] if isinstance(p, (int, np.integer)) else p for p in y_pred_raw]
        else:
            y_pred_labels = list(y_pred_raw)
    except Exception:
        y_pred_labels = list(y_pred_raw)

    shared_labels = sorted(set(y_true_raw) & set(y_pred_labels))
    macro_f1_rt = 0.0
    per_class_rt = {}
    if shared_labels:
        try:
            macro_f1_rt = f1_score(y_true_raw, y_pred_labels,
                                   labels=shared_labels, average='macro', zero_division=0)
            report = classification_report(y_true_raw, y_pred_labels,
                                           labels=shared_labels, output_dict=True, zero_division=0)
            for cls in shared_labels:
                if cls in report:
                    per_class_rt[cls] = round(report[cls]['recall'], 4)
        except Exception as e:
            print(f"  WARNING al calcular metricas: {e}")

    baseline_f1 = active.get('macro_f1', 0.0)
    degradation = baseline_f1 - macro_f1_rt
    passed = macro_f1_rt >= expected_min_f1

    _print_header(f"Red Team Result  [{run_id}]")
    print(f"  Tipo de trafico    : {label}")
    print(f"  Flujos evaluados   : {len(df_test):,}")
    print(f"  F1 umbral          : {expected_min_f1*100:.1f}%")
    print(f"  Macro F1 obtenido  : {macro_f1_rt*100:.2f}%")
    print(f"  F1 baseline        : {baseline_f1*100:.2f}%  (al promover)")
    deg_alert = '  SIGNIFICATIVA (>10%) — planifica retrain' if degradation > 0.10 else 'aceptable'
    print(f"  Degradacion        : {degradation*100:.2f}%  {deg_alert}")
    print(f"  Resultado          : {'PASS' if passed else 'FAIL'}")

    if per_class_rt:
        print(f"\n  Recall por clase (red team):")
        for cls, rec in sorted(per_class_rt.items(), key=lambda x: x[1]):
            flag = 'OK  ' if rec >= 0.70 else 'WARN'
            bar = '#' * int(rec * 20)
            print(f"    [{flag}] {cls:<16} {rec*100:5.1f}%  {bar}")

    from collections import Counter
    pred_dist = Counter(y_pred_labels)
    print(f"\n  Distribucion de predicciones:")
    for lbl, cnt in sorted(pred_dist.items(), key=lambda x: -x[1]):
        pct = cnt / max(len(y_pred_labels), 1) * 100
        print(f"    {lbl:<16} {cnt:>6,}  ({pct:.1f}%)")

    # Guardar resultado
    os.makedirs(REDTEAM_DIR, exist_ok=True)
    rt_entry = {
        'run_id':            run_id,
        'timestamp':         datetime.now().isoformat(),
        'model_id':          active.get('model_id', '?'),
        'label':             label,
        'pcap':              pcap,
        'n_flows':           int(len(df_test)),
        'expected_min_f1':   expected_min_f1,
        'f1':                round(macro_f1_rt, 4),
        'baseline_f1':       round(baseline_f1, 4),
        'degradation':       round(degradation, 4),
        'per_class_recall':  per_class_rt,
        'pred_distribution': dict(sorted(pred_dist.items())),
        'passed':            passed,
        'notes':             notes,
    }
    _append_jsonl(REDTEAM_LOG, rt_entry)
    print(f"\n  Resultado guardado: {REDTEAM_LOG}")

    if not passed:
        print(f"\n  ACCIONES:")
        print(f"    1. Captura mas variaciones de '{label}' con distintas herramientas")
        print(f"    2. python lab_pipeline.py version --tag v_post_redteam_{run_id[:8]}")
        print(f"    3. python lab_pipeline.py retrain")
        print(f"    4. python lab_pipeline.py promote  (solo si mejora)")
    elif degradation > 0.05:
        print(f"\n  F1 paso el umbral pero degradacion es {degradation*100:.1f}%.")
        print(f"  Documenta y planifica retrain preventivo.")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Jorise Lab Pipeline Enterprise — MLOps del dataset incremental',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Flujo normal:\n"
            "  capture_session.py  (x N sesiones con variedad)\n"
            "  lab_pipeline.py status       <- health check\n"
            "  lab_pipeline.py schema       <- freeze feature space\n"
            "  lab_pipeline.py version      <- snapshot versional\n"
            "  lab_pipeline.py retrain      <- train + eval + registro\n"
            "  lab_pipeline.py promote      <- gate matematico\n"
            "\n"
            "Ciclo mensual:\n"
            "  lab_pipeline.py redteam --label DDoS --pcap nueva_captura.pcap\n"
        )
    )
    sub = parser.add_subparsers(dest='command', required=True)

    sub.add_parser('status',  help='Health metrics formales: entropia, ratio, cobertura')
    sub.add_parser('history', help='Historial completo: versiones, modelos, red team')

    p_schema = sub.add_parser('schema', help='Generar / verificar feature schema freezeado')
    p_schema.add_argument('--force', action='store_true',
                          help='Regenerar schema aunque ya exista')

    p_ver = sub.add_parser('version', help='Snapshot versionado del dataset con hash SHA-256')
    p_ver.add_argument('--tag', default=None,
                       help='Nombre de la version (ej: v1.0-ddos-variado)')

    p_ret = sub.add_parser('retrain', help='Reentrenar + evaluar + registrar (no promueve)')
    p_ret.add_argument('--sources', nargs='+', default=['cicids2017', 'unsw'],
                       help='Fuentes (jorise_lab se agrega siempre)')
    p_ret.add_argument('--sample', type=int, default=20000,
                       help='Max filas por fuente (default: 20000)')
    p_ret.add_argument('--algorithm', default='xgboost',
                       choices=['xgboost', 'random_forest', 'gradient_boosting'])

    p_pro = sub.add_parser('promote', help='Gate matematico + promocion del modelo')
    p_pro.add_argument('--model', default='latest', help='ID del modelo (default: latest)')
    p_pro.add_argument('--force', action='store_true',
                       help='Forzar promocion omitiendo criterios (audit log guardado)')

    p_rt = sub.add_parser('redteam', help='Evaluacion adversarial mensual del modelo activo')
    p_rt.add_argument('--label', default='ALL',
                      help='Tipo de trafico del test (DDoS, PortScan, BruteForce... o ALL)')
    p_rt.add_argument('--pcap', default=None,
                      help='PCAP de ataque no visto previamente. Sin --pcap usa jorise_lab/')
    p_rt.add_argument('--min-f1', type=float, default=0.70,
                      help='F1 minimo esperado para pasar (default: 0.70)')
    p_rt.add_argument('--notes', default='',
                      help='Notas: herramientas usadas, variaciones, contexto del test')

    args = parser.parse_args()

    if args.command == 'status':
        cmd_status()
    elif args.command == 'history':
        cmd_history()
    elif args.command == 'schema':
        cmd_schema(force=args.force)
    elif args.command == 'version':
        cmd_version(args.tag)
    elif args.command == 'retrain':
        cmd_retrain(args.sources, args.sample, args.algorithm)
    elif args.command == 'promote':
        cmd_promote(args.model, force=args.force)
    elif args.command == 'redteam':
        cmd_redteam(args.pcap, args.label, args.min_f1, args.notes)


if __name__ == '__main__':
    main()
