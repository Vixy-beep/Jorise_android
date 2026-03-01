"""
Jorise — Lab Pipeline (MLOps)
==============================
Gestión del ciclo de vida del dataset jorise_lab y los modelos entrenados con él.

COMANDOS:
    python lab_pipeline.py status           # Balance del dataset, alertas, sesiones
    python lab_pipeline.py history          # Versiones y modelos previos
    python lab_pipeline.py version          # Crear snapshot versionado del dataset
    python lab_pipeline.py version --tag v1.2-ddos-extended
    python lab_pipeline.py retrain          # Entrenar nuevo modelo + evaluación
    python lab_pipeline.py retrain --sources cicids2017 unsw jorise_lab --sample 30000
    python lab_pipeline.py promote          # Promover el último modelo evaluado
    python lab_pipeline.py promote --model xgb_20260301_153000

FILOSOFÍA:
    1. Nunca reentrenar sin versionado previo
    2. Nunca promover un modelo sin ver métricas comparadas
    3. El operador toma la decisión final de promover
    4. Trazabilidad completa: qué datos → qué modelo → qué métricas

ESTRUCTURA EN DISCO:
    media/training/datasets/jorise_lab/
        manifest.jsonl              ← una línea por sesión de captura
        version_history.jsonl       ← una línea por versión creada
        versions/
            v_20260301_153000/      ← snapshot de CSVs en ese momento
                *.csv
                snapshot_meta.json
    media/training/models/
        registry.jsonl              ← una línea por modelo entrenado
        active/
            model.pkl               ← modelo activo (promovido)
            scaler.pkl
            model_meta.json
        archive/
            xgb_20260301_153000.pkl ← modelos históricos
            xgb_20260301_153000_meta.json
"""
import django, os, sys, argparse, subprocess, json, shutil, glob
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jorise.settings')
django.setup()

import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
from datetime import datetime
from django.conf import settings

# ── Rutas ───────────────────────────────────────────────────────────────────

MEDIA          = settings.MEDIA_ROOT
LAB_DIR        = os.path.join(MEDIA, 'training/datasets/jorise_lab')
VERSIONS_DIR   = os.path.join(LAB_DIR, 'versions')
MANIFEST       = os.path.join(LAB_DIR, 'manifest.jsonl')
VERSION_HIST   = os.path.join(LAB_DIR, 'version_history.jsonl')

MODELS_DIR     = os.path.join(MEDIA, 'training/models')
ACTIVE_DIR     = os.path.join(MODELS_DIR, 'active')
ARCHIVE_DIR    = os.path.join(MODELS_DIR, 'archive')
REGISTRY       = os.path.join(MODELS_DIR, 'registry.jsonl')

UNIFIED_DIR    = os.path.join(MEDIA, 'training/unified')   # salida de train_multisource.py

# ── Helpers de I/O ──────────────────────────────────────────────────────────

def _read_jsonl(path: str) -> list[dict]:
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


def _print_header(title: str):
    print(f"\n{'='*64}")
    print(f"  {title}")
    print(f"{'='*64}")


def _read_lab_distribution(lab_dir: str) -> tuple[int, dict]:
    """Lee todos los CSVs en lab_dir y retorna (total_rows, {label: count})."""
    dist: dict[str, int] = {}
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


def _balance_score(dist: dict) -> float:
    """
    Score de balance entre 0 y 1.
    1.0 = distribución perfectamente uniforme.
    <0.5 = muy sesgado — reentrenar puede ser contraproducente.
    """
    if not dist:
        return 0.0
    counts = list(dist.values())
    n = len(counts)
    if n == 1:
        return 0.0
    from scipy.stats import entropy
    from numpy import log
    counts_arr = np.array(counts, dtype=float)
    probs = counts_arr / counts_arr.sum()
    e = float(np.sum(-probs * np.log(probs + 1e-12)))
    max_e = float(np.log(n))
    return round(e / max_e if max_e > 0 else 0.0, 3)


# ── Comando: status ─────────────────────────────────────────────────────────

def cmd_status():
    _print_header("JORISE LAB — Estado del Dataset")

    sessions = _read_jsonl(MANIFEST)
    total_rows, dist = _read_lab_distribution(LAB_DIR)
    versions = _read_jsonl(VERSION_HIST)
    registry = _read_jsonl(REGISTRY)

    # Sesiones
    print(f"\n  Sesiones de captura : {len(sessions)}")
    if sessions:
        labels_in_sessions = {}
        tools_used = set()
        contexts_used = set()
        for s in sessions:
            labels_in_sessions[s['label']] = labels_in_sessions.get(s['label'], 0) + 1
            tools_used.add(s.get('tool', 'unknown'))
            contexts_used.add(s.get('context', 'unknown'))
        print(f"  Etiquetas capturadas: {dict(sorted(labels_in_sessions.items()))}")
        print(f"  Herramientas usadas : {sorted(tools_used - {'unknown'}) or ['(sin especificar)']}")
        print(f"  Contextos           : {sorted(contexts_used - {'unknown'}) or ['(sin especificar)']}")
        last = sessions[-1]
        print(f"  Última sesión       : {last['session_id']}  label={last['label']}  flows={last.get('n_flows', '?')}")

    # Distribución de flujos
    print(f"\n  Total flujos en jorise_lab: {total_rows:,}")
    if dist:
        max_count = max(dist.values())
        for lbl, cnt in sorted(dist.items(), key=lambda x: -x[1]):
            pct = cnt / max(total_rows, 1) * 100
            bar = '█' * int(pct / 4)
            flag = ''
            if cnt < max_count * 0.1:
                flag = '  ⚠  MINORITARIA'
            elif pct > 70:
                flag = '  ⚠  DOMINANTE'
            print(f"    {lbl:<16} {cnt:>7,}  ({pct:5.1f}%) {bar}{flag}")

        try:
            bscore = _balance_score(dist)
            print(f"\n  Score de balance    : {bscore:.3f}  (1.0 = perfecto, <0.5 = sesgado)")
            if bscore < 0.4:
                print("  ⚠  ALERTA: dataset muy desbalanceado. Añade sesiones de clases minoritarias.")
            elif bscore < 0.65:
                print("  INFO: balance moderado. Considera más variedad antes de reentrenar.")
            else:
                print("  ✓  Balance aceptable para entrenamiento.")
        except ImportError:
            pass

    # Versiones
    print(f"\n  Versiones creadas   : {len(versions)}")
    if versions:
        last_v = versions[-1]
        print(f"  Última versión      : {last_v['tag']}  ({last_v['timestamp'][:10]})")

    # Modelos
    print(f"\n  Modelos en registro : {len(registry)}")
    if os.path.isdir(ACTIVE_DIR):
        meta_path = os.path.join(ACTIVE_DIR, 'model_meta.json')
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                active_meta = json.load(f)
            acc  = active_meta.get('accuracy', 0) * 100
            f1   = active_meta.get('macro_f1', 0) * 100
            print(f"  Modelo activo       : {active_meta.get('model_id', '?')}")
            print(f"    Accuracy={acc:.1f}%  Macro-F1={f1:.1f}%")
            print(f"    Promovido el: {active_meta.get('promoted_at', '?')[:10]}")
        else:
            print("  Modelo activo       : (ninguno)")
    else:
        print("  Modelo activo       : (ninguno)")

    # Guía
    _print_header("¿Qué hacer ahora?")
    if len(sessions) < 5:
        print(f"  ⏳ Acumula más sesiones. Tienes {len(sessions)}, necesitas al menos 5-10.")
        print(f"     python capture_session.py --label DDoS --intensity high --tool hping3")
    elif not dist or (total_rows > 0 and max(dist.values()) / total_rows > 0.80):
        print(f"  ⚠  El dataset está muy sesgado. Captura más clases minoritarias.")
        lacking = [lbl for lbl, cnt in dist.items() if cnt < max(dist.values()) * 0.2]
        if lacking:
            print(f"     Clases con pocos datos: {lacking}")
    elif not versions:
        print(f"  ✓ Dataset listo. Crea una versión antes de entrenar:")
        print(f"     python lab_pipeline.py version --tag v1.0-baseline")
    else:
        print(f"  ✓ Listo para entrenar:")
        print(f"     python lab_pipeline.py retrain")


# ── Comando: history ─────────────────────────────────────────────────────────

def cmd_history():
    _print_header("JORISE LAB — Historial de Versiones y Modelos")

    versions = _read_jsonl(VERSION_HIST)
    registry = _read_jsonl(REGISTRY)

    print(f"\n  VERSIONES DEL DATASET ({len(versions)})")
    if versions:
        for v in versions:
            print(f"    [{v['tag']}]  {v['timestamp'][:19]}  "
                  f"{v.get('n_files', '?')} archivos  {v.get('total_rows', '?'):,} flujos")
    else:
        print("    (ninguna)")

    print(f"\n  MODELOS ENTRENADOS ({len(registry)})")
    if registry:
        for m in registry:
            acc = m.get('accuracy', 0) * 100
            f1  = m.get('macro_f1', 0) * 100
            promoted = ' ← ACTIVO' if m.get('is_active') else ''
            print(f"    [{m['model_id']}]  {m['trained_at'][:19]}  "
                  f"Acc={acc:.1f}%  F1={f1:.1f}%  sources={m.get('sources','?')}{promoted}")
    else:
        print("    (ninguno)")

    if not versions and not registry:
        print(f"\n  Flujo sugerido:")
        print(f"    1. python capture_session.py --label BENIGN --duration 300")
        print(f"    2. python lab_pipeline.py version --tag v1.0")
        print(f"    3. python lab_pipeline.py retrain")
        print(f"    4. python lab_pipeline.py promote")


# ── Comando: version ─────────────────────────────────────────────────────────

def cmd_version(tag: str | None = None):
    _print_header("JORISE LAB — Crear Versión del Dataset")

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    if not tag:
        tag = f'v_{ts}'
    else:
        # Sanitizar tag
        tag = tag.replace(' ', '_').replace('/', '-')
        if not tag.startswith('v'):
            tag = f'v_{tag}'

    # Verificar que hay datos
    csv_files = [f for f in os.listdir(LAB_DIR) if f.endswith('.csv')] if os.path.isdir(LAB_DIR) else []
    if not csv_files:
        print(f"\n  ERROR: no hay CSVs en {LAB_DIR}")
        print(f"  Primero captura tráfico: python capture_session.py --label BENIGN")
        sys.exit(1)

    # Comprobar que el tag no existe
    versions = _read_jsonl(VERSION_HIST)
    existing_tags = {v['tag'] for v in versions}
    if tag in existing_tags:
        print(f"\n  ERROR: el tag '{tag}' ya existe. Usa un nombre diferente.")
        sys.exit(1)

    # Crear directorio de versión
    version_dir = os.path.join(VERSIONS_DIR, tag)
    os.makedirs(version_dir, exist_ok=True)

    # Copiar CSVs
    total_rows = 0
    dist: dict[str, int] = {}
    copied = []
    for fn in csv_files:
        src = os.path.join(LAB_DIR, fn)
        dst = os.path.join(version_dir, fn)
        shutil.copy2(src, dst)
        copied.append(fn)
        try:
            tmp = pd.read_csv(src, usecols=['Label'])
            for lbl, cnt in tmp['Label'].value_counts().items():
                dist[lbl] = dist.get(lbl, 0) + int(cnt)
                total_rows += int(cnt)
        except Exception:
            pass

    # Copiar manifest
    if os.path.exists(MANIFEST):
        shutil.copy2(MANIFEST, os.path.join(version_dir, 'manifest.jsonl'))

    # Guardar metadata de la versión
    sessions = _read_jsonl(MANIFEST)
    snap_meta = {
        'tag':         tag,
        'timestamp':   datetime.now().isoformat(),
        'n_files':     len(copied),
        'total_rows':  total_rows,
        'distribution': dist,
        'n_sessions':  len(sessions),
        'version_dir': version_dir,
    }
    with open(os.path.join(version_dir, 'snapshot_meta.json'), 'w') as f:
        json.dump(snap_meta, f, indent=2)

    _append_jsonl(VERSION_HIST, snap_meta)

    print(f"\n  Versión creada: {tag}")
    print(f"  Directorio    : {version_dir}")
    print(f"  Archivos      : {len(copied)}")
    print(f"  Total flujos  : {total_rows:,}")
    print(f"  Distribución  :")
    for lbl, cnt in sorted(dist.items(), key=lambda x: -x[1]):
        pct = cnt / max(total_rows, 1) * 100
        print(f"    {lbl:<16} {cnt:>7,}  ({pct:.1f}%)")
    print(f"\n  ✓ Snapshot guardado. Ahora puedes reentrenar con seguridad:")
    print(f"     python lab_pipeline.py retrain")


# ── Comando: retrain ─────────────────────────────────────────────────────────

def cmd_retrain(sources: list[str], sample: int, algorithm: str):
    _print_header("JORISE LAB — Retrain Pipeline")

    # 1. Verificar que hay una versión reciente
    versions = _read_jsonl(VERSION_HIST)
    sessions = _read_jsonl(MANIFEST)

    if not versions:
        print(f"\n  ALERTA: no hay ninguna versión creada del dataset.")
        print(f"  Crea una versión primero para tener trazabilidad:")
        print(f"     python lab_pipeline.py version --tag v1.0")
        ans = input("\n  ¿Continuar sin versionar? (s/N): ").strip().lower()
        if ans != 's':
            print("  Abortado.")
            sys.exit(0)
    else:
        last_v = versions[-1]
        # Comprobar si hay sesiones nuevas desde la última versión
        last_v_ts = last_v['timestamp']
        new_sessions = [s for s in sessions if s.get('timestamp', '') > last_v_ts]
        if new_sessions:
            print(f"\n  INFO: hay {len(new_sessions)} sesión(es) sin versionar desde '{last_v['tag']}'.")
            ans = input("  ¿Crear versión automática antes de entrenar? (S/n): ").strip().lower()
            if ans != 'n':
                auto_tag = f"v_pre_retrain_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
                print(f"\n  Creando versión automática: {auto_tag}")
                cmd_version(auto_tag)

    # 2. Verificar balance mínimo
    total_rows, dist = _read_lab_distribution(LAB_DIR)
    if total_rows < 500:
        print(f"\n  ⚠  Solo {total_rows} flujos en jorise_lab. Puede ser insuficiente.")
        ans = input("  ¿Continuar de todas formas? (s/N): ").strip().lower()
        if ans != 's':
            print("  Abortado.")
            sys.exit(0)

    if dist:
        max_pct = max(dist.values()) / max(total_rows, 1) * 100
        if max_pct > 90:
            majority_lbl = max(dist, key=dist.get)
            print(f"\n  ⚠  ALERTA: '{majority_lbl}' ocupa {max_pct:.0f}% del dataset jorise_lab.")
            print(f"     El modelo puede aprender a clasificar todo como '{majority_lbl}'.")
            ans = input("  ¿Continuar de todas formas? (s/N): ").strip().lower()
            if ans != 's':
                print("  Abortado.")
                sys.exit(0)

    # 3. Determinar fuentes a usar
    if 'jorise_lab' not in sources:
        sources = sources + ['jorise_lab']
    print(f"\n  Fuentes: {sources}")
    print(f"  Sample : {sample}")
    print(f"  Algoritmo: {algorithm}")

    # 4. Lanzar entrenamiento
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_path = os.path.join(MEDIA, f'training/retrain_{ts}.log')

    cmd = [
        sys.executable, 'train_multisource.py',
        '--sources', *sources,
        '--algorithm', algorithm,
        '--sample', str(sample),
        '--cross-eval',
    ]
    print(f"\n  Comando: {' '.join(cmd)}")
    print(f"  Log    : {log_path}")
    print(f"\n  Iniciando entrenamiento...\n")

    import io
    os.makedirs(os.path.dirname(log_path), exist_ok=True)

    env = os.environ.copy()
    env['PYTHONUTF8'] = '1'
    env['PYTHONIOENCODING'] = 'utf-8'

    with open(log_path, 'w', encoding='utf-8') as logf:
        result = subprocess.run(
            cmd, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )
        output = result.stdout.decode('utf-8', errors='replace')
        logf.write(output)
        print(output[-4000:] if len(output) > 4000 else output)

    # 5. Leer resultados del modelo más reciente
    _print_header("Resultados del entrenamiento")

    model_files = sorted(glob.glob(os.path.join(UNIFIED_DIR, '*.pkl')), key=os.path.getmtime, reverse=True)
    model_files = [f for f in model_files if '_scaler' not in f]

    if not model_files:
        print("  ERROR: no se encontró modelo entrenado en unified/")
        sys.exit(1)

    latest_model = model_files[0]
    model_id = f"xgb_{ts}"
    model_basename = os.path.basename(latest_model).replace('.pkl', '')

    # Buscar JSON de métricas generado por train_multisource
    json_candidates = sorted(
        glob.glob(os.path.join(UNIFIED_DIR, '*.json')),
        key=os.path.getmtime, reverse=True
    )
    metrics = {}
    if json_candidates:
        with open(json_candidates[0], encoding='utf-8') as f:
            metrics = json.load(f)

    # Extraer métricas clave del log
    accuracy, macro_f1 = 0.0, 0.0
    for line in output.split('\n'):
        if 'accuracy' in line.lower() and ':' in line:
            try:
                val = float(line.split(':')[-1].strip().rstrip('%')) / 100
                if 0 < val <= 1:
                    accuracy = val
            except Exception:
                pass
        if 'macro f1' in line.lower() and ':' in line:
            try:
                val = float(line.split(':')[-1].strip().rstrip('%')) / 100
                if 0 < val <= 1:
                    macro_f1 = val
            except Exception:
                pass

    # Si el log tiene porcentajes directos (95.74%), normalizar
    for line in output.split('\n'):
        lower = line.lower()
        if 'accuracy' in lower and ':' in line:
            try:
                val = float(line.split(':')[-1].strip().rstrip('%'))
                if 1 < val <= 100:
                    accuracy = val / 100
            except Exception:
                pass
        if 'macro f1' in lower and ':' in line:
            try:
                val = float(line.split(':')[-1].strip().rstrip('%'))
                if 1 < val <= 100:
                    macro_f1 = val / 100
            except Exception:
                pass

    # Comparar con modelo activo
    active_meta_path = os.path.join(ACTIVE_DIR, 'model_meta.json')
    prev_acc, prev_f1 = 0.0, 0.0
    has_active = False
    if os.path.exists(active_meta_path):
        with open(active_meta_path) as f:
            active_meta = json.load(f)
        prev_acc = active_meta.get('accuracy', 0)
        prev_f1  = active_meta.get('macro_f1', 0)
        has_active = True

    print(f"  Modelo entrenado   : {model_basename}")
    print(f"  Accuracy           : {accuracy*100:.2f}%  {'(+' + f'{(accuracy-prev_acc)*100:.2f}' + '%)' if has_active else ''}")
    print(f"  Macro F1           : {macro_f1*100:.2f}%  {'(+' + f'{(macro_f1-prev_f1)*100:.2f}' + '%)' if has_active else ''}")

    if has_active:
        print(f"\n  Modelo activo prev : {active_meta.get('model_id', '?')}")
        print(f"  Accuracy anterior  : {prev_acc*100:.2f}%")
        print(f"  Macro F1 anterior  : {prev_f1*100:.2f}%")

        delta_f1 = macro_f1 - prev_f1
        if delta_f1 > 0.02:
            print(f"\n  ✓ MEJORA SIGNIFICATIVA: Macro F1 +{delta_f1*100:.2f}%")
            print(f"    Considera promover: python lab_pipeline.py promote --model {model_id}")
        elif delta_f1 > 0:
            print(f"\n  ~ Mejora marginal ({delta_f1*100:.2f}%). Revisa métricas por clase.")
        else:
            print(f"\n  ✗ Sin mejora (F1 delta={delta_f1*100:.2f}%). NO promover.")
            print(f"    Captura más datos variados y vuelve a intentarlo.")
    else:
        print(f"\n  (No hay modelo activo previo para comparar)")
        print(f"  Si las métricas son aceptables, promueve con:")
        print(f"    python lab_pipeline.py promote --model {model_id}")

    # 6. Registrar en registry
    scaler_file = latest_model.replace('.pkl', '_scaler.pkl')
    reg_entry = {
        'model_id':      model_id,
        'trained_at':    datetime.now().isoformat(),
        'sources':       sources,
        'sample':        sample,
        'algorithm':     algorithm,
        'accuracy':      accuracy,
        'macro_f1':      macro_f1,
        'model_path':    latest_model,
        'scaler_path':   scaler_file if os.path.exists(scaler_file) else None,
        'log_path':      log_path,
        'is_active':     False,
        'metrics_json':  json_candidates[0] if json_candidates else None,
    }
    _append_jsonl(REGISTRY, reg_entry)

    print(f"\n  Registro guardado. Log completo: {log_path}")
    print(f"  Para ver todos los modelos: python lab_pipeline.py history")


# ── Comando: promote ─────────────────────────────────────────────────────────

def cmd_promote(model_id: str | None):
    _print_header("JORISE LAB — Promover Modelo")

    registry = _read_jsonl(REGISTRY)
    if not registry:
        print("\n  ERROR: no hay modelos registrados.")
        print("  Ejecuta: python lab_pipeline.py retrain")
        sys.exit(1)

    # Encontrar modelo
    if model_id == 'latest' or not model_id:
        entry = registry[-1]
        model_id = entry['model_id']
        print(f"  Usando el modelo más reciente: {model_id}")
    else:
        matching = [e for e in registry if e['model_id'] == model_id]
        if not matching:
            print(f"\n  ERROR: modelo '{model_id}' no encontrado en el registro.")
            print(f"  IDs disponibles: {[e['model_id'] for e in registry]}")
            sys.exit(1)
        entry = matching[-1]

    print(f"\n  Modelo a promover: {entry['model_id']}")
    print(f"  Entrenado el     : {entry['trained_at'][:19]}")
    print(f"  Accuracy         : {entry.get('accuracy', 0)*100:.2f}%")
    print(f"  Macro F1         : {entry.get('macro_f1', 0)*100:.2f}%")
    print(f"  Fuentes          : {entry.get('sources', '?')}")

    # Verificar que los archivos existen
    model_path = entry.get('model_path', '')
    scaler_path = entry.get('scaler_path', '')

    if not os.path.exists(model_path):
        print(f"\n  ERROR: archivo del modelo no encontrado: {model_path}")
        sys.exit(1)

    # Confirmación del operador
    print()
    ans = input("  ¿Promover este modelo como activo? (s/N): ").strip().lower()
    if ans != 's':
        print("  Abortado. El modelo anterior sigue activo.")
        sys.exit(0)

    # Archivar modelo activo anterior (si existe)
    os.makedirs(ACTIVE_DIR, exist_ok=True)
    os.makedirs(ARCHIVE_DIR, exist_ok=True)

    active_model_path = os.path.join(ACTIVE_DIR, 'model.pkl')
    active_scaler_path = os.path.join(ACTIVE_DIR, 'scaler.pkl')
    active_meta_path = os.path.join(ACTIVE_DIR, 'model_meta.json')

    if os.path.exists(active_model_path):
        if os.path.exists(active_meta_path):
            with open(active_meta_path) as f:
                old_meta = json.load(f)
            old_id = old_meta.get('model_id', 'unknown')
        else:
            old_id = 'unknown'
        print(f"  Archivando modelo anterior: {old_id}")
        shutil.copy2(active_model_path, os.path.join(ARCHIVE_DIR, f'{old_id}.pkl'))
        if os.path.exists(active_scaler_path):
            shutil.copy2(active_scaler_path, os.path.join(ARCHIVE_DIR, f'{old_id}_scaler.pkl'))
        if os.path.exists(active_meta_path):
            shutil.copy2(active_meta_path, os.path.join(ARCHIVE_DIR, f'{old_id}_meta.json'))

        # Marcar anterior como no activo en registry
        updated_registry = []
        for r in registry:
            r = dict(r)
            if r.get('is_active'):
                r['is_active'] = False
            updated_registry.append(r)
        # Reescribir registry
        with open(REGISTRY, 'w', encoding='utf-8') as f:
            for r in updated_registry:
                f.write(json.dumps(r, ensure_ascii=False) + '\n')

    # Copiar nuevo modelo a active/
    shutil.copy2(model_path, active_model_path)
    if scaler_path and os.path.exists(scaler_path):
        shutil.copy2(scaler_path, active_scaler_path)

    # Guardar metadata del modelo activo
    promotion_ts = datetime.now().isoformat()
    active_meta = {
        **entry,
        'is_active': True,
        'promoted_at': promotion_ts,
    }
    with open(active_meta_path, 'w') as f:
        json.dump(active_meta, f, indent=2)

    # Actualizar registry para marcar este como activo
    registry_all = _read_jsonl(REGISTRY)
    updated = []
    for r in registry_all:
        r = dict(r)
        if r['model_id'] == model_id:
            r['is_active'] = True
            r['promoted_at'] = promotion_ts
        updated.append(r)
    with open(REGISTRY, 'w', encoding='utf-8') as f:
        for r in updated:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')

    print(f"\n  ✓ Modelo '{model_id}' promovido a activo.")
    print(f"    {active_model_path}")
    print(f"\n  El sistema Jorise usará este modelo en: media/training/models/active/model.pkl")


# ── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Jorise Lab Pipeline — gestión MLOps del dataset incremental',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python lab_pipeline.py status\n"
            "  python lab_pipeline.py history\n"
            "  python lab_pipeline.py version --tag v1.0-ddos-extended\n"
            "  python lab_pipeline.py retrain --sources cicids2017 unsw jorise_lab\n"
            "  python lab_pipeline.py promote --model xgb_20260301_153000\n"
            "  python lab_pipeline.py promote  # promueve el más reciente\n"
        )
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # status
    sub.add_parser('status', help='Estado del dataset, balance, alertas')

    # history
    sub.add_parser('history', help='Historial de versiones y modelos')

    # version
    p_ver = sub.add_parser('version', help='Crear snapshot versionado del dataset')
    p_ver.add_argument('--tag', default=None,
                       help='Nombre de la versión (ej: v1.0-ddos-extended). Default: v_TIMESTAMP')

    # retrain
    p_ret = sub.add_parser('retrain', help='Reentrenar + evaluar + registrar')
    p_ret.add_argument('--sources', nargs='+', default=['cicids2017', 'unsw'],
                       help='Fuentes de datos (default: cicids2017 unsw). jorise_lab se añade siempre.')
    p_ret.add_argument('--sample', type=int, default=20000,
                       help='Máximo de filas por fuente (default: 20000)')
    p_ret.add_argument('--algorithm', default='xgboost',
                       choices=['xgboost', 'random_forest', 'gradient_boosting'],
                       help='Algoritmo (default: xgboost)')

    # promote
    p_pro = sub.add_parser('promote', help='Promover modelo como activo')
    p_pro.add_argument('--model', default='latest',
                       help='ID del modelo a promover (default: "latest")')

    args = parser.parse_args()

    if args.command == 'status':
        cmd_status()
    elif args.command == 'history':
        cmd_history()
    elif args.command == 'version':
        cmd_version(args.tag)
    elif args.command == 'retrain':
        cmd_retrain(args.sources, args.sample, args.algorithm)
    elif args.command == 'promote':
        cmd_promote(args.model)


if __name__ == '__main__':
    main()
