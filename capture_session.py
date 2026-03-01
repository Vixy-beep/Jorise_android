"""
Jorise — Capture Session (v2 MLOps)
====================================
Captura tráfico de red en vivo, extrae features y guarda CSV etiquetado
con metadatos completos de trazabilidad.

FLUJO CORRECTO (disciplina MLOps):
  1. Captura múltiples sesiones con variedad (intensidad, herramienta, contexto)
  2. Acumula suficiente dataset en jorise_lab/
  3. Usa lab_pipeline.py para revisar balance → versionar → reentrenar → evaluar
  4. Promueve el modelo solo si mejora el anterior

⚠️  NO reentrenar automáticamente tras cada captura.
    Eso genera drift caótico. Usa lab_pipeline.py retrain.

Metadata registrada por sesión:
  - timestamp, session_id, label
  - intensity (low/medium/high/unknown)
  - tool (nmap, hping3, slowloris, etc.)
  - context (workday_normal, workday_peak, night_idle, night_loaded, custom)
  - notes (texto libre del operador)
  - n_flows, duration_s, interface, pcap_path

Uso básico:
    # Tráfico normal en horario laboral (baseline)
    python capture_session.py --label BENIGN --duration 300 \\
        --context workday_normal --notes "after lunch, 3 users active"

    # DDoS controlado con hping3
    python capture_session.py --label DDoS --duration 120 \\
        --intensity high --tool hping3 --context workday_peak \\
        --notes "hping3 -S --flood -V -p 80 target_ip"

    # PortScan lento con nmap
    python capture_session.py --label PortScan --duration 180 \\
        --intensity low --tool nmap \\
        --notes "nmap -sS -T2 target_ip"

    # Procesar PCAP existente
    python capture_session.py --label BruteForce --pcap mi_captura.pcap \\
        --tool hydra --intensity medium

    # Ver estado del dataset acumulado
    python lab_pipeline.py status

    # Ver interfaces
    python capture_session.py --list-interfaces

Requisitos:
    - tshark (Wireshark) o tcpdump en PATH
    - dpkt o scapy en el venv (ya instalados)
"""
import django, os, sys, argparse, subprocess, time, shutil, json
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'jorise.settings')
django.setup()

import warnings
warnings.filterwarnings('ignore')

import pandas as pd
import numpy as np
from datetime import datetime
from django.conf import settings

from training.pcap_extractor import extract_features_from_pcap, UNIVERSAL_FEATURES_MAP
from training.dataset_adapters import CANONICAL_LABELS

MEDIA      = settings.MEDIA_ROOT
LAB_DIR    = os.path.join(MEDIA, 'training/datasets/jorise_lab')
PCAP_DIR   = os.path.join(MEDIA, 'training/captures')
MANIFEST   = os.path.join(LAB_DIR, 'manifest.jsonl')   # una línea JSON por sesión

VALID_LABELS = sorted(set(CANONICAL_LABELS.values()) - {'Other'})

VALID_CONTEXTS = [
    'workday_normal',   # horario laboral, carga normal
    'workday_peak',     # horario laboral, carga alta
    'night_idle',       # nocturno, servidor en reposo
    'night_loaded',     # nocturno con background jobs
    'custom',           # describir en --notes
]

VALID_INTENSITIES = ['low', 'medium', 'high', 'unknown']

# Features universales que produce pcap_extractor y necesita el modelo
UNIVERSAL_COLS = [
    'duration', 'total_fwd_pkts', 'total_bwd_pkts',
    'total_fwd_bytes', 'total_bwd_bytes',
    'bytes_per_pkt', 'pkts_per_sec', 'bytes_per_sec',
    'fwd_bwd_pkt_ratio', 'fwd_bwd_byte_ratio',
    'avg_pkt_size',
    'flow_iat_mean', 'flow_iat_std',
    'fwd_iat_mean', 'bwd_iat_mean',
    'fin_flag_cnt', 'syn_flag_cnt', 'rst_flag_cnt',
    'ack_flag_cnt', 'psh_flag_cnt', 'urg_flag_cnt',
    'fwd_psh_flags', 'bwd_psh_flags',
    'ttl_fwd', 'proto_encoded',
]

# Mapeo pcap_extractor → UNIVERSAL_COLS (mismo concepto, distinto nombre)
PCAP_TO_UNIVERSAL = {
    'flow_duration':     'duration',
    'fwd_packets':       'total_fwd_pkts',
    'bwd_packets':       'total_bwd_pkts',
    'fwd_bytes':         'total_fwd_bytes',
    'bwd_bytes':         'total_bwd_bytes',
    'bytes_per_sec':     'bytes_per_sec',
    'packets_per_sec':   'pkts_per_sec',
    'pkt_len_mean':      'avg_pkt_size',
    'flow_iat_mean':     'flow_iat_mean',
    'flow_iat_std':      'flow_iat_std',
    'fwd_iat_mean':      'fwd_iat_mean',
    'bwd_iat_mean':      'bwd_iat_mean',
    'flag_fin':          'fin_flag_cnt',
    'flag_syn':          'syn_flag_cnt',
    'flag_rst':          'rst_flag_cnt',
    'flag_ack':          'ack_flag_cnt',
    'flag_psh':          'psh_flag_cnt',
    'flag_urg':          'urg_flag_cnt',
}


def _find_tool(names: list[str]) -> str | None:
    """Encuentra el primer binario disponible en PATH."""
    for name in names:
        if shutil.which(name):
            return name
    return None


def list_interfaces():
    """Lista interfaces de red disponibles."""
    tshark = _find_tool(['tshark', 'tshark.exe'])
    if tshark:
        try:
            result = subprocess.run(
                [tshark, '-D'],
                capture_output=True, text=True, timeout=10
            )
            print("\nInterfaces disponibles (tshark):")
            print(result.stdout)
            return
        except Exception:
            pass

    # Windows: ipconfig
    if sys.platform == 'win32':
        os.system('ipconfig')
    else:
        os.system('ip link show 2>/dev/null || ifconfig -a')


def capture_with_tshark(interface: str, duration: int, pcap_path: str) -> bool:
    """Captura con tshark. Retorna True si exitoso."""
    tshark = _find_tool(['tshark', 'tshark.exe'])
    if not tshark:
        return False

    cmd = [
        tshark,
        '-i', interface,
        '-a', f'duration:{duration}',
        '-w', pcap_path,
        '-q',                    # silencioso
    ]
    print(f"  [tshark] capturando {duration}s en interfaz '{interface}'...")
    print(f"  Comando: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, timeout=duration + 30, capture_output=True)
        if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0:
            size_mb = os.path.getsize(pcap_path) / 1024 / 1024
            print(f"  Captura completa: {pcap_path} ({size_mb:.1f} MB)")
            return True
        print(f"  ERROR tshark: {result.stderr.decode(errors='replace')[:300]}")
        return False
    except subprocess.TimeoutExpired:
        print("  WARNING: tshark timeout — intentando leer PCAP parcial...")
        return os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def capture_with_tcpdump(interface: str, duration: int, pcap_path: str) -> bool:
    """Captura con tcpdump. Retorna True si exitoso."""
    tcpdump = _find_tool(['tcpdump'])
    if not tcpdump:
        return False

    cmd = [
        'sudo', tcpdump,
        '-i', interface,
        '-G', str(duration),
        '-W', '1',
        '-w', pcap_path,
        '-q',
    ]
    print(f"  [tcpdump] capturando {duration}s en interfaz '{interface}'...")
    try:
        result = subprocess.run(cmd, timeout=duration + 30, capture_output=True)
        return os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 0
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def pcap_to_universal_csv(pcap_path: str, label: str) -> pd.DataFrame | None:
    """
    Convierte PCAP → features universales + columna Label.
    Listo para guardar como CSV y cargar con JoriseLabAdapter.
    """
    print(f"\n  Extrayendo features de {os.path.basename(pcap_path)} ...")

    logs = []
    df_raw = extract_features_from_pcap(
        pcap_path,
        progress_callback=lambda msg: logs.append(msg)
    )

    if df_raw is None or len(df_raw) == 0:
        print("  ERROR: no se extrajeron flujos del PCAP.")
        return None

    print(f"  Flujos crudos: {len(df_raw):,} × {len(df_raw.columns)} columnas")

    # Renombrar columnas al espacio universal
    df_raw = df_raw.rename(columns=PCAP_TO_UNIVERSAL)

    # Calcular features derivadas que pcap_extractor no produce directamente
    fp = df_raw.get('total_fwd_pkts', pd.Series(0, index=df_raw.index))
    bp = df_raw.get('total_bwd_pkts', pd.Series(0, index=df_raw.index))
    fb = df_raw.get('total_fwd_bytes', pd.Series(0, index=df_raw.index))
    bb = df_raw.get('total_bwd_bytes', pd.Series(0, index=df_raw.index))

    df_raw['fwd_bwd_pkt_ratio']  = fp / (bp + 1e-9)
    df_raw['fwd_bwd_byte_ratio'] = fb / (bb + 1e-9)
    df_raw['bytes_per_pkt']      = (fb + bb) / (fp + bp + 1e-9)

    # Features que pcap_extractor no captura → 0 por defecto
    for col in ['fwd_psh_flags', 'bwd_psh_flags', 'ttl_fwd', 'proto_encoded']:
        if col not in df_raw.columns:
            df_raw[col] = 0

    # Construir DataFrame final con solo UNIVERSAL_COLS + Label
    out = pd.DataFrame()
    for col in UNIVERSAL_COLS:
        if col in df_raw.columns:
            out[col] = pd.to_numeric(df_raw[col], errors='coerce').fillna(0)
        else:
            out[col] = 0.0

    out = out.replace([np.inf, -np.inf], np.nan).fillna(0)
    out['Label'] = label

    print(f"  Dataset listo: {len(out):,} flujos × {len(out.columns)} columnas")
    print(f"  Label: {label}")

    return out


def save_to_lab(df: pd.DataFrame, label: str, session_id: str) -> str:
    """Guarda CSV en jorise_lab/ con nombre descriptivo."""
    os.makedirs(LAB_DIR, exist_ok=True)
    filename = f"jorise_lab_{label}_{session_id}.csv"
    path = os.path.join(LAB_DIR, filename)
    df.to_csv(path, index=False)
    size_mb = os.path.getsize(path) / 1024 / 1024
    print(f"\n  CSV guardado: {path} ({size_mb:.2f} MB, {len(df):,} filas)")
    return path


def append_to_manifest(meta: dict):
    """
    Agrega los metadatos de la sesión al manifest.jsonl (una línea por sesión).
    Este archivo es la fuente de verdad del dataset incremental.
    """
    os.makedirs(LAB_DIR, exist_ok=True)
    with open(MANIFEST, 'a', encoding='utf-8') as f:
        f.write(json.dumps(meta, ensure_ascii=False) + '\n')


def load_manifest() -> list[dict]:
    """Carga todas las sesiones del manifest."""
    if not os.path.exists(MANIFEST):
        return []
    sessions = []
    with open(MANIFEST, encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    sessions.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return sessions


def print_lab_status(sessions: list[dict], lab_dir: str):
    """Imprime resumen del estado actual del lab."""
    csv_files = [f for f in os.listdir(lab_dir) if f.endswith('.csv')] if os.path.isdir(lab_dir) else []
    total_rows = 0
    dist: dict[str, int] = {}
    for fn in csv_files:
        try:
            tmp = pd.read_csv(os.path.join(lab_dir, fn), usecols=['Label'])
            for lbl, cnt in tmp['Label'].value_counts().items():
                dist[lbl] = dist.get(lbl, 0) + int(cnt)
                total_rows += int(cnt)
        except Exception:
            pass

    print(f"\n  jorise_lab/ — {len(csv_files)} archivos · {total_rows:,} flujos · {len(sessions)} sesiones")
    if dist:
        max_count = max(dist.values())
        for lbl, cnt in sorted(dist.items(), key=lambda x: -x[1]):
            pct = cnt / max(total_rows, 1) * 100
            bar = '█' * int(pct / 4)
            flag = ' ⚠ desbalanceado' if cnt < max_count * 0.1 else ''
            print(f"    {lbl:<16} {cnt:>7,}  ({pct:5.1f}%) {bar}{flag}")

    if total_rows > 0:
        majority_pct = max(dist.values()) / total_rows * 100
        if majority_pct > 85:
            print(f"\n  ⚠  ALERTA: clase mayoritaria ocupa {majority_pct:.0f}% del dataset.")
            print(f"     Captura más sesiones de clases minoritarias antes de reentrenar.")
        elif len(sessions) < 5:
            print(f"\n  INFO: solo {len(sessions)} sesión(es). Acumula al menos 5-10 antes de reentrenar.")
        else:
            print(f"\n  ✓ Dataset con {len(sessions)} sesiones. Usa lab_pipeline.py retrain para evaluar.")


def print_header(title: str):
    print(f"\n{'='*64}")
    print(f"  {title}")
    print(f"{'='*64}")


def main():
    parser = argparse.ArgumentParser(
        description='Jorise Capture Session v2 — captura, etiqueta y registra tráfico con trazabilidad completa',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Flujo MLOps correcto:\n"
            "  1. Captura múltiples sesiones con variedad\n"
            "  2. python lab_pipeline.py status    # revisar balance\n"
            "  3. python lab_pipeline.py version   # snapshot antes de entrenar\n"
            "  4. python lab_pipeline.py retrain   # entrenar + evaluar\n"
            "  5. python lab_pipeline.py promote   # promover si mejora\n"
        )
    )

    # ── Tráfico ─────────────────────────────────────────────────────────────
    parser.add_argument('--label', '-l', default='BENIGN',
                        choices=VALID_LABELS,
                        help=f'Etiqueta del tráfico: {VALID_LABELS}')
    parser.add_argument('--interface', '-i', default='eth0',
                        help='Interfaz de red. Windows: usar nombre de tshark -D (default: eth0)')
    parser.add_argument('--duration', '-d', type=int, default=120,
                        help='Duración en segundos (default: 120)')
    parser.add_argument('--pcap', default=None,
                        help='Procesar PCAP existente en lugar de capturar en vivo')

    # ── Metadatos de trazabilidad ────────────────────────────────────────────
    parser.add_argument('--intensity', default='unknown', choices=VALID_INTENSITIES,
                        help='Intensidad del ataque/tráfico (default: unknown)')
    parser.add_argument('--tool', default='unknown',
                        help='Herramienta usada (nmap, hping3, hydra, metasploit, etc.)')
    parser.add_argument('--context', default='workday_normal', choices=VALID_CONTEXTS,
                        help='Contexto operacional de la captura (default: workday_normal)')
    parser.add_argument('--notes', default='',
                        help='Notas libres del operador: flags usados, variaciones, etc.')

    # ── Opciones ──────────────────────────────────────────────────────────────
    parser.add_argument('--list-interfaces', action='store_true',
                        help='Listar interfaces disponibles y salir')
    parser.add_argument('--keep-pcap', action='store_true',
                        help='Conservar el .pcap después de extraer features')

    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    t_start = time.time()

    print_header(f"JORISE CAPTURE SESSION v2  [{session_id}]")
    print(f"  Interfaz  : {args.interface}")
    print(f"  Duración  : {args.duration}s")
    print(f"  Etiqueta  : {args.label}")
    print(f"  Intensidad: {args.intensity}")
    print(f"  Herramienta: {args.tool}")
    print(f"  Contexto  : {args.context}")
    if args.notes:
        print(f"  Notas     : {args.notes}")
    print(f"  Destino   : {LAB_DIR}")

    # ── Paso 1: Obtener PCAP ─────────────────────────────────────────────────
    pcap_path = args.pcap
    pcap_is_temp = False

    if pcap_path:
        if not os.path.exists(pcap_path):
            print(f"\nERROR: archivo no encontrado: {pcap_path}")
            sys.exit(1)
        print(f"\n  Usando PCAP existente: {pcap_path}")
        size_mb = os.path.getsize(pcap_path) / 1024 / 1024
        print(f"  Tamaño: {size_mb:.1f} MB")
    else:
        os.makedirs(PCAP_DIR, exist_ok=True)
        pcap_path = os.path.join(PCAP_DIR, f'capture_{session_id}.pcap')
        pcap_is_temp = True

        print_header("Paso 1: Captura de tráfico")
        ok = capture_with_tshark(args.interface, args.duration, pcap_path)
        if not ok:
            ok = capture_with_tcpdump(args.interface, args.duration, pcap_path)
        if not ok:
            print("\n  ERROR: no se encontró tshark ni tcpdump.")
            print("  Instala Wireshark (Windows) o tshark (Linux):")
            print("    Windows: https://www.wireshark.org/download.html")
            print("    Linux:   sudo apt install tshark")
            print("\n  Alternativa: captura con Wireshark y usa --pcap tu_archivo.pcap")
            sys.exit(1)

    # ── Paso 2: Extraer features ─────────────────────────────────────────────
    print_header("Paso 2: Extracción de features")
    df = pcap_to_universal_csv(pcap_path, args.label)

    if df is None or len(df) == 0:
        print("\nERROR: no se obtuvieron flujos. Verifica que el PCAP tiene tráfico IP.")
        sys.exit(1)

    # ── Paso 3: Guardar CSV + metadata ───────────────────────────────────────
    print_header("Paso 3: Guardar dataset + metadata")
    csv_path = save_to_lab(df, args.label, session_id)

    meta = {
        'session_id':  session_id,
        'timestamp':   datetime.now().isoformat(),
        # Tráfico
        'label':       args.label,
        'n_flows':     int(len(df)),
        'duration_s':  args.duration if not args.pcap else None,
        'interface':   args.interface if not args.pcap else None,
        # Trazabilidad
        'intensity':   args.intensity,
        'tool':        args.tool,
        'context':     args.context,
        'notes':       args.notes,
        # Archivos
        'csv_path':    csv_path,
        'pcap_path':   pcap_path if args.keep_pcap else None,
        # Timing
        'elapsed_s':   round(time.time() - t_start, 1),
    }
    append_to_manifest(meta)
    print(f"  Metadata registrada en: {MANIFEST}")

    # ── Paso 4: Estado del lab ───────────────────────────────────────────────
    print_header("Estado del dataset jorise_lab")
    sessions = load_manifest()
    print_lab_status(sessions, LAB_DIR)

    # ── Limpiar PCAP temporal ────────────────────────────────────────────────
    if pcap_is_temp and not args.keep_pcap and os.path.exists(pcap_path):
        os.remove(pcap_path)
        print(f"\n  PCAP temporal eliminado (usa --keep-pcap para conservarlo)")

    # ── Guía de próximos pasos ───────────────────────────────────────────────
    print_header("Próximos pasos")
    n_sess = len(sessions)
    label_counts: dict[str, int] = {}
    for s in sessions:
        label_counts[s['label']] = label_counts.get(s['label'], 0) + s.get('n_flows', 0)

    unique_labels = len(label_counts)
    print(f"  Sesiones acumuladas  : {n_sess}")
    print(f"  Etiquetas distintas  : {unique_labels}")
    print()

    if n_sess < 3:
        print(f"  ⏳ Muy pocas sesiones. Continúa capturando variedad:")
        print(f"     - Distintos horarios (workday vs night)")
        print(f"     - Distintas intensidades (low / medium / high)")
        print(f"     - Distintas herramientas para el mismo tipo de ataque")
    elif unique_labels < 3:
        print(f"  ⚠  Pocas etiquetas distintas ({unique_labels}).")
        print(f"     Agrega sesiones de otros tipos de ataque (DDoS, PortScan, BruteForce...)")
    else:
        print(f"  ✓ Dataset creciendo bien.")
        print(f"     Cuando tengas ≥10 sesiones y ≥3 etiquetas, ejecuta:")
        print()
        print(f"     python lab_pipeline.py status   # balance y alertas")
        print(f"     python lab_pipeline.py version  # snapshot versional")
        print(f"     python lab_pipeline.py retrain  # entrenar + evaluar")
        print()
        print(f"  ⚠  NO reentrenar con train_multisource.py directamente.")
        print(f"     lab_pipeline.py lo hace con gate de evaluación automática.")

    elapsed = time.time() - t_start
    print(f"\n  Sesión completada en {elapsed:.0f}s\n")


if __name__ == '__main__':
    main()
