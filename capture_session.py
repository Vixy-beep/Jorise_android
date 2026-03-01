"""
Jorise — Capture Session
Captura tráfico de red en vivo, extrae features y guarda CSV etiquetado
listo para reentrenar el modelo.

El ciclo completo:
  1. Captura N segundos de tráfico en la interfaz indicada (tshark o tcpdump)
  2. Convierte el .pcap a flujos con features universales (pcap_extractor)
  3. Asigna la etiqueta que el operador indica (BENIGN, DDoS, PortScan, ...)
  4. Guarda CSV en media/training/datasets/jorise_lab/
  5. Opcionalmente relanza el entrenamiento con la nueva data

Uso básico:
    # Capturar tráfico normal (benign) por 5 minutos
    .venv\\Scripts\\python.exe capture_session.py --label BENIGN --duration 300

    # Capturar durante un ataque DDoS controlado
    .venv\\Scripts\\python.exe capture_session.py --label DDoS --duration 60 --interface eth0

    # Ver interfaces disponibles
    .venv\\Scripts\\python.exe capture_session.py --list-interfaces

    # Después de varias capturas, reentrenar con la data propia:
    .venv\\Scripts\\python.exe train_multisource.py --sources cicids2017 unsw jorise_lab --cross-eval

Requisitos:
    - tshark (parte de Wireshark) o tcpdump instalado y en PATH
    - dpkt o scapy en el venv (ya instalados)

Instalación tshark:
    Windows: instalar Wireshark desde https://www.wireshark.org/download.html
             (marcar la opción "TShark" durante la instalación)
    Linux:   sudo apt install tshark
    VPS:     sudo apt install tshark -y
"""
import django, os, sys, argparse, subprocess, time, shutil, tempfile, json
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
PCAP_DIR   = os.path.join(MEDIA, 'training/captures')   # temp storage para .pcap

VALID_LABELS = sorted(set(CANONICAL_LABELS.values()) - {'Other'})

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


def save_session_meta(session_id: str, meta: dict):
    """Guarda metadatos de la sesión en JSON."""
    os.makedirs(LAB_DIR, exist_ok=True)
    meta_path = os.path.join(LAB_DIR, f'session_{session_id}.json')
    with open(meta_path, 'w') as f:
        json.dump(meta, f, indent=2)


def print_header(title: str):
    print(f"\n{'='*64}")
    print(f"  {title}")
    print(f"{'='*64}")


def main():
    parser = argparse.ArgumentParser(
        description='Jorise Capture Session — captura y etiqueta tráfico de red'
    )
    parser.add_argument('--interface', '-i', default='eth0',
                        help='Interfaz de red (default: eth0). Windows: usa el nombre de tshark -D')
    parser.add_argument('--duration', '-d', type=int, default=120,
                        help='Duración de captura en segundos (default: 120)')
    parser.add_argument('--label', '-l', default='BENIGN',
                        choices=VALID_LABELS,
                        help=f'Etiqueta de tráfico: {VALID_LABELS}')
    parser.add_argument('--pcap', default=None,
                        help='Usar un .pcap existente en lugar de capturar')
    parser.add_argument('--list-interfaces', action='store_true',
                        help='Listar interfaces disponibles y salir')
    parser.add_argument('--retrain', action='store_true',
                        help='Reentrenar modelo después de guardar (cicids2017 + unsw + jorise_lab)')
    parser.add_argument('--keep-pcap', action='store_true',
                        help='No borrar el .pcap temporal después de extraer features')
    args = parser.parse_args()

    if args.list_interfaces:
        list_interfaces()
        return

    session_id = datetime.now().strftime('%Y%m%d_%H%M%S')
    t_start = time.time()

    print_header(f"JORISE CAPTURE SESSION  [{session_id}]")
    print(f"  Interfaz  : {args.interface}")
    print(f"  Duración  : {args.duration}s")
    print(f"  Etiqueta  : {args.label}")
    print(f"  Destino   : {LAB_DIR}")

    # ── Paso 1: Obtener PCAP ────────────────────────────────────────────────
    pcap_path = args.pcap

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

        print_header("Paso 1: Captura de tráfico")

        ok = capture_with_tshark(args.interface, args.duration, pcap_path)
        if not ok:
            ok = capture_with_tcpdump(args.interface, args.duration, pcap_path)
        if not ok:
            print("\n  ERROR: no se encontró tshark ni tcpdump.")
            print("  Instala Wireshark (Windows) o tshark (Linux):")
            print("    Windows: https://www.wireshark.org/download.html")
            print("    Linux:   sudo apt install tshark")
            print("\n  Alternativa: captura manualmente con Wireshark y usa --pcap tu_archivo.pcap")
            sys.exit(1)

    # ── Paso 2: Extraer features ────────────────────────────────────────────
    print_header("Paso 2: Extracción de features")
    df = pcap_to_universal_csv(pcap_path, args.label)

    if df is None or len(df) == 0:
        print("\nERROR: no se obtuvieron flujos. Verifica que el PCAP tiene tráfico IP.")
        sys.exit(1)

    # Estadísticas rápidas
    n_total = len(df)
    print(f"\n  Distribución de flujos:")
    print(f"    {args.label:<20} {n_total:>8,}  (100.0%)")

    # ── Paso 3: Guardar ─────────────────────────────────────────────────────
    print_header("Paso 3: Guardar dataset")
    csv_path = save_to_lab(df, args.label, session_id)

    # Resumen del lab completo
    lab_files = [f for f in os.listdir(LAB_DIR) if f.endswith('.csv')]
    lab_rows  = 0
    lab_dist  = {}
    for fn in lab_files:
        try:
            tmp = pd.read_csv(os.path.join(LAB_DIR, fn), usecols=['Label'])
            for lbl, cnt in tmp['Label'].value_counts().items():
                lab_dist[lbl] = lab_dist.get(lbl, 0) + cnt
                lab_rows += cnt
        except Exception:
            pass

    print(f"\n  Estado actual de jorise_lab/:")
    print(f"    Archivos : {len(lab_files)}")
    print(f"    Total    : {lab_rows:,} filas")
    for lbl, cnt in sorted(lab_dist.items(), key=lambda x: -x[1]):
        pct = cnt / max(lab_rows, 1) * 100
        bar = '█' * int(pct / 5)
        print(f"    {lbl:<15} {cnt:>7,}  ({pct:.1f}%) {bar}")

    # Guardar metadatos
    meta = {
        'session_id':  session_id,
        'label':       args.label,
        'interface':   args.interface,
        'duration_s':  args.duration,
        'n_flows':     n_total,
        'csv_path':    csv_path,
        'pcap_path':   pcap_path if args.keep_pcap else None,
        'timestamp':   datetime.now().isoformat(),
        'elapsed_s':   round(time.time() - t_start, 1),
    }
    save_session_meta(session_id, meta)

    # Limpiar PCAP temporal
    if not args.keep_pcap and not args.pcap and os.path.exists(pcap_path):
        os.remove(pcap_path)
        print(f"\n  PCAP temporal eliminado (usa --keep-pcap para conservarlo)")

    # ── Paso 4 (opcional): Reentrenar ───────────────────────────────────────
    if args.retrain:
        print_header("Paso 4: Reentrenamiento automático")

        sources = ['cicids2017']
        unsw_dir = os.path.join(MEDIA, 'training/datasets/unsw')
        if os.path.isdir(unsw_dir) and any(f.endswith('.csv') for f in os.listdir(unsw_dir)):
            sources.append('unsw')
        sources.append('jorise_lab')

        print(f"  Fuentes: {sources}")
        cmd = [
            sys.executable, 'train_multisource.py',
            '--sources', *sources,
            '--algorithm', 'xgboost',
            '--sample', '20000',
            '--cross-eval',
        ]
        print(f"  Comando: {' '.join(cmd)}")
        subprocess.run(cmd)
    else:
        print_header("Listo")
        print(f"  Para reentrenar con esta nueva data:")
        print(f"  .venv\\Scripts\\python.exe train_multisource.py --sources cicids2017 unsw jorise_lab --cross-eval")
        print(f"\n  O simplemente añade --retrain a la próxima captura.")

    elapsed = time.time() - t_start
    print(f"\n  Sesión completada en {elapsed:.0f}s\n")


if __name__ == '__main__':
    main()
