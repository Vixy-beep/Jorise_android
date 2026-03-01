"""
Jorise v2 - Extractor de Features desde archivos PCAP
Convierte capturas de tráfico de red en matrices de features para ML.

Estrategia:
- Agrupa paquetes en flujos (5-tupla: src_ip, dst_ip, src_port, dst_port, proto)
- Calcula ~25 estadísticas por flujo
- Devuelve un DataFrame listo para entrenar
"""

import os
import logging
from collections import defaultdict

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────
# Estructura interna de un flujo
# ─────────────────────────────────────────────────────────
class _Flow:
    def __init__(self):
        self.fwd_pkts: list[float] = []      # longitudes paquetes fwd
        self.bwd_pkts: list[float] = []      # longitudes paquetes bwd
        self.fwd_times: list[float] = []     # timestamps fwd
        self.bwd_times: list[float] = []     # timestamps bwd
        self.all_times: list[float] = []     # timestamps todos los paquetes (flow IAT)
        self.tcp_flags: list[int] = []       # flags TCP (int) de cada paquete
        self.first_seen: float = 0.0
        self.last_seen: float = 0.0

    def add_packet(self, length: float, timestamp: float, is_fwd: bool, flags: int = 0):
        if self.first_seen == 0.0:
            self.first_seen = timestamp
        self.last_seen = timestamp
        self.tcp_flags.append(flags)
        self.all_times.append(timestamp)
        if is_fwd:
            self.fwd_pkts.append(length)
            self.fwd_times.append(timestamp)
        else:
            self.bwd_pkts.append(length)
            self.bwd_times.append(timestamp)


def _iat_stats(times: list[float]) -> tuple[float, float, float, float]:
    """Devuelve (mean, std, min, max) de inter-arrival times."""
    if len(times) < 2:
        return 0.0, 0.0, 0.0, 0.0
    iats = np.diff(sorted(times)) * 1e6   # convertir a microsegundos
    return float(np.mean(iats)), float(np.std(iats)), float(np.min(iats)), float(np.max(iats))


def _pkt_stats(pkts: list[float]) -> tuple[float, float, float, float]:
    """Devuelve (mean, std, min, max) de longitudes de paquetes."""
    if not pkts:
        return 0.0, 0.0, 0.0, 0.0
    arr = np.array(pkts)
    return float(np.mean(arr)), float(np.std(arr)), float(np.min(arr)), float(np.max(arr))


def _flag_counts(flags_list: list[int]) -> dict[str, int]:
    """Cuenta flags TCP del flujo."""
    counts = dict(fin=0, syn=0, rst=0, psh=0, ack=0, urg=0)
    for f in flags_list:
        if f & 0x01: counts['fin'] += 1
        if f & 0x02: counts['syn'] += 1
        if f & 0x04: counts['rst'] += 1
        if f & 0x08: counts['psh'] += 1
        if f & 0x10: counts['ack'] += 1
        if f & 0x20: counts['urg'] += 1
    return counts


def _flow_to_row(flow: _Flow, key: tuple) -> dict:
    src_ip, dst_ip, src_port, dst_port, proto = key

    all_pkts = flow.fwd_pkts + flow.bwd_pkts
    duration = max((flow.last_seen - flow.first_seen) * 1e6, 1.0)   # µs

    fwd_bytes = sum(flow.fwd_pkts)
    bwd_bytes = sum(flow.bwd_pkts)
    total_bytes = fwd_bytes + bwd_bytes
    fwd_count = len(flow.fwd_pkts)
    bwd_count = len(flow.bwd_pkts)
    total_pkts = fwd_count + bwd_count

    pkt_mean, pkt_std, pkt_min, pkt_max = _pkt_stats(all_pkts)
    fwd_mean, fwd_std, fwd_min, fwd_max = _pkt_stats(flow.fwd_pkts)
    bwd_mean, bwd_std, bwd_min, bwd_max = _pkt_stats(flow.bwd_pkts)
    fiat_mean, fiat_std, fiat_min, fiat_max = _iat_stats(flow.fwd_times)
    biat_mean, biat_std, biat_min, biat_max = _iat_stats(flow.bwd_times)
    flow_iat_mean, flow_iat_std, flow_iat_min, flow_iat_max = _iat_stats(flow.all_times)

    flags = _flag_counts(flow.tcp_flags)

    duration_sec  = duration / 1e6
    bytes_s       = total_bytes / duration_sec if duration_sec > 0 else 0.0
    pkts_s        = total_pkts  / duration_sec if duration_sec > 0 else 0.0
    fwd_pkts_s    = fwd_count   / duration_sec if duration_sec > 0 else 0.0
    bwd_pkts_s    = bwd_count   / duration_sec if duration_sec > 0 else 0.0
    bwd_fwd_ratio = bwd_bytes / fwd_bytes if fwd_bytes > 0 else 0.0

    return {
        'src_ip': src_ip, 'dst_ip': dst_ip,
        'src_port': src_port, 'dst_port': dst_port, 'protocol': proto,
        # Conteos
        'fwd_packets':          fwd_count,
        'bwd_packets':          bwd_count,
        'total_packets':        total_pkts,
        'fwd_bytes':            fwd_bytes,
        'bwd_bytes':            bwd_bytes,
        'total_bytes':          total_bytes,
        # Duración y tasas
        'flow_duration':        duration,
        'bytes_per_sec':        bytes_s,
        'packets_per_sec':      pkts_s,
        'fwd_packets_per_sec':  fwd_pkts_s,
        'bwd_packets_per_sec':  bwd_pkts_s,
        'bwd_fwd_byte_ratio':   bwd_fwd_ratio,
        # Estadísticas longitud paquete (global)
        'pkt_len_mean':         pkt_mean,
        'pkt_len_std':          pkt_std,
        'pkt_len_min':          pkt_min,
        'pkt_len_max':          pkt_max,
        'pkt_len_variance':     pkt_std ** 2,
        # Estadísticas longitud paquete (fwd)
        'fwd_pkt_len_mean':     fwd_mean,
        'fwd_pkt_len_std':      fwd_std,
        'fwd_pkt_len_min':      fwd_min,
        'fwd_pkt_len_max':      fwd_max,
        # Estadísticas longitud paquete (bwd)
        'bwd_pkt_len_mean':     bwd_mean,
        'bwd_pkt_len_std':      bwd_std,
        'bwd_pkt_len_min':      bwd_min,
        'bwd_pkt_len_max':      bwd_max,
        # IAT fwd
        'fwd_iat_mean':         fiat_mean,
        'fwd_iat_std':          fiat_std,
        'fwd_iat_min':          fiat_min,
        'fwd_iat_max':          fiat_max,
        # IAT bwd
        'bwd_iat_mean':         biat_mean,
        'bwd_iat_std':          biat_std,
        'bwd_iat_min':          biat_min,
        'bwd_iat_max':          biat_max,
        # IAT flujo completo
        'flow_iat_mean':        flow_iat_mean,
        'flow_iat_std':         flow_iat_std,
        'flow_iat_min':         flow_iat_min,
        'flow_iat_max':         flow_iat_max,
        # Flags TCP
        'flag_syn':  flags['syn'],
        'flag_fin':  flags['fin'],
        'flag_rst':  flags['rst'],
        'flag_ack':  flags['ack'],
        'flag_psh':  flags['psh'],
        'flag_urg':  flags['urg'],
    }


# ─────────────────────────────────────────────────────────
# Función principal: PCAP → DataFrame
# ─────────────────────────────────────────────────────────
def extract_features_from_pcap(
    pcap_path: str,
    max_packets: int = 0,        # 0 = sin límite (procesa todo el PCAP)
    min_flow_pkts: int = 1,      # 1 = incluir flujos de 1 paquete (ICMP, DNS, DoS)
    progress_callback=None,
) -> pd.DataFrame:
    """
    Lee un archivo PCAP y devuelve un DataFrame con una fila por flujo.
    Usa dpkt como backend principal (~10x más rápido que Scapy).
    Cae a Scapy automáticamente si dpkt falla.

    Args:
        pcap_path:         Ruta al archivo .pcap
        max_packets:       Límite de paquetes (0 = sin límite)
        min_flow_pkts:     Mínimo de paquetes por flujo (1 = incluye todo)
        progress_callback: Función(msg: str) para reportar progreso
    """
    if not os.path.exists(pcap_path):
        raise FileNotFoundError(f"Archivo no encontrado: {pcap_path}")

    try:
        import dpkt as _dpkt
        return _extract_dpkt(pcap_path, max_packets, min_flow_pkts, progress_callback)
    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"dpkt falló ({e}), usando Scapy como fallback…")

    return _extract_scapy(pcap_path, max_packets, min_flow_pkts, progress_callback)


def _build_flows_to_df(flows, min_flow_pkts, _log) -> pd.DataFrame:
    """Convierte el dict de flujos a DataFrame (compartido por ambos backends)."""
    rows = []
    for key, flow in flows.items():
        total = len(flow.fwd_pkts) + len(flow.bwd_pkts)
        if total < min_flow_pkts:
            continue
        rows.append(_flow_to_row(flow, key))

    if not rows:
        _log("No se generaron flujos.")
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    _log(f"DataFrame: {len(df):,} flujos × {len(df.columns)} columnas")
    return df


# ── Backend dpkt (~10x más rápido que Scapy) ─────────────
def _extract_dpkt(pcap_path, max_packets, min_flow_pkts, progress_callback):
    import dpkt
    import socket

    def _log(msg):
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    _log(f"[dpkt] Abriendo PCAP: {pcap_path}")
    flows: dict[tuple, _Flow] = defaultdict(_Flow)
    processed = 0
    skipped = 0

    with open(pcap_path, 'rb') as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except Exception:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)

        for ts, buf in reader:
            if max_packets > 0 and processed >= max_packets:
                _log(f"Límite alcanzado: {max_packets:,} paquetes.")
                break
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                if not isinstance(eth.data, dpkt.ip.IP):
                    skipped += 1
                    continue

                ip       = eth.data
                src_ip   = socket.inet_ntoa(ip.src)
                dst_ip   = socket.inet_ntoa(ip.dst)
                proto    = ip.p
                length   = len(buf)
                flags    = 0
                sp = dp = 0

                if isinstance(ip.data, dpkt.tcp.TCP):
                    t = ip.data; sp, dp, flags = t.sport, t.dport, t.flags
                elif isinstance(ip.data, dpkt.udp.UDP):
                    u = ip.data; sp, dp = u.sport, u.dport

                fwd = (src_ip, dst_ip, sp, dp, proto)
                bwd = (dst_ip, src_ip, dp, sp, proto)
                if fwd in flows:
                    flows[fwd].add_packet(length, ts, True,  flags)
                elif bwd in flows:
                    flows[bwd].add_packet(length, ts, False, flags)
                else:
                    flows[fwd].add_packet(length, ts, True,  flags)

                processed += 1
                if processed % 500_000 == 0:
                    _log(f"Procesados {processed:,} paquetes | {len(flows):,} flujos...")
            except Exception:
                skipped += 1

    _log(f"Total: {processed:,} paquetes | {skipped:,} saltados | {len(flows):,} flujos")
    return _build_flows_to_df(flows, min_flow_pkts, _log)


# ── Backend Scapy (fallback) ──────────────────────────────
def _extract_scapy(pcap_path, max_packets, min_flow_pkts, progress_callback):
    from scapy.all import PcapReader, IP, TCP, UDP

    def _log(msg):
        logger.info(msg)
        if progress_callback:
            progress_callback(msg)

    _log(f"[scapy] Abriendo PCAP: {pcap_path}")
    flows: dict[tuple, _Flow] = defaultdict(_Flow)
    processed = 0
    skipped = 0

    with PcapReader(pcap_path) as reader:
        for pkt in reader:
            if max_packets > 0 and processed >= max_packets:
                _log(f"Límite alcanzado: {max_packets:,} paquetes.")
                break
            try:
                if not pkt.haslayer(IP):
                    skipped += 1
                    continue
                ip = pkt[IP]
                length = len(pkt)
                ts = float(pkt.time)
                flags = sp = dp = 0

                if pkt.haslayer(TCP):
                    t = pkt[TCP]; sp, dp, flags = t.sport, t.dport, int(t.flags)
                elif pkt.haslayer(UDP):
                    u = pkt[UDP]; sp, dp = u.sport, u.dport

                fwd = (ip.src, ip.dst, sp, dp, ip.proto)
                bwd = (ip.dst, ip.src, dp, sp, ip.proto)
                if fwd in flows:
                    flows[fwd].add_packet(length, ts, True,  flags)
                elif bwd in flows:
                    flows[bwd].add_packet(length, ts, False, flags)
                else:
                    flows[fwd].add_packet(length, ts, True,  flags)

                processed += 1
                if processed % 100_000 == 0:
                    _log(f"Procesados {processed:,} paquetes | {len(flows):,} flujos...")
            except Exception:
                skipped += 1

    _log(f"Total: {processed:,} paquetes | {skipped:,} saltados | {len(flows):,} flujos")
    return _build_flows_to_df(flows, min_flow_pkts, _log)


def get_feature_columns() -> list[str]:
    """Devuelve la lista de columnas numéricas usadas como features para ML."""
    return [
        'fwd_packets', 'bwd_packets', 'total_packets',
        'fwd_bytes', 'bwd_bytes', 'total_bytes',
        'flow_duration', 'bytes_per_sec', 'packets_per_sec',
        'fwd_packets_per_sec', 'bwd_packets_per_sec',
        'bwd_fwd_byte_ratio',
        'pkt_len_mean', 'pkt_len_std', 'pkt_len_min', 'pkt_len_max', 'pkt_len_variance',
        'fwd_pkt_len_mean', 'fwd_pkt_len_std', 'fwd_pkt_len_min', 'fwd_pkt_len_max',
        'bwd_pkt_len_mean', 'bwd_pkt_len_std', 'bwd_pkt_len_min', 'bwd_pkt_len_max',
        'fwd_iat_mean', 'fwd_iat_std', 'fwd_iat_min', 'fwd_iat_max',
        'bwd_iat_mean', 'bwd_iat_std', 'bwd_iat_min', 'bwd_iat_max',
        'flow_iat_mean', 'flow_iat_std', 'flow_iat_min', 'flow_iat_max',
        'flag_syn', 'flag_fin', 'flag_rst', 'flag_ack', 'flag_psh', 'flag_urg',
    ]


# Mapeo: columna PCAP → columna CIC-IDS2017 equivalente
# Permite que un modelo entrenado con CSV prediga sobre flujos extraídos de PCAP
# NOTA: los nombres CIC-IDS2017 tienen espacio al inicio (' Flow Duration', etc.)
PCAP_TO_CICIDS = {
    'fwd_packets':          ' Total Fwd Packets',
    'bwd_packets':          ' Total Backward Packets',
    'fwd_bytes':            ' Total Length of Fwd Packets',
    'bwd_bytes':            ' Total Length of Bwd Packets',
    'flow_duration':        ' Flow Duration',
    'bytes_per_sec':        ' Flow Bytes/s',
    'packets_per_sec':      ' Flow Packets/s',
    'fwd_packets_per_sec':  ' Fwd Packets/s',
    'bwd_packets_per_sec':  ' Bwd Packets/s',
    'bwd_fwd_byte_ratio':   ' Down/Up Ratio',
    'pkt_len_mean':         ' Packet Length Mean',
    'pkt_len_std':          ' Packet Length Std',
    'pkt_len_min':          ' Min Packet Length',
    'pkt_len_max':          ' Max Packet Length',
    'pkt_len_variance':     ' Packet Length Variance',
    'fwd_pkt_len_mean':     ' Fwd Packet Length Mean',
    'fwd_pkt_len_std':      ' Fwd Packet Length Std',
    'fwd_pkt_len_min':      ' Fwd Packet Length Min',
    'fwd_pkt_len_max':      ' Fwd Packet Length Max',
    'bwd_pkt_len_mean':     ' Bwd Packet Length Mean',
    'bwd_pkt_len_std':      ' Bwd Packet Length Std',
    'bwd_pkt_len_min':      ' Bwd Packet Length Min',
    'bwd_pkt_len_max':      ' Bwd Packet Length Max',
    'fwd_iat_mean':         ' Fwd IAT Mean',
    'fwd_iat_std':          ' Fwd IAT Std',
    'fwd_iat_min':          ' Fwd IAT Min',
    'fwd_iat_max':          ' Fwd IAT Max',
    'bwd_iat_mean':         ' Bwd IAT Mean',
    'bwd_iat_std':          ' Bwd IAT Std',
    'bwd_iat_min':          ' Bwd IAT Min',
    'bwd_iat_max':          ' Bwd IAT Max',
    'flow_iat_mean':        ' Flow IAT Mean',
    'flow_iat_std':         ' Flow IAT Std',
    'flow_iat_min':         ' Flow IAT Min',
    'flow_iat_max':         ' Flow IAT Max',
    'flag_syn':             ' SYN Flag Count',
    'flag_fin':             ' FIN Flag Count',
    'flag_rst':             ' RST Flag Count',
    'flag_ack':             ' ACK Flag Count',
    'flag_psh':             ' PSH Flag Count',
    'flag_urg':             ' URG Flag Count',
}


def align_to_model_features(df: pd.DataFrame, model_features: list[str]) -> pd.DataFrame:
    """
    Alinea un DataFrame de flujos PCAP a las features que espera un modelo entrenado.

    Si el modelo fue entrenado con CSV CIC-IDS2017 (nombres sin espacios normalizados),
    renombra las columnas PCAP usando PCAP_TO_CICIDS y rellena con 0 lo que falte.

    Args:
        df:             DataFrame de flujos (salida de extract_features_from_pcap)
        model_features: Lista de features que el modelo espera (guardada en TrainedModel)

    Returns:
        DataFrame con exactamente las columnas de model_features, en el mismo orden.
    """
    # Detectar si el modelo usa nombres PCAP nativos o CIC-IDS2017
    overlap_native  = len(set(df.columns) & set(model_features))
    overlap_cicids  = len(set(PCAP_TO_CICIDS.values()) & set(model_features))

    if overlap_native >= overlap_cicids:
        # Modelo entrenado con PCAP → usar columnas como están
        renamed = df
    else:
        # Modelo entrenado con CSV CIC-IDS2017 → renombrar columnas
        renamed = df.rename(columns=PCAP_TO_CICIDS)

    # Construir DataFrame final con exactamente las features del modelo
    result = pd.DataFrame(index=renamed.index)
    for feat in model_features:
        if feat in renamed.columns:
            result[feat] = renamed[feat]
        else:
            result[feat] = 0.0  # feature no disponible → relleno con 0

    return result.fillna(0).replace([float('inf'), float('-inf')], 0)
