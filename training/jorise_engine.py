"""
JoriseEngine — Motor de inteligencia central.

Conecta los modelos ML entrenados (training.TrainedModel) con los módulos
de seguridad: SIEM, WAF, EDR.

Uso típico desde cualquier módulo:
    from training.jorise_engine import JoriseEngine

    result = JoriseEngine.analyze_network_flow(features_dict)
    result = JoriseEngine.analyze_http_request(request_data)
    result = JoriseEngine.analyze_process(process_data)
"""

import logging
import io
import numpy as np
import pandas as pd
import joblib
from functools import lru_cache
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# ── Resultado unificado ────────────────────────────────────────────────────────

@dataclass
class ThreatResult:
    """Resultado normalizado que devuelve el engine a cualquier módulo."""
    threat_score: float          # 0.0 – 1.0
    is_threat: bool
    attack_type: str             # 'BENIGN', 'DoS', 'PortScan', 'WebAttack', etc.
    confidence: float            # 0.0 – 1.0 (confianza del modelo)
    model_name: str              # Qué modelo tomó la decisión
    reasons: List[str] = field(default_factory=list)
    raw_prediction: Any = None   # Predicción raw del modelo

    @property
    def severity(self) -> str:
        if self.threat_score >= 0.8:
            return 'critical'
        if self.threat_score >= 0.6:
            return 'high'
        if self.threat_score >= 0.35:
            return 'medium'
        return 'low'

    def as_dict(self) -> dict:
        return {
            'threat_score':  round(self.threat_score, 4),
            'is_threat':     self.is_threat,
            'attack_type':   self.attack_type,
            'confidence':    round(self.confidence, 4),
            'severity':      self.severity,
            'model_name':    self.model_name,
            'reasons':       self.reasons,
        }


# ── Fallback cuando no hay modelo disponible ──────────────────────────────────

_FALLBACK_RESULT = ThreatResult(
    threat_score=0.0,
    is_threat=False,
    attack_type='UNKNOWN',
    confidence=0.0,
    model_name='fallback_heuristic',
    reasons=['No ML model available — heuristic only'],
)


# ── Selección de modelos ──────────────────────────────────────────────────────

# Orden de preferencia por módulo / tipo de ataque
_MODEL_PREFERENCE = {
    # Módulos de seguridad (genérico)
    'siem':     ['Wednesday-CSV', 'Tuesday-CSV', 'Friday-DDos-CSV'],
    'waf':      ['Thursday-Morning-CSV', 'Thursday-Afternoon-CSV'],
    'edr':      ['Thursday-Afternoon-CSV', 'Friday-Morning-CSV'],
    'network':  ['Wednesday-v2', 'Monday-v2', 'Friday-v2'],
    # Tipos de ataque específicos (routing inteligente)
    'dos':      ['Wednesday-CSV', 'Friday-DDos-CSV'],
    'ddos':     ['Friday-DDos-CSV', 'Wednesday-CSV'],
    'portscan': ['Friday-PortScan-CSV'],
    'bruteforce': ['Tuesday-CSV', 'Thursday-Morning-CSV'],
    'webattack':  ['Thursday-Morning-CSV'],
}


def _load_model(trained_model):
    """Carga modelo + scaler desde FileFields."""
    model_bytes = trained_model.model_file.read()
    clf = joblib.load(io.BytesIO(model_bytes))

    scaler = None
    if trained_model.scaler_file:
        scaler_bytes = trained_model.scaler_file.read()
        scaler = joblib.load(io.BytesIO(scaler_bytes))

    return clf, scaler


def _get_best_model(module: str):
    """
    Devuelve el mejor TrainedModel disponible para el módulo dado.
    Preferencia definida en _MODEL_PREFERENCE; si ninguno está disponible,
    devuelve cualquier modelo activo.
    """
    try:
        from training.models import TrainedModel
        preferences = _MODEL_PREFERENCE.get(module, [])

        for name_prefix in preferences:
            model = TrainedModel.objects.filter(
                name__istartswith=name_prefix,
                is_active=True,
            ).first()
            if model:
                return model

        # Fallback: cualquier modelo activo
        return TrainedModel.objects.filter(is_active=True).first()

    except Exception as e:
        logger.warning(f"[JoriseEngine] No se pudo cargar modelo para '{module}': {e}")
        return None


def _predict(clf, scaler, feature_vector: np.ndarray, feature_names: list = None):
    """Ejecuta predicción y devuelve (label, confidence)."""
    if feature_names is not None:
        # Pasar DataFrame con nombres para satisfacer el scaler entrenado con nombres
        X_df = pd.DataFrame([feature_vector], columns=feature_names)
        X = X_df
    else:
        X = feature_vector.reshape(1, -1)

    if scaler:
        X = scaler.transform(X)

    raw = clf.predict(X)[0]

    # Probabilidades si el modelo las soporta
    confidence = 0.75  # default
    try:
        proba = clf.predict_proba(X)[0]
        confidence = float(np.max(proba))
    except AttributeError:
        pass

    # Isolation Forest devuelve 1 (normal) / -1 (anomalía)
    is_attack = raw == -1 if raw in (-1, 1) else int(raw) == 1

    return is_attack, confidence, raw


# ── Extractores de features ────────────────────────────────────────────────────

def _features_from_dict(features: dict, model_features: list) -> np.ndarray:
    """
    Construye un vector numpy alineado a model_features.
    Rellena con 0 las columnas no disponibles.
    """
    vec = []
    for col in model_features:
        val = features.get(col, features.get(col.strip(), 0.0))
        try:
            vec.append(float(val))
        except (TypeError, ValueError):
            vec.append(0.0)
    return np.array(vec, dtype=np.float32)


# ── Heurísticas HTTP (para WAF sin ML) ───────────────────────────────────────

class HttpThreatResult:
    """
    Resultado de análisis HTTP basado en heurísticas (no ML).
    Los modelos CIC-IDS2017 son de flujos de red y no aplican a payload HTTP.
    """
    SQLI_PATTERNS = [
        r"(\%27)|(\')|(--)|(\%23)|(#)",
        r"\w*(\%27|\')(\%6F|o|\%4F)(\%72|r|\%52)",
        r"(\%27|\'|\")?\s*(union|select|insert|update|delete|drop|exec)\s",
        r"benchmark\s*\(",
        r"sleep\s*\(",
    ]
    XSS_PATTERNS = [
        r"<script[^>]*>.*?</script>",
        r"javascript\s*:",
        r"on\w+\s*=",
        r"<iframe",
        r"eval\s*\(",
    ]
    LFI_PATTERNS = [r"\.\./", r"\.\.%2F", r"/etc/passwd", r"c:\\windows"]
    CMD_PATTERNS = [r";\s*(ls|cat|wget|curl|nc|bash)", r"`.*`", r"\$\(.*\)"]

    @classmethod
    def analyze(cls, request_data: dict) -> 'ThreatResult':
        import re as _re
        url     = request_data.get('url', '')
        body    = request_data.get('body', '')
        headers = request_data.get('headers', {})
        ua      = headers.get('User-Agent', '')
        full    = f"{url} {body}"

        score   = 0.0
        reasons = []

        # SQLi
        for p in cls.SQLI_PATTERNS:
            if _re.search(p, full, _re.IGNORECASE):
                score += 0.35
                reasons.append(f"SQLi pattern: {p[:30]}")
                break
        # XSS
        for p in cls.XSS_PATTERNS:
            if _re.search(p, full, _re.IGNORECASE):
                score += 0.35
                reasons.append(f"XSS pattern: {p[:30]}")
                break
        # LFI
        for p in cls.LFI_PATTERNS:
            if _re.search(p, full, _re.IGNORECASE):
                score += 0.3
                reasons.append("Path traversal / LFI")
                break
        # CMDi
        for p in cls.CMD_PATTERNS:
            if _re.search(p, full, _re.IGNORECASE):
                score += 0.35
                reasons.append("Command injection")
                break
        # Scanner UA
        scanners = ['sqlmap', 'nikto', 'nmap', 'masscan', 'burpsuite', 'metasploit', 'havij']
        if any(s in ua.lower() for s in scanners):
            score += 0.5
            reasons.append(f"Scanner user-agent: {ua[:40]}")
        # Cuerpo enorme
        if len(body) > 100_000:
            score += 0.25
            reasons.append("Body size > 100 KB (posible DoS/upload)")

        score = min(score, 1.0)
        attack_type = 'BENIGN'
        if score > 0:
            if any('SQLi' in r for r in reasons):
                attack_type = 'SQL Injection'
            elif any('XSS' in r for r in reasons):
                attack_type = 'XSS'
            elif any('LFI' in r or 'traversal' in r for r in reasons):
                attack_type = 'LFI'
            elif any('Command' in r for r in reasons):
                attack_type = 'Command Injection'
            elif any('Scanner' in r for r in reasons):
                attack_type = 'Scanning'
            else:
                attack_type = 'WebAttack'

        return ThreatResult(
            threat_score   = round(score, 4),
            is_threat      = score >= 0.3,
            attack_type    = attack_type,
            confidence     = round(min(score + 0.1, 1.0), 4),
            model_name     = 'heuristic_waf',
            reasons        = reasons,
        )


def _extract_network_features(log_data: dict) -> dict:
    """
    Deriva features de red para el modelo CIC-IDS2017.

    CICFlowMeter usa MICROSEGUNDOS para duraciones e IAT.
    Si no se pasa 'duration', se calcula desde packets_per_sec.
    Si no se pasa 'avg_pkt_size', se calcula desde bytes_per_sec / packets_per_sec.
    """
    fwd_pkts  = float(log_data.get('fwd_packets', 1))
    bwd_pkts  = float(log_data.get('bwd_packets', 0))
    fwd_bytes = float(log_data.get('fwd_bytes', 0))
    bps       = float(log_data.get('bytes_per_sec', 0))
    pps       = float(log_data.get('packets_per_sec', 0))
    syn       = float(log_data.get('syn_count', 0))
    rst       = float(log_data.get('rst_count', 0))
    psh       = float(log_data.get('psh_count', 0))
    ack       = float(log_data.get('ack_count', 0))
    total_pkts = fwd_pkts + bwd_pkts

    # ── Duración en MICROSEGUNDOS (unidad de CICFlowMeter) ───────────────────
    # Prioridad: explícito → calculado desde pps → fallback 100ms
    if 'duration' in log_data:
        dur_us = float(log_data['duration'])
    elif pps > 0:
        dur_us = total_pkts / pps * 1_000_000.0
    else:
        dur_us = 100_000.0  # 100 ms

    # ── Tamaño de paquete ─────────────────────────────────────────────────────
    # Si se pasa explícitamente (incluso 0), respetar el valor
    if 'avg_pkt_size' in log_data:
        avg_pkt = float(log_data['avg_pkt_size'])
    else:
        # Inferir desde bytes disponibles
        total_bytes_known = float(log_data.get('fwd_bytes', 0)) + float(log_data.get('bwd_bytes', 0))
        if total_pkts > 0 and total_bytes_known > 0:
            avg_pkt = total_bytes_known / total_pkts
        elif bps > 0 and pps > 0:
            avg_pkt = bps / pps
        else:
            avg_pkt = 100.0

    # ── Bytes/s y paquetes/s inferidos si no se pasaron ──────────────────────
    if bps == 0 and dur_us > 0:
        bps = fwd_bytes / (dur_us / 1_000_000.0)
    if pps == 0 and dur_us > 0:
        pps = total_pkts / (dur_us / 1_000_000.0)

    # ── Promedio por dirección (fwd/bwd), no el combinado ────────────────────
    fwd_pkt_mean = fwd_bytes / fwd_pkts if fwd_pkts > 0 and fwd_bytes > 0 else avg_pkt

    # ── IAT en microsegundos ──────────────────────────────────────────────────
    # Flow IAT Mean = 1/pps en μs (tiempo entre paquetes consecutivos cualquier dirección)
    iat_mean = (1.0 / pps * 1_000_000.0) if pps > 0 else dur_us / max(total_pkts, 1)
    iat_std  = iat_mean * 0.5        # alta varianza real en tráfico mezclado
    iat_max  = dur_us                # el mayor gap puede ser casi toda la duración
    iat_min  = max(iat_mean * 0.05, 1.0)

    # Fwd IAT Total = suma de gaps entre paquetes forward consecutivos.
    # Es mucho MENOR que flow_duration (los paquetes fwd suelen llegar en burst).
    # Estimación conservadora: ~4% de la duración total (calibrado de datos reales).
    fwd_iat_total = dur_us * fwd_pkts / max(total_pkts, 1) * 0.04 if fwd_pkts > 1 else 0.0
    fwd_iat_mean  = fwd_iat_total / max(fwd_pkts - 1, 1) if fwd_pkts > 1 else 0.0
    fwd_iat_std   = fwd_iat_mean * 0.5
    fwd_iat_max   = dur_us * 0.8          # El gap máximo suele ocupar la mayor parte de duración
    fwd_iat_min   = max(fwd_iat_mean * 0.05, 1.0) if fwd_iat_mean > 0 else 0.0

    bwd_iat_total = dur_us * bwd_pkts / max(total_pkts, 1) * 0.10 if bwd_pkts > 1 else 0.0
    bwd_iat_mean  = bwd_iat_total / max(bwd_pkts - 1, 1) if bwd_pkts > 1 else 0.0

    # ── Backward bytes (se necesita para bwd_pkt_max, antes de pkt_max) ─────
    asymmetry = bwd_pkts / max(fwd_pkts, 1)
    if 'bwd_bytes' in log_data:
        bwd_bytes = float(log_data['bwd_bytes'])
    elif bwd_pkts == 0:
        bwd_bytes = 0.0
    elif asymmetry < 0.10:
        bwd_bytes = bwd_pkts * min(avg_pkt * 0.3, 60.0)
    else:
        bwd_bytes = bwd_pkts * avg_pkt * 0.7

    bwd_pkt_mean = bwd_bytes / bwd_pkts if bwd_pkts > 0 else 0.0
    bwd_pkt_std  = bwd_pkt_mean * 3.5    # alta varianza: mezcla de cabeceras pequeñas + payloads grandes
    bwd_pkt_max  = bwd_pkt_mean * 8.0 if bwd_pkts > 0 else 0.0

    # ── Longitud de paquete ───────────────────────────────────────────────────
    pkt_std = float(log_data.get('pkt_len_std', avg_pkt * 3.5))  # alta varianza (DoS: mezcla headers 40B y payloads 1400B)
    pkt_var = pkt_std ** 2
    pkt_max = bwd_pkt_max if bwd_pkt_max > avg_pkt else avg_pkt * 2.0

    # ── Active/Idle ─────────────────────────────────────────────────────────────
    # Active Mean=0 para flujos de única actividad (CICFlowMeter convention)
    # Idle Max ≈ 75% de la duración del flujo (hay largas pausas en DoS Hulk/Slowloris)
    active_mean = 0.0
    idle_max    = dur_us * 0.75
    idle_mean   = idle_max * 0.6
    idle_min    = idle_max * 0.3

    # ── Init window: -1 si no hay paquetes backward (convención CICFlowMeter) ───
    syn_flood = syn > 0 and ack < syn * 0.2   # muy pocos ACK vs SYN = inundación
    no_handshake = bwd_pkts == 0 or syn_flood
    init_win_fwd = float(log_data.get('init_win_fwd', 0 if syn_flood else 65535))
    # CICFlowMeter usa -1 cuando no hay flujo backward (no 0)
    init_win_bwd = float(log_data.get('init_win_bwd', -1 if bwd_pkts == 0 else (272 if syn_flood else 65535)))

    # ── pps por dirección ─────────────────────────────────────────────────────
    fwd_pps = pps * fwd_pkts / max(total_pkts, 1)
    bwd_pps = pps * bwd_pkts / max(total_pkts, 1)

    return {
        'Flow Duration':               dur_us,
        'Total Fwd Packets':           fwd_pkts,
        'Total Backward Packets':      bwd_pkts,
        'Total Length of Fwd Packets': fwd_bytes,
        'Total Length of Bwd Packets': bwd_bytes,
        'Fwd Packet Length Max':       pkt_max,
        'Fwd Packet Length Min':       0.0,
        'Fwd Packet Length Mean':      fwd_pkt_mean,
        'Fwd Packet Length Std':       pkt_std,
        'Bwd Packet Length Max':       bwd_pkt_max,
        'Bwd Packet Length Min':       0.0,
        'Bwd Packet Length Mean':      bwd_pkt_mean,
        'Bwd Packet Length Std':       bwd_pkt_std,
        'Flow Bytes/s':                bps,
        'Flow Packets/s':              pps,
        'Flow IAT Mean':               iat_mean,
        'Flow IAT Std':                iat_std,
        'Flow IAT Max':                iat_max,
        'Flow IAT Min':                iat_min,
        'Fwd IAT Total':               fwd_iat_total,
        'Fwd IAT Mean':                fwd_iat_mean,
        'Fwd IAT Std':                 fwd_iat_std,
        'Fwd IAT Max':                 fwd_iat_max,
        'Fwd IAT Min':                 fwd_iat_min,
        'Bwd IAT Total':               bwd_iat_total,
        'Bwd IAT Mean':                bwd_iat_mean if bwd_pkts > 1 else 0.0,
        'Bwd IAT Std':                 iat_std if bwd_pkts > 1 else 0.0,
        'Bwd IAT Max':                 (dur_us * 0.8) if bwd_pkts > 1 else 0.0,
        'Bwd IAT Min':                 iat_min if bwd_pkts > 1 else 0.0,
        'Fwd PSH Flags':               psh,
        'Bwd PSH Flags':               0.0,
        'Fwd URG Flags':               0.0,
        'Bwd URG Flags':               0.0,
        'Fwd Header Length':           fwd_pkts * 20.0,
        'Bwd Header Length':           bwd_pkts * 20.0,
        'Fwd Packets/s':               fwd_pps,
        'Bwd Packets/s':               bwd_pps,
        'Min Packet Length':           0.0,
        'Max Packet Length':           pkt_max,
        'Packet Length Mean':          (fwd_bytes + bwd_bytes) / max(total_pkts, 1),
        'Packet Length Std':           pkt_std,
        'Packet Length Variance':      pkt_std ** 2,
        'FIN Flag Count':              float(log_data.get('fin_count', 0)),
        'SYN Flag Count':              syn,
        'RST Flag Count':              rst,
        'PSH Flag Count':              psh,
        'ACK Flag Count':              ack,
        'URG Flag Count':              0.0,
        'CWE Flag Count':              0.0,
        'ECE Flag Count':              0.0,
        'Down/Up Ratio':               bwd_pkts / max(fwd_pkts, 1),
        'Average Packet Size':         (fwd_bytes + bwd_bytes) / max(total_pkts, 1),
        'Avg Fwd Segment Size':        fwd_pkt_mean,
        'Avg Bwd Segment Size':        bwd_pkt_mean,
        'Fwd Header Length.1':         fwd_pkts * 20.0,
        'Fwd Avg Bytes/Bulk':          0.0,
        'Fwd Avg Packets/Bulk':        0.0,
        'Fwd Avg Bulk Rate':           0.0,
        'Bwd Avg Bytes/Bulk':          0.0,
        'Bwd Avg Packets/Bulk':        0.0,
        'Bwd Avg Bulk Rate':           0.0,
        'Subflow Fwd Packets':         fwd_pkts,
        'Subflow Fwd Bytes':           fwd_bytes,
        'Subflow Bwd Packets':         bwd_pkts,
        'Subflow Bwd Bytes':           bwd_bytes,
        'Init_Win_bytes_forward':      init_win_fwd,
        'Init_Win_bytes_backward':     init_win_bwd,
        'Init_Win_bytes_backward':     init_win_bwd,
        'act_data_pkt_fwd':            fwd_pkts,
        'min_seg_size_forward':        20.0,
        'Active Mean':                 active_mean,
        'Active Std':                  0.0,
        'Active Max':                  0.0,
        'Active Min':                  0.0,
        'Idle Mean':                   idle_mean,
        'Idle Std':                    idle_max * 0.2,
        'Idle Max':                    idle_max,
        'Idle Min':                    idle_min,
        'Destination Port':            float(log_data.get('dst_port', 0)),
        # ── Aliases lowercase (compatibilidad con modelos pcap_extractor / IsolationForest) ──
        'fwd_packets':                 fwd_pkts,
        'bwd_packets':                 bwd_pkts,
        'total_packets':               total_pkts,
        'fwd_bytes':                   fwd_bytes,
        'bwd_bytes':                   bwd_bytes,
        'total_bytes':                 fwd_bytes + bwd_bytes,
        'flow_duration':               dur_us / 1000.0,
        'bytes_per_sec':               bps,
        'packets_per_sec':             pps,
        'bwd_fwd_byte_ratio':          bwd_bytes / max(fwd_bytes, 1),
        'pkt_len_mean':                (fwd_bytes + bwd_bytes) / max(total_pkts, 1),
        'pkt_len_std':                 pkt_std,
        'pkt_len_min':                 0.0,
        'pkt_len_max':                 pkt_max,
        'fwd_pkt_len_mean':            fwd_pkt_mean,
        'fwd_pkt_len_max':             pkt_max,
        'bwd_pkt_len_mean':            bwd_pkt_mean,
        'bwd_pkt_len_max':             bwd_pkt_max,
        'fwd_iat_mean':                fwd_iat_mean,
        'fwd_iat_std':                 fwd_iat_std,
        'bwd_iat_mean':                bwd_iat_mean,
        'bwd_iat_std':                 iat_std if bwd_pkts > 1 else 0.0,
        'flag_syn':                    syn,
        'flag_fin':                    float(log_data.get('fin_count', 0)),
        'flag_rst':                    rst,
        'flag_ack':                    ack,
        'flag_psh':                    psh,
        'flag_urg':                    0.0,
    }


def _extract_process_features(process_data: dict) -> dict:
    """
    Convierte datos de proceso EDR al espacio CIC-IDS2017.
    Heurística: procesos maliciosos generan mucho tráfico de red inusual.
    """
    path = process_data.get('file_path', '').lower()
    user = process_data.get('user', '').lower()
    name = process_data.get('process_name', '').lower()
    cmd  = process_data.get('command_line', '').lower()
    dur  = float(process_data.get('duration_ms', 100))

    suspicious_paths = sum(p in path for p in ['temp', 'tmp', 'appdata', 'downloads', 'recycle'])
    suspicious_exts  = 1.0 if any(path.endswith(e) for e in ['.tmp', '.bat', '.vbs', '.ps1', '.cmd']) else 0.0
    is_system        = 1.0 if user in ['system', 'nt authority\\system'] else 0.0
    has_net_cmd      = 1.0 if any(kw in cmd for kw in ['curl', 'wget', 'nc', 'iex(', 'downloadstring', 'invoke-expression']) else 0.0
    is_encoded       = 1.0 if '-enc' in cmd or 'base64' in cmd or 'encodedcommand' in cmd else 0.0
    has_pipe         = 1.0 if '|' in cmd else 0.0

    # Proceso malicioso → simula un flujo de red con muchos paquetes pequeños (brute/exfil)
    fwd_pkts  = (suspicious_paths * 100 + has_net_cmd * 500 + is_encoded * 300)
    bwd_pkts  = fwd_pkts * 0.8
    avg_pkt   = 64.0 if is_encoded else 200.0
    bps       = fwd_pkts * avg_pkt / max(dur / 1000, 0.001)
    pps       = fwd_pkts / max(dur / 1000, 0.001)
    syn       = fwd_pkts * 0.3

    features = _extract_network_features({
        'fwd_packets':    fwd_pkts,
        'bwd_packets':    bwd_pkts,
        'fwd_bytes':      fwd_pkts * avg_pkt,
        'avg_pkt_size':   avg_pkt,
        'bytes_per_sec':  bps,
        'packets_per_sec': pps,
        'duration':       dur * 1000,  # ms → µs
        'syn_count':      syn,
        'ack_count':      bwd_pkts,
        'psh_count':      fwd_pkts * 0.5,
        'dst_port':       float(process_data.get('dst_port', 443)),
        'init_win_fwd':   64.0,
    })
    return features


# ── API pública ────────────────────────────────────────────────────────────────

class JoriseEngine:
    """
    Motor de inteligencia de amenazas de Jorise.
    Punto de entrada único para todos los módulos de seguridad.
    """

    @staticmethod
    def analyze_http_request(request_data: dict) -> ThreatResult:
        """
        Analiza una petición HTTP y devuelve un ThreatResult.
        Usado por el módulo WAF.

        Los modelos CIC-IDS2017 son de flujos de red y NO aplican a payload HTTP.
        Esta función usa el analizador heurístico WAF (HttpThreatResult) que sí
        inspecciona el contenido de la petición (SQLi, XSS, LFI, CMDi, scanners).
        """
        return HttpThreatResult.analyze(request_data)

    @staticmethod
    def analyze_network_flow(flow_data: dict) -> ThreatResult:
        """
        Analiza un flujo de red con estrategia ensemble:
        prueba varios modelos especializados y devuelve el de mayor threat_score.

        Acepta dos formatos de entrada:
          1. Log simplificado: {'fwd_packets':N, 'bwd_packets':N, 'packets_per_sec':N, ...}
             → _extract_network_features() convierte a las 69 features CICFlowMeter
          2. Features CICFlowMeter ya calculadas (p. ej. desde la UI de entrenamiento):
             Si flow_data contiene 'Flow Duration' se usan directamente (sin conversión).
        """
        # ── Detección de features CIC ya calculadas ──────────────────────────
        _cicflow_passthrough = 'Flow Duration' in flow_data and 'Bwd Packet Length Mean' in flow_data
        dst_port = int(flow_data.get('dst_port', 0))
        pps      = float(flow_data.get('packets_per_sec', 0))

        # Candidatos en orden: siempre probar Wednesday-CSV (DoS) y
        # Friday-PortScan-CSV; si es puerto de servicios, añadir Tuesday-CSV
        candidate_keys: list[str] = ['siem', 'portscan']
        if dst_port in (22, 21, 23, 3389, 5900):
            candidate_keys.insert(0, 'bruteforce')
        if pps > 5000:
            candidate_keys.insert(0, 'ddos')

        best: ThreatResult = _FALLBACK_RESULT

        for key in candidate_keys:
            tm = _get_best_model(key)
            if tm is None:
                continue
            try:
                clf, scaler = _load_model(tm)
                if _cicflow_passthrough:
                    # Features CICFlowMeter ya calculadas → usar directamente
                    features = flow_data
                else:
                    features = _extract_network_features(flow_data)
                vec = _features_from_dict(features, tm.features_json)
                fn  = tm.features_json

                X = pd.DataFrame([vec], columns=fn)
                if scaler:
                    X = scaler.transform(X)

                # Obtener probabilidad de ataque directamente (no el threshold 50% del clf)
                try:
                    proba = clf.predict_proba(X)[0]
                    attack_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])
                except AttributeError:
                    # IsolationForest (no predict_proba): usar predict directamente
                    raw_pred = clf.predict(X)[0]
                    attack_prob = 0.70 if raw_pred == -1 else 0.10

                # Con features sintéticas el threshold es 20%; con CICFlowMeter real, 50%
                THRESHOLD = 0.50 if _cicflow_passthrough else 0.20
                is_attack = attack_prob >= THRESHOLD

                result = ThreatResult(
                    threat_score   = round(attack_prob, 4),
                    is_threat      = is_attack,
                    attack_type    = 'BENIGN',
                    confidence     = attack_prob,
                    model_name     = tm.name,
                    raw_prediction = attack_prob,
                )
                if result.threat_score > best.threat_score:
                    best = result
            except Exception as e:
                logger.error(f"[JoriseEngine.analyze_network_flow/{key}] {e}")

        if best.is_threat:
            if 'PortScan' in best.model_name:
                best.attack_type = 'PortScan'
            elif 'Tuesday' in best.model_name:
                best.attack_type = 'SSH-BruteForce' if dst_port == 22 else 'BruteForce'
            elif 'DDos' in best.model_name or 'DDoS' in best.model_name:
                best.attack_type = 'DDoS'
            else:
                # Fallback: inferir por puerto
                if dst_port in (80, 8080):
                    best.attack_type = 'DoS Hulk'
                elif dst_port == 443:
                    best.attack_type = 'DoS HTTPS'
                elif dst_port == 22:
                    best.attack_type = 'SSH-BruteForce'
                elif dst_port == 21:
                    best.attack_type = 'FTP-BruteForce'
                else:
                    best.attack_type = 'NetworkAttack'

        return best

    @staticmethod
    def analyze_process(process_data: dict) -> ThreatResult:
        """
        Analiza un proceso del sistema (EDR).
        Combina detección ML con heurísticas de comportamiento del proceso.
        """
        tm = _get_best_model('edr')

        # ── Heurísticas de comportamiento ────────────────────────────────────
        reasons = []
        path = process_data.get('file_path', '').lower()
        cmd  = process_data.get('command_line', '').lower()
        user = process_data.get('user', '').lower()

        if any(p in path for p in ['temp', 'tmp', 'appdata', 'downloads']):
            reasons.append("Ejecución desde directorio temporal")
        if any(kw in cmd for kw in ['curl', 'wget', 'iex(', 'downloadstring', 'invoke-expression']):
            reasons.append("Comando con patrones de descarga/ejecución remota")
        if '-enc' in cmd or 'encodedcommand' in cmd or 'base64' in cmd.lower():
            reasons.append("Comando PowerShell con payload encoded (Base64)")
        if user in ('system', 'nt authority\\system'):
            reasons.append("Ejecución como SYSTEM")
        if any(path.endswith(e) for e in ['.tmp', '.bat', '.vbs', '.ps1', '.cmd', '.scr']):
            reasons.append("Extensión de archivo sospechosa")
        if 'powershell' in path or 'wscript' in path or 'cscript' in path:
            reasons.append("Intérprete de scripts potencialmente malicioso")

        # Score heurístico: cada indicador suma 0.20 (máx. 0.90)
        heuristic_score = min(len(reasons) * 0.20, 0.90)

        # ── ML (opcional) ─────────────────────────────────────────────────────
        ml_score = 0.0
        ml_model_name = 'heuristic_only'
        if tm is not None:
            try:
                clf, scaler = _load_model(tm)
                features = _extract_process_features(process_data)
                vec = _features_from_dict(features, tm.features_json)
                fn  = tm.features_json
                X = pd.DataFrame([vec], columns=fn)
                if scaler:
                    X = scaler.transform(X)
                try:
                    proba = clf.predict_proba(X)[0]
                    ml_score = float(proba[1]) if len(proba) > 1 else float(proba[0])
                except AttributeError:
                    raw_pred = clf.predict(X)[0]
                    ml_score = 0.70 if raw_pred == -1 else 0.10
                ml_model_name = tm.name
            except Exception as e:
                logger.error(f"[JoriseEngine.analyze_process] {e}")

        # Score final: máximo entre heurístico y ML
        final_score = max(heuristic_score, ml_score)
        is_threat   = final_score >= 0.20  # umbral 20%

        return ThreatResult(
            threat_score    = round(final_score, 4),
            is_threat       = is_threat,
            attack_type     = 'Malware/Suspicious' if is_threat else 'BENIGN',
            confidence      = final_score,
            model_name      = ml_model_name,
            reasons         = reasons,
            raw_prediction  = ml_score,
        )

    @staticmethod
    def enrich_anomaly_score(base_score: float, base_reasons: list,
                              log_data: dict) -> tuple[float, list]:
        """
        Enriquece un score de anomalía heurístico con la decisión del modelo ML.
        Retorna (nuevo_score, nueva_lista_de_razones).

        log_data puede incluir campos de flujo de red (fwd_packets, dst_port, etc.)
        o valores SIEM agregados (recent_count). Se normaliza internamente a
        un flujo por evento para que los modelos CIC-IDS2017 funcionen.
        """
        # Construir un flujo representativo a partir de métricas del evento SIEM
        # Los modelos esperan estadísticas por-flujo (no totales agregados)
        recent_count = log_data.get('fwd_packets', log_data.get('recent_count', 1))

        # Si los datos son estadísticas de log (no flujo), construir flujo promedio
        if 'recent_count' in log_data and 'fwd_packets' not in log_data:
            # Estimar un flujo HTTP típico derivado de la tasa de eventos
            rate = log_data.get('packets_per_sec', recent_count / 300.0)
            flow_data = {
                'fwd_packets':     min(max(int(rate * 0.5), 1), 50),  # flujo individual
                'bwd_packets':     min(max(int(rate * 0.3), 0), 40),
                'fwd_bytes':       min(max(int(rate * 0.5 * 800), 40), 75000),
                'bytes_per_sec':   log_data.get('bytes_per_sec', rate * 800),
                'packets_per_sec': rate,
                'dst_port':        log_data.get('dst_port', 80),
                'syn_count':       min(int(rate * 0.5), 50),
                'ack_count':       min(int(rate * 0.3), 40),
                'psh_count':       min(int(rate * 0.3), 40),
            }
        else:
            flow_data = log_data

        ml_result = JoriseEngine.analyze_network_flow(flow_data)

        if ml_result.model_name == 'fallback_heuristic':
            return base_score, base_reasons

        combined_reasons = list(base_reasons)

        if ml_result.is_threat:
            # Combinación: 60% heurística + 40% ML
            new_score = base_score * 0.6 + ml_result.threat_score * 0.4
            combined_reasons.append(
                f"[Jorise ML — {ml_result.model_name}] "
                f"Ataque detectado: {ml_result.attack_type} "
                f"(confianza {ml_result.confidence:.0%})"
            )
        else:
            # ML dice que es benigno → reduce score ligeramente
            new_score = base_score * 0.8
            combined_reasons.append(
                f"[Jorise ML — {ml_result.model_name}] "
                f"Tráfico clasificado como benigno (confianza {ml_result.confidence:.0%})"
            )

        return round(min(new_score, 1.0), 4), combined_reasons
