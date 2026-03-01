"""
Dataset Adapters — Normalize public IDS datasets to a common feature space.

Each dataset has different column names and label schemes.
Every adapter outputs the SAME canonical DataFrame regardless of source.

Supported:
    - CIC-IDS2017 (existing)
    - UNSW-NB15
    - CTU-13 (NetFlow)
    - CICIOT2023

Universal feature set (~25 features derivable from all sources):
    duration, total_fwd_pkts, total_bwd_pkts, total_fwd_bytes, total_bwd_bytes,
    bytes_per_pkt, pkts_per_sec, bytes_per_sec, fwd_bwd_pkt_ratio, fwd_bwd_byte_ratio,
    avg_pkt_size, flow_iat_mean, flow_iat_std, fwd_iat_mean, bwd_iat_mean,
    fwd_psh_flags, bwd_psh_flags, fin_flag_cnt, syn_flag_cnt, rst_flag_cnt,
    ack_flag_cnt, psh_flag_cnt, urg_flag_cnt, ttl_fwd, proto_encoded

Download instructions per dataset are printed by calling adapter.download_info().
"""
import os
import numpy as np
import pandas as pd

# ── Canonical classes (same as unified_dataset.py) ───────────────────────────
# Every adapter maps its labels to this set.
CANONICAL_LABELS = {
    'benign': 'BENIGN',
    'normal': 'BENIGN',
    '0': 'BENIGN',
    # DDoS
    'ddos': 'DDoS',
    'ddos attacks-loic-http': 'DDoS',
    'backdoor': 'DDoS',           # CTU-13 botnet DDoS
    # DoS
    'dos hulk': 'DoS',
    'dos goldeneye': 'DoS',
    'dos slowloris': 'DoS',
    'dos slowhttptest': 'DoS',
    'heartbleed': 'DoS',
    'generic': 'DoS',             # UNSW-NB15
    'exploits': 'DoS',            # UNSW-NB15
    # PortScan
    'portscan': 'PortScan',
    'port scan': 'PortScan',
    'reconnaissance': 'PortScan', # UNSW-NB15
    # BruteForce
    'ftp-patator': 'BruteForce',
    'ssh-patator': 'BruteForce',
    'brute force': 'BruteForce',
    # WebAttack
    'web attack \x96 brute force': 'WebAttack',
    'web attack – brute force': 'WebAttack',
    'web attack brute force': 'WebAttack',
    'web attack \x96 xss': 'WebAttack',
    'web attack – xss': 'WebAttack',
    'web attack xss': 'WebAttack',
    'web attack \x96 sql injection': 'WebAttack',
    'web attack – sql injection': 'WebAttack',
    'web attack sql injection': 'WebAttack',
    'xss': 'WebAttack',
    'sql injection': 'WebAttack',
    # Infiltration / APT
    'infiltration': 'Infiltration',
    'shellcode': 'Infiltration',  # UNSW-NB15
    'worms': 'Infiltration',      # UNSW-NB15
    'fuzzers': 'Infiltration',    # UNSW-NB15
    # Bot / Malware
    'bot': 'Bot',
    'botnet': 'Bot',              # CTU-13
    'backdoors': 'Bot',           # UNSW-NB15
    'analysis': 'Bot',            # UNSW-NB15 (network analysis tools)
    # IoT-specific (CICIOT2023)
    'mirai': 'DDoS',
    'gamarue': 'Bot',
    'ares': 'Bot',
    'command injection': 'WebAttack',
    'uploading': 'Infiltration',
    'xss_iot': 'WebAttack',
    'ddos-udpflood': 'DDoS',
    'ddos-tcpflood': 'DDoS',
    'ddos-httpflood': 'DDoS',
    'ddos-icmpflood': 'DDoS',
    'ddos-synflood': 'DDoS',
    'dos-synflood': 'DoS',
    'dos-udpflood': 'DoS',
    'recon-portscan': 'PortScan',
    'recon-osscan': 'PortScan',
    'recon-hostdiscovery': 'PortScan',
    'recon-vulnerabilityscan': 'PortScan',
    'mitm-arpspoofing': 'Infiltration',
    'dns-spoofing': 'Infiltration',
    'mqtt-publish': 'Bot',
}

# ── Universal feature set output by every adapter ────────────────────────────
UNIVERSAL_FEATURES = [
    'duration',
    'total_fwd_pkts',
    'total_bwd_pkts',
    'total_fwd_bytes',
    'total_bwd_bytes',
    'bytes_per_pkt',
    'pkts_per_sec',
    'bytes_per_sec',
    'fwd_bwd_pkt_ratio',
    'fwd_bwd_byte_ratio',
    'avg_pkt_size',
    'flow_iat_mean',
    'flow_iat_std',
    'fwd_iat_mean',
    'bwd_iat_mean',
    'fin_flag_cnt',
    'syn_flag_cnt',
    'rst_flag_cnt',
    'ack_flag_cnt',
    'psh_flag_cnt',
    'urg_flag_cnt',
    'fwd_psh_flags',
    'bwd_psh_flags',
    'ttl_fwd',
    'proto_encoded',
]


def _safe(df: pd.DataFrame, col: str, default=0.0) -> pd.Series:
    return df[col] if col in df.columns else pd.Series(default, index=df.index)


def _encode_proto(series: pd.Series) -> pd.Series:
    """Map protocol name/number to integer code."""
    mapping = {'tcp': 6, 'udp': 17, 'icmp': 1, '6': 6, '17': 17, '1': 1}
    return pd.to_numeric(
        series.astype(str).str.lower().map(mapping),
        errors='coerce'
    ).fillna(0).astype(int)


def normalize_label(raw: str) -> str:
    key = str(raw).strip().lower()
    if key in CANONICAL_LABELS:
        return CANONICAL_LABELS[key]
    for k, v in CANONICAL_LABELS.items():
        if k in key:
            return v
    return 'Other'


def _clean(df: pd.DataFrame) -> pd.DataFrame:
    """Replace Inf/NaN and clip extreme values."""
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
    for col in df.select_dtypes(include=[np.number]).columns:
        df[col] = df[col].clip(lower=0)
    return df


# ─────────────────────────────────────────────────────────────────────────────
# ADAPTER: CIC-IDS2017
# Already handled by unified_dataset.py — passthrough adapter for consistency.
# ─────────────────────────────────────────────────────────────────────────────

class CICIDS2017Adapter:
    """Adapter for the original CIC-IDS2017 dataset (existing pipeline)."""
    NAME = 'CIC-IDS2017'

    def download_info(self):
        return (
            "CIC-IDS2017 — Already in media/training/datasets/\n"
            "Source: https://www.unb.ca/cic/datasets/ids-2017.html\n"
            "8 CSVs, 2.8 GB total. Already downloaded."
        )

    def load(self, csv_path: str, n: int = 15000) -> tuple[pd.DataFrame, pd.Series]:
        """Load one CIC-IDS2017 CSV, return (X_universal, y_canonical)."""
        df = pd.read_csv(csv_path, low_memory=False)
        df.columns = df.columns.str.strip()
        if 'Label' not in df.columns:
            raise ValueError(f"No Label column in {csv_path}")

        y = df['Label'].apply(normalize_label)

        # Map CIC-IDS2017 native columns → universal
        dur = _safe(df, 'Flow Duration', 0) / 1e6   # microseconds → seconds
        fp  = _safe(df, 'Total Fwd Packets', 0)
        bp  = _safe(df, 'Total Backward Packets', 0)
        fb  = _safe(df, 'Total Length of Fwd Packets', 0)
        bb  = _safe(df, 'Total Length of Bwd Packets', 0)

        total_pkts  = fp + bp + 1e-9
        total_bytes = fb + bb + 1e-9

        out = pd.DataFrame({
            'duration':           dur,
            'total_fwd_pkts':     fp,
            'total_bwd_pkts':     bp,
            'total_fwd_bytes':    fb,
            'total_bwd_bytes':    bb,
            'bytes_per_pkt':      total_bytes / total_pkts,
            'pkts_per_sec':       total_pkts / (dur + 1e-9),
            'bytes_per_sec':      total_bytes / (dur + 1e-9),
            'fwd_bwd_pkt_ratio':  fp / (bp + 1e-9),
            'fwd_bwd_byte_ratio': fb / (bb + 1e-9),
            'avg_pkt_size':       _safe(df, 'Average Packet Size', 0),
            'flow_iat_mean':      _safe(df, 'Flow IAT Mean', 0) / 1e6,
            'flow_iat_std':       _safe(df, 'Flow IAT Std', 0) / 1e6,
            'fwd_iat_mean':       _safe(df, 'Fwd IAT Mean', 0) / 1e6,
            'bwd_iat_mean':       _safe(df, 'Bwd IAT Mean', 0) / 1e6,
            'fin_flag_cnt':       _safe(df, 'FIN Flag Count', 0),
            'syn_flag_cnt':       _safe(df, 'SYN Flag Count', 0),
            'rst_flag_cnt':       _safe(df, 'RST Flag Count', 0),
            'ack_flag_cnt':       _safe(df, 'ACK Flag Count', 0),
            'psh_flag_cnt':       _safe(df, 'PSH Flag Count', 0),
            'urg_flag_cnt':       _safe(df, 'URG Flag Count', 0),
            'fwd_psh_flags':      _safe(df, 'Fwd PSH Flags', 0),
            'bwd_psh_flags':      _safe(df, 'Bwd PSH Flags', 0),
            'ttl_fwd':            _safe(df, 'Fwd TTL Max',
                                   _safe(df, 'Fwd Header Length', 64)) ,
            'proto_encoded':      _safe(df, 'Protocol', 6),
        })

        if len(out) > n:
            out, y = _stratified_sample(out, y, n)

        return _clean(out), y.reset_index(drop=True)


# ─────────────────────────────────────────────────────────────────────────────
# ADAPTER: UNSW-NB15
# ─────────────────────────────────────────────────────────────────────────────

class UNSWB15Adapter:
    """
    Adapter for UNSW-NB15 dataset.

    Columns (49 features):
      srcip, sport, dstip, dsport, proto, state, dur, sbytes, dbytes,
      sttl, dttl, sloss, dloss, service, sload, dload, spkts, dpkts,
      swin, dwin, stcpb, dtcpb, smeansz, dmeansz, trans_depth, res_bdy_len,
      sjit, djit, stime, ltime, sintpkt, dintpkt, tcprtt, synack, ackdat,
      is_sm_ips_ports, ct_state_ttl, ct_flw_http_mthd, is_ftp_login,
      ct_ftp_cmd, ct_srv_src, ct_srv_dst, ct_dst_ltm, ct_src_ltm,
      ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm, attack_cat, label
    """
    NAME = 'UNSW-NB15'

    def download_info(self):
        return (
            "UNSW-NB15 Dataset\n"
            "URL: https://research.unsw.edu.au/projects/unsw-nb15-dataset\n"
            "Direct: https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys\n"
            "Files needed: UNSW-NB15_1.csv (106MB), _2.csv (163MB),\n"
            "              _3.csv (166MB), _4.csv (69MB)\n"
            "Also download: NUSW-NB15_features.csv (column names for headerless CSVs)\n"
            "Place in: media/training/datasets/unsw/\n\n"
            "wget command:\n"
            "  wget 'https://cloudstor.aarnet.edu.au/plus/s/2DhnLGDdEECo4ys/download?path=%2F&files=UNSW-NB15_1.csv' -O media/training/datasets/unsw/UNSW-NB15_1.csv"
        )

    # UNSW-NB15 column headers (CSVs have no header row)
    COLUMNS = [
        'srcip','sport','dstip','dsport','proto','state','dur',
        'sbytes','dbytes','sttl','dttl','sloss','dloss','service',
        'sload','dload','spkts','dpkts','swin','dwin','stcpb','dtcpb',
        'smeansz','dmeansz','trans_depth','res_bdy_len','sjit','djit',
        'stime','ltime','sintpkt','dintpkt','tcprtt','synack','ackdat',
        'is_sm_ips_ports','ct_state_ttl','ct_flw_http_mthd','is_ftp_login',
        'ct_ftp_cmd','ct_srv_src','ct_srv_dst','ct_dst_ltm','ct_src_ltm',
        'ct_src_dport_ltm','ct_dst_sport_ltm','ct_dst_src_ltm',
        'attack_cat','label',
    ]

    def load(self, csv_path: str, n: int = 15000) -> tuple[pd.DataFrame, pd.Series]:
        """Load UNSW-NB15 CSV (with or without header)."""
        # Try with header first
        df = pd.read_csv(csv_path, low_memory=False)
        if df.columns[0].lower() in ('srcip', 'id', '0', 'no.'):
            df.columns = df.columns.str.lower().str.strip()
        else:
            # No header — use known column list
            df = pd.read_csv(csv_path, header=None, low_memory=False)
            if len(df.columns) == len(self.COLUMNS):
                df.columns = self.COLUMNS
            else:
                # Partial — use what we have
                df.columns = self.COLUMNS[:len(df.columns)]

        # Label is in 'attack_cat' (category name) or 'label' (0/1)
        if 'attack_cat' in df.columns:
            y = df['attack_cat'].fillna('Normal').apply(normalize_label)
        elif 'label' in df.columns:
            y = df['label'].apply(lambda v: 'BENIGN' if str(v).strip() in ('0','normal','Normal') else 'Other')
        else:
            raise ValueError("No label column found in UNSW-NB15 CSV")

        dur  = pd.to_numeric(df.get('dur', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        sp   = pd.to_numeric(df.get('spkts', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        dp   = pd.to_numeric(df.get('dpkts', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        sb   = pd.to_numeric(df.get('sbytes', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        db_  = pd.to_numeric(df.get('dbytes', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        sm   = pd.to_numeric(df.get('smeansz', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        dm   = pd.to_numeric(df.get('dmeansz', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        sttl = pd.to_numeric(df.get('sttl', pd.Series(64, index=df.index)), errors='coerce').fillna(64)
        sint = pd.to_numeric(df.get('sintpkt', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        dint = pd.to_numeric(df.get('dintpkt', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        sjit = pd.to_numeric(df.get('sjit', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        djit = pd.to_numeric(df.get('djit', pd.Series(0, index=df.index)), errors='coerce').fillna(0)

        total_pkts  = sp + dp + 1e-9
        total_bytes = sb + db_ + 1e-9

        # TCP flags from state string (e.g. "S0", "SF", "REJ")
        state = df.get('state', pd.Series('', index=df.index)).astype(str).str.upper()
        proto_raw = df.get('proto', pd.Series('tcp', index=df.index)).astype(str)

        out = pd.DataFrame({
            'duration':           dur,
            'total_fwd_pkts':     sp,
            'total_bwd_pkts':     dp,
            'total_fwd_bytes':    sb,
            'total_bwd_bytes':    db_,
            'bytes_per_pkt':      total_bytes / total_pkts,
            'pkts_per_sec':       total_pkts / (dur + 1e-9),
            'bytes_per_sec':      total_bytes / (dur + 1e-9),
            'fwd_bwd_pkt_ratio':  sp / (dp + 1e-9),
            'fwd_bwd_byte_ratio': sb / (db_ + 1e-9),
            'avg_pkt_size':       (sm + dm) / 2,
            'flow_iat_mean':      sint,
            'flow_iat_std':       sjit,
            'fwd_iat_mean':       sint,
            'bwd_iat_mean':       dint,
            'fin_flag_cnt':       state.str.contains('FIN|SF').astype(int),
            'syn_flag_cnt':       state.str.contains('S[0-9]|SYN').astype(int),
            'rst_flag_cnt':       state.str.contains('RST|REJ').astype(int),
            'ack_flag_cnt':       state.str.contains('ACK|SF').astype(int),
            'psh_flag_cnt':       pd.Series(0, index=df.index),
            'urg_flag_cnt':       pd.Series(0, index=df.index),
            'fwd_psh_flags':      pd.Series(0, index=df.index),
            'bwd_psh_flags':      pd.Series(0, index=df.index),
            'ttl_fwd':            sttl,
            'proto_encoded':      _encode_proto(proto_raw),
        })

        if len(out) > n:
            out, y = _stratified_sample(out, y, n)

        return _clean(out), y.reset_index(drop=True)


# ─────────────────────────────────────────────────────────────────────────────
# ADAPTER: CTU-13 (NetFlow botnet scenarios)
# ─────────────────────────────────────────────────────────────────────────────

class CTU13Adapter:
    """
    Adapter for CTU-13 dataset (13 botnet scenarios, NetFlow format).

    Columns: StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport,
             State, sTos, dTos, TotPkts, TotBytes, SrcBytes, Label
    """
    NAME = 'CTU-13'

    def download_info(self):
        return (
            "CTU-13 Botnet Dataset (13 scenarios)\n"
            "URL: https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/\n"
            "Each scenario has a .binetflow file (rename to .csv)\n"
            "Recommended scenarios: 1, 2, 3, 7, 9, 10 (most complete)\n\n"
            "Direct scenario 1:\n"
            "  wget https://mcfp.felk.cvut.cz/publicDatasets/CTU-13-Dataset/CTU-13-Dataset-1/capture20110810.binetflow -O media/training/datasets/ctu13/scenario1.csv\n\n"
            "Label format: 'flow=...' for botnet, 'Background' for benign\n"
            "Place in: media/training/datasets/ctu13/"
        )

    def load(self, csv_path: str, n: int = 15000) -> tuple[pd.DataFrame, pd.Series]:
        """Load CTU-13 binetflow CSV."""
        df = pd.read_csv(csv_path, low_memory=False)
        df.columns = df.columns.str.strip()

        # CTU-13 label: "flow=From-Botnet-V42-UDP" / "Background" / "flow=From-Normal-..."
        raw_label = df.get('Label', pd.Series('Background', index=df.index)).astype(str)

        def _ctu_label(l: str) -> str:
            l = l.strip().lower()
            if 'background' in l or 'normal' in l:
                return 'BENIGN'
            if 'botnet' in l:
                return 'Bot'
            if 'ddos' in l:
                return 'DDoS'
            if 'spam' in l:
                return 'Bot'
            return 'Bot'  # all CTU-13 non-background is botnet

        y = raw_label.apply(_ctu_label)

        dur  = pd.to_numeric(df.get('Dur', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        tp   = pd.to_numeric(df.get('TotPkts', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        tb   = pd.to_numeric(df.get('TotBytes', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        sb   = pd.to_numeric(df.get('SrcBytes', pd.Series(0, index=df.index)), errors='coerce').fillna(0)
        db_  = tb - sb
        proto_raw = df.get('Proto', pd.Series('tcp', index=df.index)).astype(str)
        state = df.get('State', pd.Series('', index=df.index)).astype(str).str.upper()

        # CTU-13 doesn't split fwd/bwd packets — split roughly by direction
        # Dir column: "  ->", " <-", " <->"
        direction = df.get('Dir', pd.Series('->', index=df.index)).astype(str)
        is_bidir  = direction.str.contains('<->').astype(int)
        sp = tp * (0.5 + 0.5 * is_bidir)   # estimate
        dp = tp * 0.5 * is_bidir

        total_pkts  = tp + 1e-9
        total_bytes = tb + 1e-9

        out = pd.DataFrame({
            'duration':           dur,
            'total_fwd_pkts':     sp,
            'total_bwd_pkts':     dp,
            'total_fwd_bytes':    sb,
            'total_bwd_bytes':    db_.clip(0),
            'bytes_per_pkt':      total_bytes / total_pkts,
            'pkts_per_sec':       total_pkts / (dur + 1e-9),
            'bytes_per_sec':      total_bytes / (dur + 1e-9),
            'fwd_bwd_pkt_ratio':  sp / (dp + 1e-9),
            'fwd_bwd_byte_ratio': sb / (db_.clip(0) + 1e-9),
            'avg_pkt_size':       total_bytes / total_pkts,
            'flow_iat_mean':      pd.Series(0, index=df.index),
            'flow_iat_std':       pd.Series(0, index=df.index),
            'fwd_iat_mean':       pd.Series(0, index=df.index),
            'bwd_iat_mean':       pd.Series(0, index=df.index),
            'fin_flag_cnt':       state.str.contains('FIN|SF').astype(int),
            'syn_flag_cnt':       state.str.contains('S[0-9]|SYN').astype(int),
            'rst_flag_cnt':       state.str.contains('RST|REJ').astype(int),
            'ack_flag_cnt':       state.str.contains('ACK|SF').astype(int),
            'psh_flag_cnt':       pd.Series(0, index=df.index),
            'urg_flag_cnt':       pd.Series(0, index=df.index),
            'fwd_psh_flags':      pd.Series(0, index=df.index),
            'bwd_psh_flags':      pd.Series(0, index=df.index),
            'ttl_fwd':            pd.to_numeric(df.get('sTos', pd.Series(64, index=df.index)), errors='coerce').fillna(64),
            'proto_encoded':      _encode_proto(proto_raw),
        })

        if len(out) > n:
            out, y = _stratified_sample(out, y, n)

        return _clean(out), y.reset_index(drop=True)


# ─────────────────────────────────────────────────────────────────────────────
# ADAPTER: CICIOT2023
# ─────────────────────────────────────────────────────────────────────────────

class CICIOT2023Adapter:
    """
    Adapter for CICIOT2023 (IoT traffic, 2023).

    Modern dataset with 46 features. Contains IoT-specific attack patterns.
    Source: https://www.unb.ca/cic/datasets/iotdataset-2023.html
    """
    NAME = 'CICIOT2023'

    def download_info(self):
        return (
            "CICIOT2023 — IoT Dataset 2023\n"
            "URL: https://www.unb.ca/cic/datasets/iotdataset-2023.html\n"
            "Registration required (free). ~8 GB compressed.\n"
            "Alternative (Kaggle mirror):\n"
            "  kaggle datasets download -d mohamedaminferchichi/cic-iot-2023\n\n"
            "Files: part-00000-...-c000.csv (multiple part files)\n"
            "Place in: media/training/datasets/ciciot2023/\n\n"
            "Labels: BENIGN, DDoS-UDP_Flood, DDoS-TCP_Flood, DDoS-ICMP_Flood,\n"
            "        DoS-UDP_Flood, BruteForce-SSH, Recon-PortScan, etc."
        )

    def load(self, csv_path: str, n: int = 15000) -> tuple[pd.DataFrame, pd.Series]:
        """Load CICIOT2023 CSV part file."""
        df = pd.read_csv(csv_path, low_memory=False)
        df.columns = df.columns.str.strip()

        # Find label column
        label_col = None
        for candidate in ('Label', 'label', 'attack', 'Attack', 'class', 'Class'):
            if candidate in df.columns:
                label_col = candidate
                break
        if label_col is None:
            raise ValueError(f"No label column in {csv_path}")

        y = df[label_col].apply(normalize_label)

        # CICIOT2023 column mapping (uses CICFlowMeter-like names)
        # Column names may vary — try common variants
        def gcol(candidates, default=0):
            for c in candidates:
                if c in df.columns:
                    return pd.to_numeric(df[c], errors='coerce').fillna(default)
            return pd.Series(default, index=df.index)

        dur = gcol(['flow_duration', 'Flow Duration', 'FlowDuration'], 0) / 1e6
        fp  = gcol(['tot_fwd_pkts', 'Total Fwd Packets', 'TotFwdPkts', 'Fwd Packets'], 0)
        bp  = gcol(['tot_bwd_pkts', 'Total Backward Packets', 'TotBwdPkts', 'Bwd Packets'], 0)
        fb  = gcol(['totlen_fwd_pkts', 'Total Length of Fwd Packets', 'FwdPacketBytes'], 0)
        bb  = gcol(['totlen_bwd_pkts', 'Total Length of Bwd Packets', 'BwdPacketBytes'], 0)

        total_pkts  = fp + bp + 1e-9
        total_bytes = fb + bb + 1e-9

        out = pd.DataFrame({
            'duration':           dur,
            'total_fwd_pkts':     fp,
            'total_bwd_pkts':     bp,
            'total_fwd_bytes':    fb,
            'total_bwd_bytes':    bb,
            'bytes_per_pkt':      total_bytes / total_pkts,
            'pkts_per_sec':       total_pkts / (dur + 1e-9),
            'bytes_per_sec':      total_bytes / (dur + 1e-9),
            'fwd_bwd_pkt_ratio':  fp / (bp + 1e-9),
            'fwd_bwd_byte_ratio': fb / (bb + 1e-9),
            'avg_pkt_size':       gcol(['pkt_size_avg', 'Average Packet Size', 'AvgPktSize'], 0),
            'flow_iat_mean':      gcol(['flow_iat_mean', 'Flow IAT Mean', 'FlowIATMean'], 0) / 1e6,
            'flow_iat_std':       gcol(['flow_iat_std', 'Flow IAT Std', 'FlowIATStd'], 0) / 1e6,
            'fwd_iat_mean':       gcol(['fwd_iat_mean', 'Fwd IAT Mean', 'FwdIATMean'], 0) / 1e6,
            'bwd_iat_mean':       gcol(['bwd_iat_mean', 'Bwd IAT Mean', 'BwdIATMean'], 0) / 1e6,
            'fin_flag_cnt':       gcol(['fin_flag_cnt', 'FIN Flag Count', 'FINFlagCnt'], 0),
            'syn_flag_cnt':       gcol(['syn_flag_cnt', 'SYN Flag Count', 'SYNFlagCnt'], 0),
            'rst_flag_cnt':       gcol(['rst_flag_cnt', 'RST Flag Count', 'RSTFlagCnt'], 0),
            'ack_flag_cnt':       gcol(['ack_flag_cnt', 'ACK Flag Count', 'ACKFlagCnt'], 0),
            'psh_flag_cnt':       gcol(['psh_flag_cnt', 'PSH Flag Count', 'PSHFlagCnt'], 0),
            'urg_flag_cnt':       gcol(['urg_flag_cnt', 'URG Flag Count', 'URGFlagCnt'], 0),
            'fwd_psh_flags':      gcol(['fwd_psh_flags', 'Fwd PSH Flags', 'FwdPSHFlags'], 0),
            'bwd_psh_flags':      gcol(['bwd_psh_flags', 'Bwd PSH Flags', 'BwdPSHFlags'], 0),
            'ttl_fwd':            gcol(['fwd_init_win_byts', 'Fwd TTL Max', 'FwdTTL'], 64),
            'proto_encoded':      gcol(['protocol', 'Protocol'], 6).astype(int),
        })

        if len(out) > n:
            out, y = _stratified_sample(out, y, n)

        return _clean(out), y.reset_index(drop=True)


# ─────────────────────────────────────────────────────────────────────────────
# ADAPTER: Jorise Lab (custom captures — Phase 2)
# ─────────────────────────────────────────────────────────────────────────────

class JoriseLabAdapter:
    """
    Adapter for Jorise Lab 2026 — your own captured and labeled traffic.
    Expects CICFlowMeter-exported CSVs (same format as CIC-IDS2017).
    """
    NAME = 'Jorise-Lab-2026'

    def download_info(self):
        return (
            "Jorise Lab 2026 — Your own dataset.\n"
            "Capture: tcpdump / Wireshark on lab VMs\n"
            "Process: CICFlowMeter (Java) or flowtbag\n"
            "  docker run -v $(pwd):/data cic/cicflowmeter -f capture.pcap -c /data/flows.csv\n"
            "Label: add Label column manually after capture\n"
            "Place in: media/training/datasets/jorise_lab/"
        )

    def load(self, csv_path: str, n: int = 15000) -> tuple[pd.DataFrame, pd.Series]:
        """Same format as CIC-IDS2017 (CICFlowMeter output)."""
        return CICIDS2017Adapter().load(csv_path, n)


# ─────────────────────────────────────────────────────────────────────────────
# Registry and helpers
# ─────────────────────────────────────────────────────────────────────────────

ADAPTERS = {
    'cicids2017':  CICIDS2017Adapter,
    'unsw':        UNSWB15Adapter,
    'ctu13':       CTU13Adapter,
    'ciciot2023':  CICIOT2023Adapter,
    'jorise_lab':  JoriseLabAdapter,
}


def get_adapter(name: str):
    """Return an instantiated adapter by key name."""
    cls = ADAPTERS.get(name.lower())
    if not cls:
        raise ValueError(f"Unknown adapter '{name}'. Options: {list(ADAPTERS)}")
    return cls()


def _stratified_sample(X: pd.DataFrame, y: pd.Series, n: int):
    """Downsample X, y preserving class distribution."""
    rng = np.random.default_rng(42)
    groups = []
    for cls in y.unique():
        idx = y[y == cls].index.tolist()
        frac = len(idx) / len(y)
        want = max(1, int(frac * n))
        chosen = rng.choice(idx, min(want, len(idx)), replace=False)
        groups.extend(chosen)
    groups = rng.permutation(groups)
    return X.loc[groups].reset_index(drop=True), y.loc[groups].reset_index(drop=True)


def print_all_download_info():
    """Print download instructions for all datasets."""
    for name, cls in ADAPTERS.items():
        adapter = cls()
        print(f"\n{'='*60}")
        print(f"  {adapter.NAME}")
        print(f"{'='*60}")
        print(adapter.download_info())
