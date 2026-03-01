"""
Lab Capture Manager
===================
Wraps tcpdump / tshark to capture PCAPs during controlled attack sessions.
Maintains a session log that records attack type + time windows for labeling.

Session log format (JSON):
    [
       {"session_id": "syn_flood_01",
        "attack_type": "DoS SYN Flood",
        "canonical_label": "DoS",
        "interface": "eth0",
        "pcap_file": "/lab/pcaps/syn_flood_01.pcap",
        "start_ts": 1700000000.0,
        "stop_ts":  1700000120.0,
        "notes": "Hping3 from Kali, target 192.168.1.50"},
       ...
    ]
"""
import json, os, subprocess, time, datetime
from pathlib import Path

SESSION_LOG = Path("lab_toolkit/sessions.json")
PCAP_DIR    = Path("media/training/lab_pcaps")

CANONICAL_ATTACK_TYPES = [
    "DoS",
    "DDoS",
    "Port Scan",
    "Brute Force",
    "Web Attack",
    "Botnet",
    "Infiltration",
    "BENIGN",
]


def _load_sessions() -> list:
    if SESSION_LOG.exists():
        return json.loads(SESSION_LOG.read_text())
    return []


def _save_sessions(sessions: list):
    SESSION_LOG.parent.mkdir(parents=True, exist_ok=True)
    SESSION_LOG.write_text(json.dumps(sessions, indent=2))


def start_session(session_id: str, attack_type: str, canonical_label: str,
                  interface: str = "eth0", notes: str = "") -> dict:
    """
    Begin recording a lab session.  Launches tcpdump in background.

    Returns the session dict.  Call stop_session(session_id) when done.

    Example:
        sess = start_session("syn_01", "DoS SYN Flood", "DoS", interface="eth0",
                             notes="hping3 -S --flood -p 80 192.168.1.50")
    """
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    pcap_path = str(PCAP_DIR / f"{session_id}.pcap")

    session = {
        "session_id":      session_id,
        "attack_type":     attack_type,
        "canonical_label": canonical_label,
        "interface":       interface,
        "pcap_file":       pcap_path,
        "start_ts":        time.time(),
        "stop_ts":         None,
        "pid":             None,
        "notes":           notes,
    }

    # Try to start tcpdump  (Linux / macOS / WSL)
    try:
        proc = subprocess.Popen(
            ["tcpdump", "-i", interface, "-w", pcap_path, "-q"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        session["pid"] = proc.pid
        print(f"[capture] tcpdump started (PID {proc.pid})  →  {pcap_path}")
    except FileNotFoundError:
        print("[capture] tcpdump not found — start capturing manually.")
        print(f"          Target pcap: {pcap_path}")

    sessions = _load_sessions()
    sessions.append(session)
    _save_sessions(sessions)
    return session


def stop_session(session_id: str) -> dict:
    """Stop the active tcpdump process and seal the session timestamp."""
    sessions = _load_sessions()
    for s in sessions:
        if s["session_id"] == session_id and s["stop_ts"] is None:
            s["stop_ts"] = time.time()
            pid = s.get("pid")
            if pid:
                try:
                    subprocess.run(["kill", str(pid)], check=False)
                    print(f"[capture] tcpdump (PID {pid}) stopped.")
                except Exception as e:
                    print(f"[capture] Could not kill PID {pid}: {e}")
            _save_sessions(sessions)
            duration = s["stop_ts"] - s["start_ts"]
            print(f"[capture] Session '{session_id}' sealed  ({duration:.0f}s)")
            return s
    raise ValueError(f"No open session found with id '{session_id}'")


def list_sessions() -> list:
    return _load_sessions()


def get_session(session_id: str) -> dict:
    for s in _load_sessions():
        if s["session_id"] == session_id:
            return s
    raise ValueError(f"Session '{session_id}' not found")


def print_sessions():
    sessions = _load_sessions()
    if not sessions:
        print("No sessions recorded yet.")
        return
    print(f"\n{'ID':<20} {'Label':<18} {'Duration':>10}  {'PCAP'}")
    print("-" * 75)
    for s in sessions:
        dur = f"{s['stop_ts']-s['start_ts']:.0f}s" if s["stop_ts"] else "RUNNING"
        print(f"{s['session_id']:<20} {s['canonical_label']:<18} {dur:>10}  {s['pcap_file']}")
