"""
PCAP → CSV Converter via CICFlowMeter (Docker)
===============================================
Converts raw PCAP files to CICFlowMeter feature CSVs.
Runs CICFlowMeter in a Docker container so no Java installation required.

Prerequisites (one-time):
    docker pull jsrojas/ip-network-traffic-flows-labeled-with-87-apps

Or build the minimal wrapper in docker-compose.lab.yml:
    docker compose -f docker-compose.lab.yml build cicflowmeter

Usage from Python:
    from lab_toolkit.pcap_to_csv import convert_all_pcaps
    convert_all_pcaps()

Usage from CLI:
    python setup_lab.py pcap2csv
    python setup_lab.py pcap2csv --pcap path/to/file.pcap
"""
import os, subprocess
from pathlib import Path

PCAP_DIR     = Path("media/training/lab_pcaps")
OUTPUT_DIR   = Path("media/training/datasets/jorise_lab")
DOCKER_IMAGE = "jorise/cicflowmeter:latest"  # from docker-compose.lab.yml build

# Alternative: use the public image (no build needed)
PUBLIC_IMAGE = "jsrojas/ip-network-traffic-flows-labeled-with-87-apps"

# CICFlowMeter native binary path (if installed locally, no Docker)
LOCAL_CICFLOW = None  # e.g. "/opt/CICFlowMeter/bin/cfm"


def _docker_available() -> bool:
    try:
        subprocess.run(["docker", "info"], capture_output=True, timeout=5, check=True)
        return True
    except Exception:
        return False


def _convert_with_docker(pcap_path: Path, out_dir: Path, image: str) -> bool:
    """
    Run CICFlowMeter via Docker.
    Mounts pcap directory and output directory into the container.
    """
    pcap_abs = pcap_path.resolve()
    out_abs  = out_dir.resolve()
    out_abs.mkdir(parents=True, exist_ok=True)

    cmd = [
        "docker", "run", "--rm",
        "-v", f"{pcap_abs.parent}:/pcaps:ro",
        "-v", f"{out_abs}:/output",
        image,
        "cfm", f"/pcaps/{pcap_abs.name}", "/output"
    ]
    print(f"  [pcap2csv] {pcap_path.name}  →  {out_dir}/")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [pcap2csv] ERROR:\n{result.stderr[:500]}")
        return False
    return True


def _convert_with_local(pcap_path: Path, out_dir: Path) -> bool:
    """Run CICFlowMeter installed locally (Java required)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [LOCAL_CICFLOW, str(pcap_path), str(out_dir)]
    print(f"  [pcap2csv] {pcap_path.name}  →  {out_dir}/  (local binary)")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  [pcap2csv] ERROR:\n{result.stderr[:500]}")
        return False
    return True


def convert_pcap(pcap_path: str, out_dir: str | None = None) -> bool:
    """Convert a single PCAP to CSV features."""
    pcap = Path(pcap_path)
    if not pcap.exists():
        print(f"  [pcap2csv] File not found: {pcap_path}")
        return False

    out = Path(out_dir) if out_dir else OUTPUT_DIR

    if LOCAL_CICFLOW and Path(LOCAL_CICFLOW).exists():
        return _convert_with_local(pcap, out)
    if _docker_available():
        # Try built image first, fall back to public
        for img in [DOCKER_IMAGE, PUBLIC_IMAGE]:
            try:
                subprocess.run(
                    ["docker", "image", "inspect", img],
                    capture_output=True, check=True
                )
                return _convert_with_docker(pcap, out, img)
            except subprocess.CalledProcessError:
                continue
        print("[pcap2csv] No CICFlowMeter Docker image found.")
        print("           Run: docker compose -f docker-compose.lab.yml build")
        return False
    print("[pcap2csv] Neither Docker nor local CICFlowMeter found.")
    print("           Install Docker or set LOCAL_CICFLOW path.")
    return False


def convert_all_pcaps(pcap_dir: str | None = None, out_dir: str | None = None):
    """Convert all .pcap files in pcap_dir to CSV features."""
    pcap_dir = Path(pcap_dir) if pcap_dir else PCAP_DIR
    pcaps = list(pcap_dir.glob("*.pcap")) + list(pcap_dir.glob("*.pcapng"))

    if not pcaps:
        print(f"[pcap2csv] No PCAP files found in {pcap_dir}")
        print(f"           Place your capture files there and retry.")
        return

    print(f"[pcap2csv] Converting {len(pcaps)} PCAP file(s)...")
    ok = sum(1 for p in pcaps if convert_pcap(str(p), out_dir))
    print(f"[pcap2csv] Done: {ok}/{len(pcaps)} converted.")
    if ok > 0:
        out = Path(out_dir) if out_dir else OUTPUT_DIR
        print(f"[pcap2csv] CSVs in: {out}")
        print("[pcap2csv] Next step: python setup_lab.py label")


def install_info():
    print("""
CICFlowMeter Setup Options
===========================

Option A — Docker (recommended, no Java needed):
    1. Install Docker Desktop: https://docs.docker.com/get-docker/
    2. Run: docker compose -f docker-compose.lab.yml build
    3. Then: python setup_lab.py pcap2csv

Option B — Local binary (requires Java 8+):
    1. Download: https://github.com/ahlashkari/CICFlowMeter/releases
    2. Unzip and note the path to cfm binary
    3. Set LOCAL_CICFLOW in lab_toolkit/pcap_to_csv.py
    4. Then: python setup_lab.py pcap2csv

Option C — Built-in Python flow generator (no external tools):
    Use PyFlowMeter: pip install pyflowmeter
    (Fewer features than CICFlowMeter but works standalone)
""")
