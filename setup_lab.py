"""
Jorise Lab Setup — Phase 2 Own-Capture Dataset CLI
====================================================
Unified CLI for managing the lab data-capture pipeline.

Usage:
    # One-time setup: show what to install
    python setup_lab.py install-info

    # Start a capture session
    python setup_lab.py start-session --name "syn_flood_01" \\
                                      --attack "DoS SYN Flood" \\
                                      --label "DoS" \\
                                      --interface eth0 \\
                                      --notes "hping3 -S --flood -p 80 192.168.1.50"

    # Stop the session
    python setup_lab.py stop-session --name "syn_flood_01"

    # List all recorded sessions
    python setup_lab.py sessions

    # Convert PCAPs to feature CSVs
    python setup_lab.py pcap2csv
    python setup_lab.py pcap2csv --pcap media/training/lab_pcaps/syn_flood_01.pcap

    # Inject labels into CSVs
    python setup_lab.py label

    # Show feature distribution of the lab dataset
    python setup_lab.py stats

    # Full pipeline: pcap2csv → label → stats
    python setup_lab.py pipeline

Attack type quick reference:
    DoS, DDoS, Port Scan, Brute Force, Web Attack, Botnet, Infiltration, BENIGN
"""
import argparse, sys


def cmd_install_info(args):
    from lab_toolkit.pcap_to_csv import install_info
    install_info()
    print("""
VM Lab Architecture
===================
Network: 192.168.100.0/24 (host-only, isolated)

VMs:
  Kali   192.168.100.10  — attacker
  Win10  192.168.100.20  — victim 1 (Windows services)
  Ubuntu 192.168.100.30  — victim 2 (web server)

Capture: tcpdump on the host-only bridge interface
  Linux/macOS: tcpdump -i virbr0 -w capture.pcap
  Windows:     WireShark on the VMware/VBox host-only adapter

Attacks to run (map to canonical labels):
  DoS:         hping3 -S --flood -p 80 <target>
  DDoS:        Multiple Kali VMs simultaneously
  Port Scan:   nmap -sS -p- <target>
  Brute Force: hydra -l admin -P rockyou.txt ssh://<target>
  Web Attack:  nikto -h http://<target> ; sqlmap
  Botnet:      Metasploit meterpreter C2 simulation
""")


def cmd_start_session(args):
    from lab_toolkit.capture import start_session
    s = start_session(
        session_id     = args.name,
        attack_type    = args.attack,
        canonical_label= args.label,
        interface      = args.interface,
        notes          = args.notes or "",
    )
    print(f"\nSession '{args.name}' started.")
    print(f"  Label    : {s['canonical_label']}")
    print(f"  Interface: {s['interface']}")
    print(f"  PCAP     : {s['pcap_file']}")
    print(f"\nRun your attack now.")
    print(f"When done: python setup_lab.py stop-session --name \"{args.name}\"")


def cmd_stop_session(args):
    from lab_toolkit.capture import stop_session
    try:
        s = stop_session(args.name)
        print(f"\nSession sealed.")
        print(f"Next: python setup_lab.py pcap2csv")
    except ValueError as e:
        print(f"ERROR: {e}")
        sys.exit(1)


def cmd_sessions(args):
    from lab_toolkit.capture import print_sessions
    print_sessions()


def cmd_pcap2csv(args):
    from lab_toolkit.pcap_to_csv import convert_pcap, convert_all_pcaps
    if args.pcap:
        convert_pcap(args.pcap)
    else:
        convert_all_pcaps()


def cmd_label(args):
    from lab_toolkit.label import label_all
    label_all()


def cmd_stats(args):
    from lab_toolkit.label import label_distribution
    label_distribution()


def cmd_pipeline(args):
    """Full pipeline: pcap2csv → label → stats."""
    print("=" * 50)
    print("  Jorise Lab Pipeline")
    print("=" * 50)

    print("\nStep 1: Convert PCAPs to feature CSVs")
    from lab_toolkit.pcap_to_csv import convert_all_pcaps
    convert_all_pcaps()

    print("\nStep 2: Inject labels from session log")
    from lab_toolkit.label import label_all
    label_all()

    print("\nStep 3: Dataset statistics")
    from lab_toolkit.label import label_distribution
    label_distribution()

    print("\nPipeline complete.")
    print("To train: python train_multisource.py --sources cicids2017 jorise_lab")


def main():
    parser = argparse.ArgumentParser(
        description='Jorise Lab Toolkit — Phase 2 Dataset Capture',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest='command')

    # install-info
    sub.add_parser('install-info', help='Show CICFlowMeter + VM lab setup instructions')

    # start-session
    p = sub.add_parser('start-session', help='Start a capture session')
    p.add_argument('--name',      required=True,  help='Session ID (e.g. syn_flood_01)')
    p.add_argument('--attack',    required=True,  help='Human-readable attack description')
    p.add_argument('--label',     required=True,
                   choices=['DoS', 'DDoS', 'Port Scan', 'Brute Force',
                            'Web Attack', 'Botnet', 'Infiltration', 'BENIGN'],
                   help='Canonical label for ML training')
    p.add_argument('--interface', default='eth0', help='Network interface to capture on')
    p.add_argument('--notes',     default='',     help='Optional notes about the attack')

    # stop-session
    p = sub.add_parser('stop-session', help='Stop a running capture session')
    p.add_argument('--name', required=True, help='Session ID to stop')

    # sessions
    sub.add_parser('sessions', help='List all recorded sessions')

    # pcap2csv
    p = sub.add_parser('pcap2csv', help='Convert PCAP files to CICFlowMeter CSV features')
    p.add_argument('--pcap', default=None, help='Single PCAP file (default: all in lab_pcaps/)')

    # label
    sub.add_parser('label', help='Inject labels into feature CSVs from session log')

    # stats
    sub.add_parser('stats', help='Show label distribution of the lab dataset')

    # pipeline
    sub.add_parser('pipeline', help='Run full pipeline: pcap2csv → label → stats')

    args = parser.parse_args()

    dispatch = {
        'install-info':  cmd_install_info,
        'start-session': cmd_start_session,
        'stop-session':  cmd_stop_session,
        'sessions':      cmd_sessions,
        'pcap2csv':      cmd_pcap2csv,
        'label':         cmd_label,
        'stats':         cmd_stats,
        'pipeline':      cmd_pipeline,
    }

    if not args.command:
        parser.print_help()
        return

    dispatch[args.command](args)


if __name__ == '__main__':
    main()
