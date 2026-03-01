"""
Jorise Lab Toolkit — Phase 2 Own-Capture Dataset Pipeline
==========================================================
Tools for building a controlled, labeled dataset from a local VM lab.

Architecture:
    VM lab (Kali attacker + Windows/Ubuntu victims)
        └── tcpdump / WireShark captures PCAP files
    Host (this machine)
        └── pcap_to_csv.py   -- runs CICFlowMeter via Docker, PCAP → CSV
        └── label.py         -- injects LABEL column using attack session log
        └── capture.py       -- tcpdump wrapper + session logger
    Training pipeline
        └── train_multisource.py  --sources jorise_lab

Usage flow:
    1. Start a lab session:        python setup_lab.py start-session --name "syn_flood_01"
    2. Run your attack in the VM
    3. Stop the session:           python setup_lab.py stop-session
    4. Convert PCAP to CSV:        python setup_lab.py pcap2csv
    5. Label flows:                python setup_lab.py label
    6. Train including lab data:   python train_multisource.py --sources cicids2017 jorise_lab
"""
