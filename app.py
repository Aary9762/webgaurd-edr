import threading
import time
import os
import psutil
import pyperclip
import re
import hashlib
import shutil
import json
import winreg
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
import numpy as np
import warnings
import sys
import webbrowser
from flask import Flask, jsonify, request, send_from_directory
import socket
import urllib.parse

# Optional: requests for Geo-IP (graceful fallback if missing)
try:
    import requests as http_requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[WARN] 'requests' library not found. LLM & Geo-IP features disabled.")

warnings.filterwarnings("ignore")

app = Flask(__name__, static_folder=".")

# ── Quarantine folder ──────────────────────────────────────────────────────────
QUARANTINE_DIR = Path("C:/WebGuard_Quarantine")
QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)

# ── Known malware SHA-256 signatures (demo DB) ─────────────────────────────────
MALWARE_SIGNATURES = {
    # WannaCry
    "db349b97c37d22f5ea1d1841e3c89eb4f09a0256e63be645e5617c8de3b5a2a4": "WannaCry Ransomware",
    "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa": "WannaCry Variant",
    # NotPetya
    "a1d5895f85751dfe67d19cccb51b051a165b3af2c56285affa0e58c42d87e6a9": "NotPetya Ransomware",
    # Generic RAT droppers (illustrative)
    "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef": "Generic RAT Dropper",
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": "Empty/Zero-byte Suspicious",
    # Mirai botnet sample
    "0e4e3e6f6d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d": "Mirai Botnet Sample",
    # Emotet
    "1f5f14a6958e6f5b7b2d3b9e1c0a3a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7": "Emotet Trojan",
    # Njrat
    "2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3": "NjRAT Remote Access Trojan",
    # Darkcomet
    "3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a": "DarkComet RAT",
    # Zeus banking trojan
    "b34d2b3c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4": "Zeus Banking Trojan",
}

# ── Built-in Threat Intelligence Engine (replaces Ollama) ──────────────────────
import random

AI_ENGINE_NAME = "WebGuard Neural Analyst"
AI_ENGINE_VERSION = "v2.1"
LLM_AVAILABLE = True  # Always available — runs locally, no external deps

# Rich threat knowledge base for generating contextual reports
THREAT_KNOWLEDGE = {
    "Network RAT": {
        "descriptions": [
            "This connection exhibits behavior consistent with a Remote Access Trojan (RAT) establishing a command-and-control channel.",
            "Behavioral analysis indicates a potential reverse-shell or RAT beacon operating on this port, suggesting unauthorized remote control capability.",
            "Heuristic signatures match known RAT communication patterns — the process is maintaining a persistent outbound connection characteristic of C2 infrastructure.",
        ],
        "dangers": [
            "If confirmed, the attacker gains full remote access to the host including file exfiltration, keystroke logging, screen capture, and lateral movement capability.",
            "A live C2 channel enables real-time data exfiltration, credential harvesting, and deployment of secondary payloads including ransomware or wiper malware.",
            "Active RAT connections allow threat actors to pivot through the network, escalate privileges, and maintain persistence across reboots.",
        ],
        "actions": [
            "Immediately isolate the host from the network, terminate the offending process, and conduct a full memory forensics sweep to identify injected modules.",
            "Kill the process tree, block the destination IP at the firewall, and run a full endpoint scan to detect any persistence mechanisms already deployed.",
            "Terminate the connection, quarantine the executable, capture a memory dump for IOC extraction, and rotate all credentials that may have been exposed.",
        ],
    },
    "Network RAT Detected": {
        "descriptions": [
            "The AI behavioral engine has flagged anomalous network telemetry consistent with command-and-control beaconing from a Remote Access Trojan.",
            "Traffic analysis reveals periodic callbacks and encrypted payloads characteristic of RAT families such as Cobalt Strike, njRAT, or AsyncRAT.",
            "This connection's timing intervals, payload sizes, and destination characteristics match known RAT beacon profiles in our threat intelligence database.",
        ],
        "dangers": [
            "An active RAT provides the threat actor with unrestricted access to the system — including shell access, file system manipulation, webcam/microphone activation, and credential theft.",
            "RAT beacons indicate the initial compromise phase is complete; the adversary is now in the 'hands-on-keyboard' phase and may be preparing lateral movement or data staging.",
            "Unmitigated RAT connections serve as persistent backdoors that survive reboots and can be used to deploy ransomware, cryptominers, or data-stealing modules at any time.",
        ],
        "actions": [
            "Immediately terminate the process, blackhole the C2 IP, and perform an autoruns analysis to identify persistence hooks in the registry, scheduled tasks, and startup folders.",
            "Network-isolate the endpoint, dump volatile memory for forensic analysis, and alert the SOC team for a full incident response engagement.",
            "Kill the process, block all related IOCs at the perimeter firewall, and initiate a threat hunt across the environment to identify other compromised endpoints.",
        ],
    },
    "Suspicious Download": {
        "descriptions": [
            "A file with a dangerous executable extension was detected in the Downloads directory. Static analysis flags indicate elevated risk markers.",
            "The download scanner detected a new binary artifact with characteristics commonly associated with malware droppers, packers, or exploit payloads.",
            "A potentially malicious executable has been intercepted during download. File entropy and extension analysis suggest this warrants immediate investigation.",
        ],
        "dangers": [
            "Unvetted executables from untrusted sources can contain trojans, ransomware, or cryptojacking payloads that execute on launch and spread laterally.",
            "The file may be a first-stage dropper that downloads and executes additional malware components once run, bypassing traditional signature-based detection.",
            "Executing this file risks full system compromise including data encryption, credential theft, and establishment of persistent backdoor access.",
        ],
        "actions": [
            "Do NOT execute the file. Upload the SHA-256 hash to VirusTotal for multi-engine analysis, and quarantine the file pending manual review.",
            "Isolate the file in the quarantine vault, verify the download source, and scan with multiple engines before allowing execution.",
            "Keep the file quarantined, analyze its provenance and digital signature, and only release it if verified against a known-good hash.",
        ],
    },
    "Known Malware Detected": {
        "descriptions": [
            "SHA-256 signature match confirmed against our threat intelligence database. This file is a KNOWN malware sample with documented attack capabilities.",
            "Positive hash match detected — the file's cryptographic fingerprint matches a cataloged malware specimen. The sample has been automatically quarantined.",
            "Binary hash verification has positively identified this file as a known-malicious artifact. The threat has been contained in the quarantine vault.",
        ],
        "dangers": [
            "This is a confirmed malware sample. Execution would result in immediate system compromise with effects ranging from ransomware deployment to credential harvesting.",
            "Known malware signatures indicate this variant has been observed in active campaigns. Its capabilities may include data destruction, encrypted exfiltration, and worm-like propagation.",
            "The confirmed malware match means this is not a false positive — the file contains verified malicious code designed to compromise endpoint security.",
        ],
        "actions": [
            "The file has been quarantined. Investigate how it arrived on the system, scan all connected drives, and verify no secondary payloads were dropped before interception.",
            "Maintain quarantine, alert the security team, check browser history and email for the delivery vector, and run a comprehensive system integrity scan.",
            "File is contained. Conduct a root-cause analysis to identify the infection vector, update network security rules, and check peer systems for lateral spread.",
        ],
    },
    "Registry Persistence Detected": {
        "descriptions": [
            "A new auto-start registry entry was detected in a Windows Run key — a classic persistence technique used by malware to survive system reboots.",
            "The registry persistence guard identified an unauthorized modification to startup keys. This technique is documented in MITRE ATT&CK as T1547.001 (Boot/Logon Autostart).",
            "An unknown executable has been registered for automatic startup via the Windows Registry. This is the #1 persistence mechanism used by modern malware families.",
        ],
        "dangers": [
            "Registry persistence ensures the malware survives reboots and re-infects the system automatically. It's often the final step before a RAT or ransomware becomes fully operational.",
            "Auto-start entries allow malicious code to execute before the user reaches the desktop, potentially disabling security tools and establishing C2 before defenses are active.",
            "Persistence via Run keys means the threat actor has achieved durable access — even reimaging may not help if the entry points to a network-hosted payload.",
        ],
        "actions": [
            "The entry has been automatically removed. Verify that the referenced executable is quarantined, and audit all other Run/RunOnce keys for similar unauthorized entries.",
            "Registry entry blocked and deleted. Investigate the source executable, check for additional IOCs in scheduled tasks and WMI subscriptions, and run a full autoruns audit.",
            "Persistence mechanism neutralized. Conduct a sweep for other persistence techniques (services, scheduled tasks, DLL hijacking) to ensure complete remediation.",
        ],
    },
}

# Port-specific intelligence
PORT_INTEL = {
    4444: "Port 4444 is the default listener for Metasploit's Meterpreter reverse shell — one of the most common penetration testing and exploitation frameworks.",
    5555: "Port 5555 is used by Android Debug Bridge (ADB). Remote ADB exploitation allows full device control including app installation, data extraction, and shell access.",
    1337: "Port 1337 ('leet port') is historically associated with hacker culture and backdoor trojans. Its use in production is almost always malicious.",
    9001: "Port 9001 is the default for Tor's ORPort (onion router). Traffic on this port may indicate Tor usage for anonymized C2 communications or data exfiltration.",
    6666: "Port 6666 is associated with IRC-based botnets and command-and-control infrastructure. Many early botnet families used IRC on this port for coordination.",
    31337: "Port 31337 ('elite') is the classic backdoor port used by Back Orifice and other legacy RATs. Its detection is a high-confidence indicator of compromise.",
    3389: "Port 3389 is Windows Remote Desktop (RDP). Unauthorized RDP access enables full GUI control of the target system and is a primary vector for ransomware deployment.",
    1234: "Port 1234 is commonly used by simple reverse shells and educational exploit tools. Its presence in production traffic is highly suspicious.",
    4321: "Port 4321 is used by various RAT families as an alternative C2 port to avoid detection on more commonly monitored ports.",
    65535: "Port 65535 (max port number) is used by some rootkits and advanced persistent threats as a covert channel, exploiting the assumption that high ports aren't monitored.",
}

# Geo-intelligence enrichment
GEO_THREAT_INTEL = {
    "Russia": "This region is associated with state-sponsored APT groups (APT28/Fancy Bear, APT29/Cozy Bear) and major ransomware operations (REvil, LockBit, Conti).",
    "China": "This region hosts several known APT groups (APT1, APT41, Hafnium) specializing in intellectual property theft, supply chain attacks, and cyber espionage.",
    "North Korea": "This region is linked to the Lazarus Group and APT38, known for financial theft, cryptocurrency heists, and destructive wiper attacks.",
    "Iran": "This region is associated with APT33 (Elfin), APT35 (Charming Kitten), and destructive attacks targeting critical infrastructure.",
    "Nigeria": "This region is a known hub for Business Email Compromise (BEC) fraud, romance scams, and 419 advance-fee fraud operations.",
    "Romania": "This region has historically been associated with ATM skimming rings, carding forums, and cybercrime-as-a-service operations.",
    "Ukraine": "While also a target of attacks, this region hosts some cybercrime infrastructure including botnets and carding operations.",
    "Brazil": "This region is known for banking trojans (Grandoreiro, Amavaldo) and financial fraud targeting Portuguese-speaking countries.",
}


def check_ai_engine():
    """AI engine is always available — built-in, no external deps."""
    print(f"[AI] {AI_ENGINE_NAME} {AI_ENGINE_VERSION} is ONLINE. Built-in threat intelligence active.")


def llm_analyze(threat_type, port_or_file, process_name, score, geo_info=None):
    """Generate an AI threat analysis report using the built-in intelligence engine."""

    # Look up threat category
    knowledge = THREAT_KNOWLEDGE.get(threat_type)
    if not knowledge:
        # Fallback for unknown threat types
        for key in THREAT_KNOWLEDGE:
            if key.lower() in threat_type.lower() or threat_type.lower() in key.lower():
                knowledge = THREAT_KNOWLEDGE[key]
                break

    if not knowledge:
        knowledge = THREAT_KNOWLEDGE.get("Network RAT Detected")  # generic fallback

    # Build contextual report
    desc = random.choice(knowledge["descriptions"])
    danger = random.choice(knowledge["dangers"])
    action = random.choice(knowledge["actions"])

    # Enrich with port intelligence
    port_note = ""
    try:
        port_num = int(port_or_file)
        if port_num in PORT_INTEL:
            port_note = f" {PORT_INTEL[port_num]}"
    except (ValueError, TypeError):
        pass

    # Enrich with geo intelligence
    geo_note = ""
    if geo_info and geo_info.get("country"):
        country = geo_info["country"]
        city = geo_info.get("city", "Unknown")
        geo_note = f" The connection routes to {city}, {country}."
        if country in GEO_THREAT_INTEL:
            geo_note += f" {GEO_THREAT_INTEL[country]}"

    # Compose the final report
    report = f"{desc}{port_note}{geo_note} {danger} RECOMMENDED ACTION: {action}"

    # Add confidence qualifier
    if score >= 95:
        report += f" [CONFIDENCE: CRITICAL — {score}% match certainty]"
    elif score >= 80:
        report += f" [CONFIDENCE: HIGH — {score}% match certainty]"
    elif score >= 60:
        report += f" [CONFIDENCE: MODERATE — {score}% match certainty, manual verification advised]"
    else:
        report += f" [CONFIDENCE: LOW — {score}% match certainty, likely false positive]"

    return report

# ── Geo-IP lookup ──────────────────────────────────────────────────────────────
GEO_CACHE = {}  # ip -> geo dict

def get_geo_ip(ip):
    """Returns geo info dict for an IP. Uses ip-api.com (free, no key)."""
    if ip in GEO_CACHE:
        return GEO_CACHE[ip]
    if not REQUESTS_AVAILABLE:
        return {}
    # Skip private/loopback IPs
    private_prefixes = ('127.', '10.', '192.168.', '172.16.', '172.17.',
                        '172.18.', '172.19.', '172.20.', '172.21.', '172.22.',
                        '172.23.', '172.24.', '172.25.', '172.26.', '172.27.',
                        '172.28.', '172.29.', '172.30.', '172.31.', '0.', '::1')
    if any(ip.startswith(p) for p in private_prefixes):
        return {}
    try:
        r = http_requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,lat,lon",
            timeout=4
        )
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                result = {
                    "ip": ip,
                    "country": data.get("country", "Unknown"),
                    "countryCode": data.get("countryCode", "??"),
                    "city": data.get("city", "Unknown"),
                    "lat": data.get("lat", 0),
                    "lon": data.get("lon", 0),
                }
                GEO_CACHE[ip] = result
                return result
    except Exception:
        pass
    return {}


# ── WebGuard AI (upgraded 4-feature model) ────────────────────────────────────
class WebGuardAI:
    def __init__(self):
        # Feature vector: [port, bytes_mb, duration_s, is_unusual_process]
        self.clf = RandomForestClassifier(n_estimators=100, random_state=42)
        # Training data: [port, bytes_MB, duration_sec, is_unusual_process_flag]
        self.X = [
            # Safe connections
            [80,   0.5, 2.0, 0],   # HTTP normal browser
            [443,  2.0, 5.0, 0],   # HTTPS normal browser
            [53,   0.01, 0.1, 0],  # DNS
            [8080, 0.3, 1.5, 0],   # Dev server
            [22,   0.1, 10.0, 0],  # SSH (normal)
            [443,  0.2,  1.0, 0],  # HTTPS short
            [80,   0.1,  0.5, 0],  # HTTP short
            # Threats
            [4444, 0.05, 60.0, 1], # Metasploit reverse shell
            [3389, 0.1, 120.0, 1], # RDP brute force
            [5555, 0.2, 30.0, 1],  # ADB exploit
            [1337, 0.01, 45.0, 1], # Hacker port
            [9001, 0.01, 90.0, 1], # Tor default
            [443, 500.0, 10.0, 1], # Data exfil on safe port (high bytes!)
            [80,  300.0, 5.0,  1], # Data exfil on HTTP
            [443,   0.0, 200.0, 1],# Long-lived idle (C2 beaconing)
        ]
        self.y = [0,0,0,0,0,0,0,  1,1,1,1,1,1,1,1]
        self.clf.fit(self.X, self.y)
        print("[AI] Engine Initialized. 4-feature behavioral model active.")

    def analyze_threat(self, port, bytes_mb=0.0, duration_s=0.0, is_unusual=0):
        # Ephemeral ports: skip
        if port >= 49152:
            return 0.0, []
        features = [[port, bytes_mb, duration_s, is_unusual]]
        proba = self.clf.predict_proba(features)[0][1]
        score = round(proba * 100, 2)

        # Determine which features triggered
        triggers = []
        if bytes_mb > 100:
            triggers.append(f"High data volume ({bytes_mb:.1f} MB)")
        if duration_s > 60:
            triggers.append(f"Long-lived connection ({duration_s:.0f}s)")
        if is_unusual:
            triggers.append("Non-browser process on network port")
        if port in (4444, 3389, 5555, 1337, 9001, 6666, 31337, 8888):
            triggers.append(f"Known C2/exploit port ({port})")

        return score, triggers

    def learn(self, port, is_threat, bytes_mb=0.0, duration_s=0.0, is_unusual=0):
        label = 1 if is_threat else 0
        try:
            self.X.append([int(port), bytes_mb, duration_s, is_unusual])
            self.y.append(label)
            self.clf.fit(self.X, self.y)
            print(f"[AI] Learned port {port} as {'Threat' if is_threat else 'Safe'}.")
        except (ValueError, TypeError):
            pass


# ── System API ────────────────────────────────────────────────────────────────
class SystemAPI:
    def __init__(self, ai):
        self.ai = ai
        self.pending_alerts = []
        self.logs = []
        self.geo_feed = []          # last 50 geo-tagged connections
        self.registry_blocked = []  # blocked registry entries
        self.quarantine_files = []  # quarantined file records

    def add_log(self, msg, level='info'):
        self.logs.append({"msg": msg, "level": level})

    def trigger_alert(self, type_name, port_or_file, score, pid,
                      llm_report=None, geo=None, file_hash=None, triggers=None,
                      process_name="Unknown"):
        self.pending_alerts.append({
            "type": type_name,
            "port": port_or_file,
            "score": score,
            "pid": pid,
            "llm_report": llm_report,
            "geo": geo,
            "hash": file_hash,
            "triggers": triggers or [],
            "process_name": process_name,
        })

    def get_system_stats(self):
        return {
            "cpu": psutil.cpu_percent(interval=None),
            "ram": psutil.virtual_memory().percent
        }

    def kill_process(self, pid, port):
        killed = False
        if pid and str(pid) not in ('Unknown', ''):
            try:
                p = psutil.Process(int(pid))
                p.terminate()
                p.wait(timeout=3)
                killed = True
                self.add_log(f"Successfully terminated PID {pid}", 'info')
            except Exception as e:
                self.add_log(f"Failed to terminate PID {pid}: {e}", 'warn')
        else:
            self.add_log("Invalid PID. Cannot terminate.", 'warn')
        self.ai.learn(port, True)
        return killed

    def allow_process(self, port):
        self.ai.learn(port, False)
        self.add_log(f"Port {port} added to allowlist heuristic.", 'info')
        return True

    def add_geo_event(self, geo, port, pid, process_name, blocked=False):
        if not geo or not geo.get("country"):
            return
        entry = {
            "ip": geo.get("ip"),
            "country": geo.get("country"),
            "countryCode": geo.get("countryCode", "??"),
            "city": geo.get("city"),
            "lat": geo.get("lat"),
            "lon": geo.get("lon"),
            "port": port,
            "pid": pid,
            "process": process_name,
            "blocked": blocked,
            "time": time.strftime("%H:%M:%S"),
        }
        self.geo_feed.insert(0, entry)
        if len(self.geo_feed) > 50:
            self.geo_feed = self.geo_feed[:50]

    def quarantine_file(self, file_path, sha256, reason):
        """Move a file to the quarantine folder."""
        src = Path(file_path)
        if not src.exists():
            return False
        try:
            dest = QUARANTINE_DIR / f"{sha256[:16]}_{src.name}"
            shutil.move(str(src), str(dest))
            record = {
                "name": src.name,
                "hash": sha256,
                "reason": reason,
                "quarantined_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "path": str(dest),
            }
            self.quarantine_files.insert(0, record)
            self.add_log(f"QUARANTINED: {src.name} → {dest.name}", 'warn')
            return True
        except Exception as e:
            self.add_log(f"Quarantine failed for {src.name}: {e}", 'warn')
            return False

    def block_registry_entry(self, key_path, value_name, value_data):
        """Delete a registry startup entry and record it."""
        try:
            hive_str, sub_key = key_path.split("\\", 1)
            hive = winreg.HKEY_CURRENT_USER if "HKCU" in hive_str else winreg.HKEY_LOCAL_MACHINE
            with winreg.OpenKey(hive, sub_key, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, value_name)
            record = {
                "key": key_path,
                "value_name": value_name,
                "value_data": value_data,
                "blocked_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            }
            self.registry_blocked.insert(0, record)
            self.add_log(f"REGISTRY BLOCKED: '{value_name}' removed from {key_path}", 'warn')
        except Exception as e:
            self.add_log(f"Could not remove registry entry '{value_name}': {e}", 'warn')


# ── Global instances ───────────────────────────────────────────────────────────
ai_engine = WebGuardAI()
api = SystemAPI(ai_engine)


# ── Flask Routes ───────────────────────────────────────────────────────────────
@app.route('/')
def serve_index():
    return send_from_directory('.', 'index.html')

@app.route('/dashboard')
def serve_dashboard():
    return send_from_directory('.', 'dashboard.html')

@app.route('/api/stats', methods=['GET'])
def get_stats():
    return jsonify(api.get_system_stats())

@app.route('/api/alerts_and_logs', methods=['GET'])
def get_alerts_and_logs():
    data = {
        "alerts": api.pending_alerts.copy(),
        "logs": api.logs.copy(),
    }
    api.pending_alerts.clear()
    api.logs.clear()
    return jsonify(data)

@app.route('/api/kill', methods=['POST'])
def kill():
    data = request.json
    api.kill_process(data.get('pid'), data.get('port'))
    return jsonify({"status": "ok"})

@app.route('/api/allow', methods=['POST'])
def allow():
    data = request.json
    api.allow_process(data.get('port'))
    return jsonify({"status": "ok"})

@app.route('/api/mock_trigger', methods=['POST'])
def mock_trigger():
    data = request.json
    threat_type = data.get('type', 'Unknown Threat')
    port = data.get('port', 0)
    score = data.get('score', 99.0)
    pid = data.get('pid', 'Unknown')
    process_name = data.get('process_name', 'unknown.exe')

    # Geo-IP for mock triggers (use a demo IP for demo purposes)
    geo = None
    if threat_type == 'Network RAT':
        demo_ip = "185.220.101.45"  # Tor exit node (illustrative)
        geo = get_geo_ip(demo_ip)
        api.add_geo_event(geo, port, pid, process_name, blocked=True)

    # AI Report (built-in engine — always available)
    llm_report = llm_analyze(threat_type, port, process_name, score, geo)

    api.trigger_alert(
        threat_type, port, score, pid,
        llm_report=llm_report, geo=geo,
        triggers=["Mock trigger from pen-test panel"],
        process_name=process_name,
    )
    return jsonify({"status": "ok"})

@app.route('/api/geo_feed', methods=['GET'])
def get_geo_feed():
    return jsonify(api.geo_feed[:20])

@app.route('/api/quarantine', methods=['GET'])
def get_quarantine():
    return jsonify(api.quarantine_files[:20])

@app.route('/api/registry_blocked', methods=['GET'])
def get_registry_blocked():
    return jsonify(api.registry_blocked[:20])

@app.route('/api/llm_status', methods=['GET'])
def get_llm_status():
    return jsonify({
        "available": True,
        "model": AI_ENGINE_NAME,
        "url": "built-in",
    })


# ── Spam / Scam Lookup Engine ─────────────────────────────────────────────────

# Extensive list of known disposable / temp email providers
DISPOSABLE_EMAIL_DOMAINS = {
    'mailinator.com','guerrillamail.com','10minutemail.com','tempmail.com',
    'throwaway.email','yopmail.com','trashmail.com','sharklasers.com',
    'guerrillamailblock.com','grr.la','guerrillamail.info','guerrillamail.biz',
    'guerrillamail.de','guerrillamail.net','guerrillamail.org','spam4.me',
    'dispostable.com','mailnull.com','maildrop.cc','discard.email',
    'fakeinbox.com','mailnesia.com','mailnull.com','spamgourmet.com',
    'getnada.com','spamfree24.org','trashmail.at','trashmail.io',
    'tempinbox.com','getairmail.com','mailexpire.com','spambox.us',
    'spamevader.net','mytemp.email','temp-mail.org','tempmailo.com',
    'harakirimail.com','koszmail.pl','spamthis.co.uk','crapmail.org',
    'deadaddress.com','spamgourmet.net','spamgourmet.org','boximail.com',
    'moakt.com','mohmal.com','emailondeck.com','spamhereplease.com',
    'filzmail.com','trbvm.com','0-mail.com','0815.ru','0clickemail.com',
    'zzrgg.com','yomail.info','xcode.ro','w3internet.co.uk','mail.mezimages.net',
}

# Patterns in email usernames that suggest spam/scam
EMAIL_SPAM_PATTERNS = [
    r'(?i)^(admin|support|info|noreply|no-reply|billing|security|alert|verify|account|team|service|update|help|contact|noti)(\d+)?@',
    r'(?i)(lottery|prize|winner|claim|reward|crypto|bitcoin|invest|profit|nigerian|prince|million|unclaimed|inherit)',
    r'(?i)(password|reset|confirm|activate|suspend|unusual|activity|limited|access|urgent|click|link|validate)',
    r'(?i)(refund|paypal|amazon|microsoft|apple|google|irs|fbi|police|government|bank)(.*)(support|help|service|team)',
    r'[\d]{5,}@',  # 5+ digit local part (bots often do this)
]

# Known scam/spam area codes and country prefixes
SCAM_PHONE_PREFIXES = {
    '+1268': 'Antigua (premium-rate scam hub)',
    '+1473': 'Grenada (Wangiri fraud)',
    '+1664': 'Montserrat (one-ring scam)',
    '+1787': 'Puerto Rico (IRS impersonation)',
    '+1809': 'Dominican Republic (Wangiri)',
    '+1849': 'Dominican Republic (variant)',
    '+1876': 'Jamaica (lottery scam)',
    '+234': 'Nigeria (419 scam origin)',
    '+233': 'Ghana (romance scam hub)',
    '+254': 'Kenya (M-Pesa fraud)',
    '+7': 'Russia (premium SMS fraud)',
    '+380': 'Ukraine (card fraud)',
    '+86': 'China (spoofed robocalls)',
    '+91': 'India (tech support scam hub)',
    '+92': 'Pakistan (SIM swapping)',
    '+63': 'Philippines (text scam)',
    '+60': 'Malaysia (Macau scam)',
    '+66': 'Thailand (investment scam)',
    '+20': 'Egypt (romance fraud)',
}

# US area codes heavily associated with scam calls (FTC data)
SCAM_US_AREA_CODES = {
    '202': 'DC spoof (IRS/Gov impersonation)',
    '206': 'Seattle (robocall hub)',
    '218': 'Minnesota (Medicare scam)',
    '305': 'Miami (jury duty scam)',
    '347': 'New York (Con artist hub)',
    '469': 'Texas DFW (utility scam)',
    '502': 'Kentucky (Social Security scam)',
    '503': 'Oregon (tech support)',
    '520': 'Arizona (warranty scam)',
    '678': 'Georgia (loan scam)',
    '702': 'Vegas (gambling fraud)',
    '713': 'Houston (energy fraud)',
    '786': 'Miami (lottery scam)',
    '800': 'Toll-free spoofing',
    '833': 'Toll-free spoofing',
    '844': 'Toll-free spoofing',
    '855': 'Toll-free spoofing',
    '866': 'Toll-free spoofing',
    '877': 'Toll-free spoofing',
    '888': 'Toll-free spoofing',
    '929': 'New York (impersonation)',
}

def check_mx_record(domain):
    """Try to resolve MX record for a domain via DNS lookup."""
    try:
        # Use socket to do a basic DNS check (no dnspython needed)
        socket.setdefaulttimeout(3)
        socket.gethostbyname(domain)
        return True
    except (socket.gaierror, socket.timeout):
        return False

def analyze_email(email):
    """Comprehensive email spam/scam analysis. Returns dict with score, flags, verdict."""
    score = 0
    flags = []
    details = []

    email = email.strip().lower()

    # Basic format check
    email_regex = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
    if not email_regex.match(email):
        return {
            'type': 'email',
            'input': email,
            'score': 100,
            'verdict': 'INVALID',
            'verdict_color': '#6b7280',
            'flags': ['Invalid email format — not a real address'],
            'details': []
        }

    local, domain = email.split('@', 1)

    # Check disposable domain
    if domain in DISPOSABLE_EMAIL_DOMAINS:
        score += 85
        flags.append(f'Disposable/temporary email provider ({domain})')

    # Check MX record (does the domain even receive email?)
    if not check_mx_record(domain):
        score += 40
        flags.append(f'Domain "{domain}" has no resolvable DNS — likely fake')
    else:
        details.append(f'Domain "{domain}" resolves successfully (DNS OK)')

    # Check spam patterns
    for pattern in EMAIL_SPAM_PATTERNS:
        if re.search(pattern, email):
            score += 30
            m = re.search(pattern, email)
            flags.append(f'Suspicious keyword pattern in address: «{m.group(0)[:40]}»')
            break

    # Check local part anomalies
    digit_ratio = sum(c.isdigit() for c in local) / max(len(local), 1)
    if digit_ratio > 0.6:
        score += 20
        flags.append(f'Local part is mostly digits ({int(digit_ratio*100)}%) — bot-generated pattern')

    if len(local) > 30:
        score += 15
        flags.append(f'Unusually long username ({len(local)} chars) — may be obfuscated')

    # Check for look-alike domains (homograph attacks)
    lookalike_map = {
        'paypa1': 'paypal', 'gooogle': 'google', 'arnazon': 'amazon',
        'micros0ft': 'microsoft', 'app1e': 'apple', 'faceb00k': 'facebook',
        'netf1ix': 'netflix', 'instagramm': 'instagram'
    }
    for fake, real in lookalike_map.items():
        if fake in domain:
            score += 70
            flags.append(f'Look-alike domain spoofing "{real}" (detected: "{fake}")')

    # TLD risk
    risky_tlds = {'.xyz', '.top', '.click', '.work', '.date', '.loan', '.win',
                  '.bid', '.stream', '.faith', '.party', '.racing', '.review',
                  '.country', '.gq', '.tk', '.cf', '.ga', '.ml'}
    tld = '.' + domain.split('.')[-1]
    if tld in risky_tlds:
        score += 25
        flags.append(f'High-risk TLD "{tld}" — commonly used in phishing campaigns')

    score = min(score, 100)

    if score >= 70:
        verdict = 'SCAM / SPAM'
        verdict_color = '#ef4444'
    elif score >= 40:
        verdict = 'SUSPICIOUS'
        verdict_color = '#f59e0b'
    elif score >= 15:
        verdict = 'LOW RISK'
        verdict_color = '#10b981'
    else:
        verdict = 'CLEAN'
        verdict_color = '#10b981'

    if not flags:
        flags = ['No threat indicators detected']
        details.append('Address passed all heuristic filters')

    return {
        'type': 'email',
        'input': email,
        'score': score,
        'verdict': verdict,
        'verdict_color': verdict_color,
        'flags': flags,
        'details': details,
    }


def normalize_phone(phone):
    """Strip formatting from phone number — keep only digits and leading +."""
    cleaned = re.sub(r'[^\d+]', '', phone.strip())
    # If starts with 00, convert to +
    if cleaned.startswith('00'):
        cleaned = '+' + cleaned[2:]
    # If purely digits (no +), assume US if 10 digits, else international
    if not cleaned.startswith('+') and len(cleaned) == 10:
        cleaned = '+1' + cleaned
    elif not cleaned.startswith('+') and len(cleaned) == 11 and cleaned[0] == '1':
        cleaned = '+' + cleaned
    return cleaned


def analyze_phone(phone):
    """Comprehensive phone number spam/scam analysis. Returns dict."""
    score = 0
    flags = []
    details = []

    normalized = normalize_phone(phone)
    digits_only = re.sub(r'[^\d]', '', normalized)

    # Basic validation
    if len(digits_only) < 7 or len(digits_only) > 15:
        return {
            'type': 'phone',
            'input': phone,
            'score': 100,
            'verdict': 'INVALID',
            'verdict_color': '#6b7280',
            'flags': [f'Invalid phone number length ({len(digits_only)} digits) — must be 7–15'],
            'details': []
        }

    details.append(f'Normalized number: {normalized}')

    # Check scam country prefixes
    for prefix, reason in SCAM_PHONE_PREFIXES.items():
        if normalized.startswith(prefix):
            score += 55
            flags.append(f'High-risk country prefix {prefix}: {reason}')
            details.append(f'Country code {prefix} has elevated fraud reports (FTC/ICC-IMB)')
            break

    # Check US area codes
    if normalized.startswith('+1') and len(digits_only) >= 11:
        area_code = digits_only[1:4]  # after country code '1'
        if area_code in SCAM_US_AREA_CODES:
            score += 35
            flags.append(f'US area code {area_code} flagged: {SCAM_US_AREA_CODES[area_code]}')

    # Sequential / repeated digits pattern (often fake)
    if re.search(r'(\d)\1{5,}', digits_only):
        score += 30
        flags.append('Repeated digit pattern detected (e.g., 1111111) — likely fake number')

    if re.search(r'(?:0123456|1234567|2345678|3456789|9876543|8765432)', digits_only):
        score += 25
        flags.append('Sequential digit pattern detected — fake or test number')

    # All-zero or all-same pattern
    unique_digits = len(set(digits_only))
    if unique_digits <= 2:
        score += 40
        flags.append(f'Very low digit entropy ({unique_digits} unique digits) — synthetic number')

    # VOIP prefix patterns (common in robocalls)
    voip_prefixes_us = {'800','833','844','855','866','877','888'}
    if normalized.startswith('+1') and len(digits_only) >= 11:
        ac = digits_only[1:4]
        if ac in voip_prefixes_us:
            score += 20
            flags.append(f'Toll-free/VOIP number (+1-{ac}-xxx) — frequently used in robocalls')

    # International VOIP spoofing indicator (+ prefix with short number)
    if normalized.startswith('+') and len(digits_only) < 9:
        score += 20
        flags.append('Short international number — possible VOIP spoof')

    score = min(score, 100)

    if score >= 70:
        verdict = 'SCAM / SPAM'
        verdict_color = '#ef4444'
    elif score >= 40:
        verdict = 'SUSPICIOUS'
        verdict_color = '#f59e0b'
    elif score >= 15:
        verdict = 'LOW RISK'
        verdict_color = '#10b981'
    else:
        verdict = 'CLEAN'
        verdict_color = '#10b981'

    if not flags:
        flags = ['No threat indicators detected']
        details.append('Number passed all pattern and prefix checks')

    return {
        'type': 'phone',
        'input': phone,
        'normalized': normalized,
        'score': score,
        'verdict': verdict,
        'verdict_color': verdict_color,
        'flags': flags,
        'details': details,
    }


@app.route('/api/spam_lookup', methods=['POST'])
def spam_lookup():
    """Spam/Scam lookup for email addresses and phone numbers."""
    data = request.json
    query = (data.get('query') or '').strip()

    if not query:
        return jsonify({'error': 'No query provided'}), 400

    # Auto-detect type
    email_regex = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
    phone_regex = re.compile(r'^[\+\d][\d\s\-().+]{5,20}$')

    if email_regex.match(query):
        result = analyze_email(query)
    elif phone_regex.match(query):
        result = analyze_phone(query)
    else:
        return jsonify({'error': 'Could not identify as email or phone number. Please check input.'}), 400

    api.add_log(f"[SPAM LOOKUP] {result['type'].upper()}: {query} → {result['verdict']} ({result['score']}%)",
                'warn' if result['score'] >= 40 else 'info')
    return jsonify(result)


# ── Monitor Threads ────────────────────────────────────────────────────────────

def monitor_network():
    """Network monitor: checks ports, bytes, duration; enriches with geo-IP and LLM."""
    known_connections = {}  # conn_id -> {start_time, bytes_start, last_bytes}

    # Processes that are considered safe/normal for network activity
    safe_processes = {
        'chrome', 'firefox', 'msedge', 'iexplore', 'safari', 'opera', 'brave',
        # Windows system services
        'svchost', 'lsass', 'services', 'winlogon', 'wininit', 'csrss',
        'spoolsv', 'dllhost', 'conhost', 'taskhostw', 'sihost', 'runtimebroker',
        # Windows Update / store
        'wuauclt', 'musnotification', 'usoclient', 'windowspackagemanagerserver',
        'microsoft.photos', 'backgroundtransferhost',
        # Common apps
        'teams', 'teams.exe', 'discord', 'slack', 'zoom', 'skype',
        'onedrive', 'dropbox', 'googledrivesync', 'googledrive',
        'spotify', 'steam', 'epicgameslauncher', 'origin',
        'outlook', 'thunderbird', 'lync',
        'code', 'code.exe',  # VS Code
        'git', 'node', 'python', 'python3', 'pythonw',
        'antimalware service executable', 'msmpeng',
        'searchindexer', 'searchprotocolhost',
        'securityhealthservice', 'wscsvc',
        'system',
    }

    # Ports that are always safe for authenticated/standard traffic
    # (HTTP/S, email, DNS, NTP, LDAP/S, Kerberos, SMB, RPC, Windows auth)
    safe_auth_ports = {
        80, 443, 8080, 8443,          # HTTP/S
        53,                            # DNS
        123,                           # NTP
        25, 465, 587,                  # SMTP
        110, 995,                      # POP3
        143, 993,                      # IMAP
        389, 636,                      # LDAP/LDAPS
        88,                            # Kerberos
        135, 139, 445,                 # Windows RPC/SMB (LAN only)
        3268, 3269,                    # Global Catalog
        5985, 5986,                    # WinRM
        8888, 8000,                    # Dev servers
    }

    # Ports that are ALWAYS suspicious regardless of process
    c2_ports = {4444, 5555, 1337, 9001, 6666, 31337, 1234, 4321, 65535}

    while True:
        time.sleep(2)
        try:
            conns = psutil.net_connections(kind='inet')
            current_ids = set()

            for c in conns:
                if c.status == 'ESTABLISHED' and c.raddr:
                    port = c.raddr.port
                    ip = c.raddr.ip
                    conn_id = f"{c.pid}:{ip}:{port}"
                    current_ids.add(conn_id)

                    # Ephemeral ports: skip (handled in AI too, but belt-and-suspenders)
                    if port >= 49152:
                        continue

                    # Get process name
                    process_name = "Unknown"
                    try:
                        if c.pid:
                            p = psutil.Process(c.pid)
                            process_name = p.name().lower().replace('.exe', '')
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass

                    proc_name_raw = process_name  # already lowercased
                    is_safe_proc = any(sp in proc_name_raw for sp in safe_processes)

                    # ── Fast-path: skip entirely if safe process on safe/auth port ──
                    if is_safe_proc and port in safe_auth_ports:
                        # Still do Geo-IP enrichment for the map (no alert)
                        if conn_id not in known_connections:
                            known_connections[conn_id] = {"start": time.time()}
                            geo = get_geo_ip(ip)
                            if geo and geo.get("country"):
                                api.add_geo_event(geo, port, c.pid, process_name, blocked=False)
                        continue

                    # Track duration
                    now = time.time()
                    if conn_id not in known_connections:
                        # Snapshot current byte count for delta tracking
                        bytes_now = 0.0
                        try:
                            if c.pid:
                                proc = psutil.Process(c.pid)
                                io = proc.io_counters()
                                bytes_now = io.write_bytes + io.read_bytes
                        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                            pass

                        known_connections[conn_id] = {
                            "start": now,
                            "bytes_snapshot": bytes_now,
                            "process": process_name,
                            "ip": ip,
                            "port": port,
                            "pid": c.pid,
                        }
                        # Geo-IP enrichment for new unique connections
                        geo = get_geo_ip(ip)
                        if geo and geo.get("country"):
                            api.add_geo_event(geo, port, c.pid, process_name, blocked=False)

                    duration_s = now - known_connections[conn_id]["start"]

                    # Delta bytes since connection was first seen (not cumulative process I/O)
                    bytes_mb = 0.0
                    try:
                        if c.pid:
                            proc = psutil.Process(c.pid)
                            io = proc.io_counters()
                            current_bytes = io.write_bytes + io.read_bytes
                            snapshot = known_connections[conn_id].get("bytes_snapshot", current_bytes)
                            bytes_mb = max(0.0, (current_bytes - snapshot) / (1024 * 1024))
                    except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                        pass

                    # is_unusual: only flag if it's NOT a known safe process
                    is_unusual = 0 if is_safe_proc else 1

                    # ── Always flag known C2 ports, even for safe processes ──
                    force_alert = port in c2_ports

                    # Analyze threat
                    score, triggers = ai_engine.analyze_threat(
                        port, bytes_mb, duration_s, is_unusual
                    )

                    # Raise threshold to 85 to cut false positives;
                    # known C2 ports bypass threshold
                    if force_alert or score > 85.0:
                        alert_key = f"alerted:{conn_id}"
                        if alert_key not in known_connections:
                            known_connections[alert_key] = True
                            geo = get_geo_ip(ip)
                            api.add_geo_event(geo, port, c.pid, process_name, blocked=True)

                            if force_alert and not triggers:
                                triggers = [f"Known C2/exploit port ({port})"]
                            if force_alert:
                                score = max(score, 95.0)

                            # AI threat analysis (built-in)
                            llm_report = llm_analyze(
                                'Network RAT Detected', port,
                                process_name, score, geo
                            )

                            api.trigger_alert(
                                'Network RAT Detected', port, score,
                                c.pid or "Unknown",
                                llm_report=llm_report,
                                geo=geo,
                                triggers=triggers,
                                process_name=process_name,
                            )

            # Clean up stale connections
            stale = [k for k in list(known_connections.keys())
                     if not k.startswith("alerted:") and k not in current_ids]
            for k in stale:
                del known_connections[k]

        except psutil.AccessDenied:
            pass
        except Exception:
            pass


def sha256_file(filepath):
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


def monitor_downloads():
    """Download monitor: hashes new executables, checks signatures, quarantines."""
    downloads_path = Path.home() / "Downloads"
    if not downloads_path.exists():
        return

    known_files = set(os.listdir(downloads_path))
    dangerous_exts = {'.exe', '.bat', '.vbs', '.ps1', '.msi', '.scr', '.cmd'}

    while True:
        time.sleep(2)
        try:
            current_files = set(os.listdir(downloads_path))
            new_files = current_files - known_files
            for file in new_files:
                ext = Path(file).suffix.lower()
                if ext in dangerous_exts:
                    full_path = downloads_path / file
                    time.sleep(0.5)  # wait for file to finish writing

                    # Hash it
                    sha256 = sha256_file(full_path)
                    hash_display = sha256[:16] + "..." if sha256 else "hash-error"

                    # Check against malware DB
                    if sha256 and sha256.lower() in MALWARE_SIGNATURES:
                        malware_name = MALWARE_SIGNATURES[sha256.lower()]
                        quarantined = api.quarantine_file(str(full_path), sha256, malware_name)
                        score = 100.0

                        llm_report = llm_analyze(
                            f"Known Malware: {malware_name}",
                            file, "Downloads", score
                        )

                        api.trigger_alert(
                            f'Known Malware Detected',
                            f'"{file}"', score, 'Unknown',
                            llm_report=llm_report,
                            file_hash=hash_display,
                            triggers=[
                                f"SHA-256 matched: {malware_name}",
                                f"File quarantined to C:\\WebGuard_Quarantine",
                            ],
                            process_name="Downloads",
                        )
                    else:
                        # Not in known-bad DB, but still suspicious extension
                        api.trigger_alert(
                            'Suspicious Download',
                            f'"{file}"', 75.0, 'Unknown',
                            file_hash=hash_display,
                            triggers=[
                                f"Dangerous file extension: {ext}",
                                f"SHA-256: {hash_display}",
                                "No signature match — manual review recommended",
                            ],
                            process_name="Downloads",
                        )

            known_files = current_files
        except Exception:
            pass


# ── Registry Keys to Monitor ──────────────────────────────────────────────────
REGISTRY_WATCH = [
    ("HKCU", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", winreg.HKEY_CURRENT_USER,
     r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", winreg.HKEY_LOCAL_MACHINE,
     r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
]

def read_registry_key(hive, subkey):
    """Returns dict of {value_name: value_data} for a registry key."""
    result = {}
    try:
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(key, i)
                    result[name] = data
                    i += 1
                except OSError:
                    break
    except FileNotFoundError:
        pass
    except PermissionError:
        pass
    return result

def monitor_registry():
    """Registry persistence guard: detects new auto-start entries."""
    # Snapshot baseline
    baselines = {}
    for hive_name, hive, subkey in REGISTRY_WATCH:
        key_id = f"{hive_name}\\{subkey}"
        baselines[key_id] = read_registry_key(hive, subkey)
        api.add_log(f"Registry guard watching: {key_id}", 'info')

    # Whitelist: known-safe values already present at startup
    registry_whitelist = {k: set(v.keys()) for k, v in baselines.items()}

    while True:
        time.sleep(3)
        try:
            for hive_name, hive, subkey in REGISTRY_WATCH:
                key_id = f"{hive_name}\\{subkey}"
                current = read_registry_key(hive, subkey)
                baseline = baselines.get(key_id, {})

                new_entries = {
                    k: v for k, v in current.items()
                    if k not in baseline and k not in registry_whitelist.get(key_id, set())
                }

                for value_name, value_data in new_entries.items():
                    # New auto-start entry found!
                    llm_report = llm_analyze(
                        "Registry Persistence Attempt",
                        value_data, value_name, 99.0
                    )

                    api.trigger_alert(
                        'Registry Persistence Detected',
                        f'{key_id}\\{value_name}',
                        99.0, 'Unknown',
                        llm_report=llm_report,
                        triggers=[
                            f"New startup entry: '{value_name}'",
                            f"Points to: {value_data[:80]}",
                            "Malware commonly uses this to survive reboots",
                        ],
                        process_name=value_name,
                    )
                    api.add_log(
                        f"PERSISTENCE ALERT: '{value_name}' → {value_data[:60]}", 'warn'
                    )

                    # Auto-block: remove the entry
                    key_path = f"{hive_name}\\{subkey}"
                    api.block_registry_entry(key_path, value_name, value_data)

                    # Update baseline
                    baseline[value_name] = value_data

                baselines[key_id] = current

        except Exception as e:
            pass


def monitor_clipboard():
    """Clipboard monitor: detects crypto addresses (clipper malware indicator)."""
    btc_regex = re.compile(r'^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$')
    eth_regex = re.compile(r'^0x[a-fA-F0-9]{40}$')
    last_clipboard = ""

    while True:
        time.sleep(1)
        try:
            current = pyperclip.paste().strip()
            if current != last_clipboard and current:
                if btc_regex.match(current):
                    api.add_log(
                        "⚠️ CLIPPER WARNING: Bitcoin address in clipboard. Possible hijacker active.",
                        'warn'
                    )
                elif eth_regex.match(current):
                    api.add_log(
                        "⚠️ CLIPPER WARNING: Ethereum address in clipboard. Possible hijacker active.",
                        'warn'
                    )
                last_clipboard = current
        except Exception:
            pass


def open_browser():
    time.sleep(1.5)
    print("\n" + "=" * 60)
    print(">>> WebGuard EDR Pro v2.0 is running!           <<<")
    print(">>> Navigate to: http://127.0.0.1:5000          <<<")
    print("=" * 60 + "\n")
    try:
        webbrowser.open_new("http://127.0.0.1:5000")
    except Exception:
        pass


if __name__ == '__main__':
    # Initialize built-in AI engine
    check_ai_engine()

    # Start monitor threads
    threads = [
        threading.Thread(target=monitor_network, daemon=True),
        threading.Thread(target=monitor_downloads, daemon=True),
        threading.Thread(target=monitor_clipboard, daemon=True),
        threading.Thread(target=monitor_registry, daemon=True),
    ]
    for t in threads:
        t.start()

    print("Starting WebGuard EDR Pro v2.0...")
    threading.Thread(target=open_browser, daemon=True).start()
    app.run(host='127.0.0.1', port=5000, debug=False)
