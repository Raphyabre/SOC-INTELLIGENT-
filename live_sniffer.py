import sys
try:
    sys.stdout.reconfigure(encoding='utf-8')
except:
    pass

import time
import requests
import random
import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP
import sqlite3
from datetime import datetime
import json

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

API_URL = "http://127.0.0.1:8000/predict"
DB_FILE = "soc_alerts.db"

def init_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            src_ip TEXT,
            src_lat REAL,
            src_lon REAL,
            dst_ip TEXT,
            dst_lat REAL,
            dst_lon REAL,
            protocol_type TEXT,
            service TEXT,
            src_bytes INTEGER,
            dst_bytes INTEGER,
            true_label TEXT,
            prediction TEXT,
            confidence REAL,
            ensemble_score REAL,
            shap_json TEXT,
            mitre_tactic TEXT,
            mitre_technique TEXT,
            ai_report TEXT
        )
    """)
    conn.commit()
    conn.close()

def save_event_to_db(timestamp, raw_data, pred_result, geo_data):
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        shap_json = json.dumps(pred_result.get("top_shap_features", {}))
        mitre_info = pred_result.get("mitre", {})
        
        cursor.execute("""
            INSERT INTO events (
                timestamp, src_ip, src_lat, src_lon, dst_ip, dst_lat, dst_lon,
                protocol_type, service, src_bytes, dst_bytes,
                true_label, prediction, confidence, ensemble_score, shap_json,
                mitre_tactic, mitre_technique, ai_report
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            geo_data["src_ip"],
            geo_data["src_lat"],
            geo_data["src_lon"],
            geo_data["dst_ip"],
            geo_data["dst_lat"],
            geo_data["dst_lon"],
            raw_data.get("protocol_type"),
            raw_data.get("service"),
            int(raw_data.get("src_bytes", 0)),
            int(raw_data.get("dst_bytes", 0)),
            pred_result.get("true_label", "unknown"),
            pred_result.get("prediction", "UNKNOWN"),
            float(pred_result.get("confidence", 0)),
            float(pred_result.get("ensemble_score", 0)),
            shap_json,
            mitre_info.get("tactic", "N/A"),
            mitre_info.get("technique", "N/A"),
            pred_result.get("ai_report", "")
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ Erreur SQLite: {e}")

FEATURE_COLS = [
    'duration', 'protocol_type', 'service', 'flag', 'src_bytes',
    'dst_bytes', 'land', 'wrong_fragment', 'urgent', 'hot',
    'num_failed_logins', 'logged_in', 'num_compromised', 'root_shell',
    'su_attempted', 'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count', 'dst_host_same_srv_rate',
    'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
    'dst_host_srv_diff_host_rate', 'dst_host_serror_rate',
    'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
    'dst_host_srv_rerror_rate'
]

def resolve_geo(ip: str) -> dict:
    """Mock géolocalisation pour le vrai réseau local."""
    if ip.startswith("192.168.") or ip.startswith("10.") or ip == "127.0.0.1":
        return {"lat": 48.8566, "lon": 2.3522} # Local = Paris
    
    cities = [
        {"lat": 40.7128, "lon": -74.0060}, # NY
        {"lat": 39.9042, "lon": 116.4074}, # Beijing
        {"lat": 55.7558, "lon": 37.6173},  # Moscow
        {"lat": 51.5074, "lon": -0.1278}   # London
    ]
    return random.choice(cities)

def packet_handler(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_bytes = len(pkt)
        dst_bytes = 0  # Simplification unidirectionnelle pour le direct
        
        protocol_type = "tcp"
        service = "other"
        
        if TCP in pkt:
            protocol_type = "tcp"
            port = pkt[TCP].dport
            if port == 80 or port == 443: service = "http"
            elif port == 21: service = "ftp"
            elif port == 22: service = "ssh"
            elif port == 25: service = "smtp"
        elif UDP in pkt:
            protocol_type = "udp"
            port = pkt[UDP].dport
            if port == 53: service = "domain_u"
        elif ICMP in pkt:
            protocol_type = "icmp"
            service = "eco_i"
        else:
            return # On ignore le reste

        # Construction du payload type NSL-KDD avec des valeurs par défaut pour les features complexes
        event_data = {col: 0.0 for col in FEATURE_COLS}
        event_data['protocol_type'] = protocol_type
        event_data['service'] = service
        event_data['flag'] = "SF"
        event_data['src_bytes'] = float(src_bytes)
        event_data['dst_bytes'] = float(dst_bytes)
        
        src_geo = resolve_geo(src_ip)
        dst_geo = resolve_geo(dst_ip)
        geo_data = {
            "src_ip": src_ip,
            "src_lat": src_geo["lat"],
            "src_lon": src_geo["lon"],
            "dst_ip": dst_ip,
            "dst_lat": dst_geo["lat"],
            "dst_lon": dst_geo["lon"]
        }
        
        payload = {
            "data": event_data,
            "true_label": "normal",
            "geo_data": geo_data
        }
        
        try:
            response = requests.post(API_URL, json=payload, timeout=2)
            if response.status_code == 200:
                pred_result = response.json()
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                save_event_to_db(timestamp, event_data, pred_result, geo_data)
                
                status = "🔴 BLOCKED" if pred_result.get("action_taken") == "Blocked at Firewall" else ("🚨 ATTACK" if pred_result.get("prediction") == "ATTACK" else "✅ OK")
                print(f"[{status}] {src_ip} -> {dst_ip} [{protocol_type}/{service}] - {src_bytes}B")
        except Exception as e:
            print(f"API unreachable: {e}")

if __name__ == "__main__":
    init_database()
    print("======================================================")
    print("📡 LIVE SNIFFER STARTING...")
    print("Ecoute du trafic reel. Appuyez sur Ctrl+C pour arreter.")
    print("======================================================")
    
    try:
        # Sniff sur l'interface par défaut
        sniff(prn=packet_handler, store=False, filter="ip")
    except KeyboardInterrupt:
        print("\nArret du sniffer.")
    except Exception as e:
        print(f"\nErreur de capture : {e}")
        print("Avez-vous installe Npcap (https://npcap.com/) sur Windows ?")
