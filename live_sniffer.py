import sys
try:
    sys.stdout.reconfigure(encoding='utf-8')
except:
    pass

import time
import requests
import random
import logging
from collections import deque
import threading
from scapy.all import sniff, IP, TCP, UDP, ICMP
import sqlite3
from datetime import datetime
import json

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

API_URL = "http://127.0.0.1:8000/predict"
DB_FILE = "soc_alerts.db"

# =====================================================================
# ROLLING WINDOW ENGINE — Intelligence Statistique Temps Réel
# =====================================================================
# Cette structure mémorise les 2000 dernières connexions pour calculer
# les features statistiques NSL-KDD (count, srv_count, serror_rate, etc.)
# en temps réel au lieu d'envoyer des zéros à l'IA.
# =====================================================================

ROLLING_WINDOW = deque(maxlen=2000)
WINDOW_LOCK = threading.Lock()
WINDOW_SECONDS = 2.0  # Fenêtre glissante de 2 secondes (similaire à NSL-KDD)


def compute_rolling_features(src_ip, dst_ip, protocol_type, service, flag):
    """Calcule les 19 features statistiques NSL-KDD depuis le trafic réel capturé."""
    now = time.time()

    with WINDOW_LOCK:
        # Enregistrer la connexion courante dans la fenêtre
        ROLLING_WINDOW.append({
            'time': now,
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'protocol': protocol_type,
            'service': service,
            'flag': flag
        })

        # Filtrer : ne garder que les connexions des 2 dernières secondes
        recent = [c for c in ROLLING_WINDOW if now - c['time'] <= WINDOW_SECONDS]
        # Snapshot de la fenêtre globale pour les dst_host features
        all_window = list(ROLLING_WINDOW)

    if not recent:
        return {}

    # --- count : nb de connexions vers le même hôte dans la fenêtre ---
    same_host = [c for c in recent if c['dst_ip'] == dst_ip]
    count = len(same_host)

    # --- srv_count : nb de connexions vers le même service ---
    same_srv_all = [c for c in recent if c['service'] == service]
    srv_count = len(same_srv_all)

    # --- same_srv_rate : % du même service parmi les connexions au même hôte ---
    same_srv_same_host = sum(1 for c in same_host if c['service'] == service)
    same_srv_rate = same_srv_same_host / max(count, 1)
    diff_srv_rate = 1.0 - same_srv_rate

    # --- serror_rate : % d'erreurs SYN (connexions TCP échouées) ---
    syn_errors = ['S0', 'S1', 'S2', 'S3']
    serror_host = sum(1 for c in same_host if c['flag'] in syn_errors)
    serror_rate = serror_host / max(count, 1)

    serror_srv = sum(1 for c in same_srv_all if c['flag'] in syn_errors)
    srv_serror_rate = serror_srv / max(srv_count, 1)

    # --- rerror_rate : % de rejets ---
    rej_host = sum(1 for c in same_host if c['flag'] == 'REJ')
    rerror_rate = rej_host / max(count, 1)

    rej_srv = sum(1 for c in same_srv_all if c['flag'] == 'REJ')
    srv_rerror_rate = rej_srv / max(srv_count, 1)

    # --- dst_host features (sur la fenêtre globale complète, pas juste 2s) ---
    all_to_dst = [c for c in all_window if c['dst_ip'] == dst_ip]
    dst_host_count = min(len(all_to_dst), 255)
    dst_host_srv = sum(1 for c in all_to_dst if c['service'] == service)
    dst_host_srv_count = min(dst_host_srv, 255)
    dst_host_same_srv_rate = dst_host_srv / max(len(all_to_dst), 1)
    dst_host_diff_srv_rate = 1.0 - dst_host_same_srv_rate

    # srv_diff_host_rate : diversité des hôtes source vers le même service
    unique_src = len(set(c['src_ip'] for c in all_to_dst if c['service'] == service))
    srv_diff_host_rate = (unique_src - 1) / max(unique_src, 1) if unique_src > 1 else 0.0

    # dst_host_serror/rerror (sur fenêtre globale)
    dst_serror = sum(1 for c in all_to_dst if c['flag'] in syn_errors)
    dst_serror_rate = dst_serror / max(len(all_to_dst), 1)
    dst_rej = sum(1 for c in all_to_dst if c['flag'] == 'REJ')
    dst_rerror_rate = dst_rej / max(len(all_to_dst), 1)

    dst_srv_conns = [c for c in all_to_dst if c['service'] == service]
    dst_srv_serror = sum(1 for c in dst_srv_conns if c['flag'] in syn_errors)
    dst_srv_serror_rate = dst_srv_serror / max(len(dst_srv_conns), 1)
    dst_srv_rej = sum(1 for c in dst_srv_conns if c['flag'] == 'REJ')
    dst_srv_rerror_rate = dst_srv_rej / max(len(dst_srv_conns), 1)

    return {
        'count': float(count),
        'srv_count': float(srv_count),
        'same_srv_rate': round(same_srv_rate, 4),
        'diff_srv_rate': round(diff_srv_rate, 4),
        'serror_rate': round(serror_rate, 4),
        'srv_serror_rate': round(srv_serror_rate, 4),
        'rerror_rate': round(rerror_rate, 4),
        'srv_rerror_rate': round(srv_rerror_rate, 4),
        'srv_diff_host_rate': round(srv_diff_host_rate, 4),
        'dst_host_count': float(dst_host_count),
        'dst_host_srv_count': float(dst_host_srv_count),
        'dst_host_same_srv_rate': round(dst_host_same_srv_rate, 4),
        'dst_host_diff_srv_rate': round(dst_host_diff_srv_rate, 4),
        'dst_host_same_src_port_rate': 0.0,
        'dst_host_srv_diff_host_rate': round(srv_diff_host_rate, 4),
        'dst_host_serror_rate': round(dst_serror_rate, 4),
        'dst_host_srv_serror_rate': round(dst_srv_serror_rate, 4),
        'dst_host_rerror_rate': round(dst_rerror_rate, 4),
        'dst_host_srv_rerror_rate': round(dst_srv_rerror_rate, 4),
    }


# =====================================================================
# DATABASE
# =====================================================================
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


# =====================================================================
# NSL-KDD FEATURE COLUMNS
# =====================================================================
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
    """Géolocalisation via l'API publique ip-api.com."""
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") or ip == "127.0.0.1":
        return {"lat": 48.8566, "lon": 2.3522}  # Local = Paris

    try:
        # Appel API GeoIP
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {"lat": float(data["lat"]), "lon": float(data["lon"])}
    except Exception:
        pass

    # Fallback en cas de rate-limit ou d'échec
    cities = [
        {"lat": 40.7128, "lon": -74.0060},   # New York
        {"lat": 39.9042, "lon": 116.4074},   # Beijing
        {"lat": 55.7558, "lon": 37.6173},    # Moscow
        {"lat": 51.5074, "lon": -0.1278},    # London
        {"lat": 35.6762, "lon": 139.6503},   # Tokyo
        {"lat": -33.8688, "lon": 151.2093},  # Sydney
    ]
    return random.choice(cities)


# =====================================================================
# PACKET HANDLER — Capture et Analyse en Temps Réel
# =====================================================================
def packet_handler(pkt):
    if IP in pkt:
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        src_bytes = len(pkt)
        dst_bytes = 0

        protocol_type = "tcp"
        service = "other"
        flag = "SF"  # Par défaut : connexion réussie

        if TCP in pkt:
            protocol_type = "tcp"
            port = pkt[TCP].dport
            tcp_flags = pkt[TCP].flags

            # Détection intelligente du flag TCP pour les features statistiques
            if tcp_flags & 0x04:              # RST → connexion rejetée
                flag = "REJ"
            elif tcp_flags & 0x02 and not (tcp_flags & 0x10):  # SYN sans ACK
                flag = "S0"
            elif tcp_flags & 0x01:            # FIN → fermeture normale
                flag = "SF"
            else:
                flag = "SF"

            # Mapping port → service (enrichi)
            port_map = {
                80: "http", 443: "http", 8080: "http",
                21: "ftp", 20: "ftp_data",
                22: "ssh", 23: "telnet",
                25: "smtp", 110: "pop_3", 143: "imap4",
                53: "domain_u", 67: "other", 68: "other",
                3306: "other", 5432: "other", 3389: "other",
            }
            service = port_map.get(port, "other")

        elif UDP in pkt:
            protocol_type = "udp"
            flag = "SF"
            port = pkt[UDP].dport
            if port == 53:
                service = "domain_u"
            elif port == 67 or port == 68:
                service = "other"

        elif ICMP in pkt:
            protocol_type = "icmp"
            service = "eco_i"
            flag = "SF"
        else:
            return  # Ignorer les paquets non IP/TCP/UDP/ICMP

        # ===== ROLLING WINDOW : Calcul des features statistiques =====
        rolling = compute_rolling_features(src_ip, dst_ip, protocol_type, service, flag)

        # Construction du payload NSL-KDD enrichi
        event_data = {col: 0.0 for col in FEATURE_COLS}
        event_data['protocol_type'] = protocol_type
        event_data['service'] = service
        event_data['flag'] = flag
        event_data['src_bytes'] = float(src_bytes)
        event_data['dst_bytes'] = float(dst_bytes)

        # Injection des features calculées par le Rolling Window
        event_data.update(rolling)

        # Géolocalisation
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

                # Affichage console enrichi avec les features Rolling Window
                status = "🔴 BLOCKED" if pred_result.get("action_taken") == "Blocked at Firewall" else (
                    "🚨 ATTACK" if pred_result.get("prediction") == "ATTACK" else "✅ OK")
                rw_info = f"cnt={int(rolling.get('count', 0))} srv={int(rolling.get('srv_count', 0))} serr={rolling.get('serror_rate', 0):.2f}"
                print(f"[{status}] {src_ip} -> {dst_ip} [{protocol_type}/{service}] {src_bytes}B | RW:[{rw_info}]")
        except Exception as e:
            print(f"API unreachable: {e}")


# =====================================================================
# MAIN
# =====================================================================
if __name__ == "__main__":
    init_database()
    print("=" * 60)
    print("📡 CYBERSHIELD LIVE SNIFFER v2.0 — Rolling Window Engine")
    print("=" * 60)
    print("🧠 Features statistiques calculées en temps réel (count,")
    print("   srv_count, serror_rate, etc.) via fenêtre glissante 2s.")
    print("   Écoute du trafic réel. Ctrl+C pour arrêter.")
    print("=" * 60)

    try:
        sniff(prn=packet_handler, store=False, filter="ip")
    except KeyboardInterrupt:
        print("\nArrêt du sniffer.")
    except Exception as e:
        print(f"\nErreur de capture : {e}")
        print("Avez-vous installé Npcap (https://npcap.com/) sur Windows ?")
