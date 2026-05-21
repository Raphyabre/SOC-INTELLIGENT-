# honeypot.py
import socket
import threading
import sqlite3
import datetime
import subprocess
import requests
import json
import time
import os

DB_FILE = "soc_events.db"
FTP_PORT = 21

def block_ip(ip):
    try:
        rule_name = f"SOC_HONEYPOT_BLOCK_{ip}"
        cmd = f"netsh advfirewall firewall add rule name=\"{rule_name}\" dir=in action=block remoteip={ip}"
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except Exception:
        return False

def resolve_geo(ip: str) -> dict:
    if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172.") or ip == "127.0.0.1":
        return {"lat": 48.8566, "lon": 2.3522}
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=2)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return {"lat": float(data["lat"]), "lon": float(data["lon"])}
    except Exception:
        pass
    return {"lat": 40.7128, "lon": -74.0060}

def handle_connection(client_socket, address):
    ip = address[0]
    print(f"\\n🍯 [HONEYPOT] 🚨 ALERTE CRITIQUE : Connexion FTP non autorisée depuis {ip} !")
    
    # Send fake FTP banner
    try:
        client_socket.send(b"220 CyberShield FTP Server Ready.\\r\\n")
        client_socket.recv(1024)
    except:
        pass
    client_socket.close()

    # Bloquer IP
    print(f"🛡️  [HONEYPOT] Blocage immédiat de l'IP {ip} via Windows Firewall...")
    block_ip(ip)

    # Enregistrer dans la base
    geo_data = resolve_geo(ip)
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO events (
                timestamp, src_ip, src_lat, src_lon, dst_ip, dst_lat, dst_lon,
                protocol_type, service, src_bytes, dst_bytes,
                true_label, prediction, confidence, ensemble_score, shap_json,
                mitre_tactic, mitre_technique, ai_report
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp,
            ip, geo_data["lat"], geo_data["lon"],
            "127.0.0.1", 48.8566, 2.3522,
            "tcp", "ftp", 0, 0,
            "attack", "ATTACK", 1.0, 1.0, "{}",
            "Initial Access", "T1190 - Exploit Public-Facing App",
            "🚨 DÉCISION AUTONOME : Adresse IP bloquée par le pare-feu. Motif : Intrusion Honeypot FTP."
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[HONEYPOT] Erreur BDD: {e}")

def start_honeypot():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("0.0.0.0", FTP_PORT))
        server.listen(5)
        print("=" * 60)
        print(f"🍯 CYBERSHIELD HONEYPOT v1.0")
        print("=" * 60)
        print(f"✅ Écoute active sur le port {FTP_PORT} (FTP)...")
        print(f"Piège tendu. Toute tentative de connexion entraînera un ban.")
        print("=" * 60)
        
        while True:
            try:
                client, addr = server.accept()
                client_thread = threading.Thread(target=handle_connection, args=(client, addr))
                client_thread.start()
            except KeyboardInterrupt:
                break
            except Exception as e:
                pass
    except Exception as e:
        print(f"Impossible de lancer le Honeypot sur le port {FTP_PORT}. Est-il déjà utilisé ?\\nErreur : {e}")
        time.sleep(5)
            
if __name__ == "__main__":
    start_honeypot()
