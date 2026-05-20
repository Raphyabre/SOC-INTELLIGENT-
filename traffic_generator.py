import os
import sys
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except AttributeError:
    pass
import time
import random
import sqlite3
from datetime import datetime
import pandas as pd
import requests

# Constantes
API_URL = "http://127.0.0.1:8000/predict"
TEST_URL = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTest+.txt"
LOCAL_TEST_FILE = "KDDTest+.txt"
DB_FILE = "soc_events.db"

COLUMNS = [
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
    'dst_host_srv_rerror_rate', 'label', 'difficulty_level'
]

# Colonnes de features à envoyer à l'API (excluant label et difficulty_level)
FEATURE_COLS = COLUMNS[:-2]

def init_database():
    """Initialise la base de données SQLite pour stocker les alertes et événements."""
    # En mode démo, on recrée la table pour avoir le bon schéma (V2)
    if os.path.exists(DB_FILE):
        try:
            os.remove(DB_FILE)
        except:
            pass
            
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
    print(f"📁 Base de données SQLite V2 initialisée : '{DB_FILE}'")

def download_test_set():
    """Télécharge le fichier KDDTest+.txt s'il n'est pas présent localement."""
    if not os.path.exists(LOCAL_TEST_FILE):
        print(f"📥 Fichier '{LOCAL_TEST_FILE}' non trouvé. Téléchargement depuis GitHub...")
        try:
            r = requests.get(TEST_URL)
            with open(LOCAL_TEST_FILE, 'wb') as f:
                f.write(r.content)
            print("✅ Téléchargement réussi !")
        except Exception as e:
            print(f"❌ Erreur lors du téléchargement du dataset : {e}")
            raise e
    else:
        print(f"✅ Fichier '{LOCAL_TEST_FILE}' présent localement.")

def save_event_to_db(timestamp, raw_data, pred_result, geo_data):
    """Enregistre le paquet réseau, la prédiction et la géolocalisation dans SQLite."""
    import json
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
        print(f"⚠️ Erreur d'écriture dans SQLite : {e}")

def run_simulation(interval=0.5):
    """Simule un flux réseau en envoyant des requêtes à l'API."""
    init_database()
    download_test_set()
    
    print("📖 Chargement des données de simulation...")
    df = pd.read_csv(LOCAL_TEST_FILE, header=None, names=COLUMNS)
    
    # Mélanger les données pour simuler un vrai trafic
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    
    print(f"\n📡 Lancement du Générateur de Trafic Réseau...")
    print(f"🔗 Envoi vers : {API_URL}")
    print(f"⏱️ Intervalle : {interval} seconde(s) par paquet")
    print(f"Appuyez sur Ctrl+C pour arrêter.\n")
    print("-" * 90)
    print(f"{'Horodatage':<19} | {'Proto':<5} | {'Service':<10} | {'Vraie Cible':<10} | {'Prédiction':<10} | {'Conf':<6} | {'Status'}")
    print("-" * 90)
    
    idx = 0
    
    # Géolocalisations fictives d'attaquants mondiaux
    GEO_ATTACKERS = [
        {"ip": "104.244.42.1", "lat": 40.7128, "lon": -74.0060}, # NY
        {"ip": "185.60.216.35", "lat": 51.5074, "lon": -0.1278}, # London
        {"ip": "220.181.38.148", "lat": 39.9042, "lon": 116.4074}, # Beijing
        {"ip": "178.23.11.90", "lat": 55.7558, "lon": 37.6173}, # Moscow
        {"ip": "45.12.33.11", "lat": -23.5505, "lon": -46.6333}, # Sao Paulo
        {"ip": "8.8.8.8", "lat": 37.3861, "lon": -122.0839}, # Mountain View
    ]
    SOC_SERVER = {"ip": "192.168.1.100", "lat": 48.8566, "lon": 2.3522} # Paris SOC

    while True:
        try:
            # Récupérer une ligne
            row = df.iloc[idx % len(df)]
            idx += 1
            
            # Extraire les features
            row_dict = row.to_dict()
            feature_data = {col: row_dict[col] for col in FEATURE_COLS}
            
            # Geo Data Fictive
            attacker = random.choice(GEO_ATTACKERS)
            geo_data = {
                "src_ip": attacker["ip"],
                "src_lat": attacker["lat"] + random.uniform(-1.0, 1.0),
                "src_lon": attacker["lon"] + random.uniform(-1.0, 1.0),
                "dst_ip": SOC_SERVER["ip"],
                "dst_lat": SOC_SERVER["lat"],
                "dst_lon": SOC_SERVER["lon"]
            }
            
            # Préparer le payload
            payload = {
                "data": feature_data,
                "true_label": str(row_dict["label"]),
                "geo_data": geo_data
            }
            
            # Envoyer à l'API FastAPI
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                response = requests.post(API_URL, json=payload, timeout=2)
                if response.status_code == 200:
                    res = response.json()
                    pred = res["prediction"]
                    conf = res["confidence"]
                    true_lbl = res["true_label"]
                    
                    # Indicateur visuel du statut
                    if pred == "ATTACK":
                        status_str = "🚨 ATTACK DETECTED"
                    else:
                        status_str = "✅ NORMAL"
                        
                    print(f"{ts} | {feature_data['protocol_type']:<5} | {feature_data['service']:<10} | {true_lbl[:10]:<10} | {pred:<10} | {conf:.2f} | {status_str}")
                    
                    # Sauvegarder dans SQLite (avec Geo Data)
                    save_event_to_db(ts, feature_data, res, geo_data)
                else:
                    print(f"⚠️ Erreur API ({response.status_code}): {response.text}")
            except requests.exceptions.ConnectionError:
                print(f"❌ Impossible de se connecter à l'API FastAPI sur {API_URL}. Est-elle en cours d'exécution ?")
            except Exception as e:
                print(f"⚠️ Erreur requête : {e}")
                
            # Attendre l'intervalle spécifié
            time.sleep(interval)
            
        except KeyboardInterrupt:
            print("\n🛑 Simulation arrêtée par l'utilisateur.")
            break
        except Exception as e:
            print(f"❌ Erreur critique dans la boucle de simulation : {e}")
            time.sleep(2)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Simulateur de trafic réseau SOC")
    parser.add_argument("--interval", type=float, default=0.5, help="Intervalle d'envoi en secondes (default: 0.5)")
    args = parser.parse_args()
    
    run_simulation(interval=args.interval)
