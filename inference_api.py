import os
import sys
try:
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
except AttributeError:
    pass
import numpy as np
import pandas as pd
import joblib
import tensorflow as tf
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any
import subprocess

# Variables globales pour l'IPS
BLOCKED_IPS = set()

def block_ip_windows(ip: str):
    """Exécute la commande netsh pour bloquer l'IP dans le pare-feu Windows."""
    if ip == "127.0.0.1" or ip in BLOCKED_IPS:
        return
    try:
        # Création de la règle de blocage entrante
        cmd = f'netsh advfirewall firewall add rule name="CyberShield_Block_IP" dir=in action=block remoteip={ip}'
        subprocess.run(cmd, shell=True, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        BLOCKED_IPS.add(ip)
        print(f"🛡️ [IPS] Règle de pare-feu ajoutée : {ip} bloquée.")
    except Exception as e:
        print(f"⚠️ [IPS] Échec du blocage de {ip} (Mode Admin requis). Erreur: {e}")

# Initialisation de l'API FastAPI
app = FastAPI(
    title="Moteur d'Inférence SOC Intelligent",
    description="API de classification de trafic réseau en temps réel (Normal vs Attaque)",
    version="1.0.0"
)

# Configuration CORS pour permettre au Dashboard Streamlit de requêter l'API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Variables globales pour les modèles et encodeurs
MODELS = {}

# Configuration du logging TensorFlow
tf.get_logger().setLevel('ERROR')

@app.on_event("startup")
def load_models_and_scaler():
    """Charge tous les artefacts de modèles et de prétraitement au démarrage de l'API."""
    models_path = "models"
    required_files = [
        "scaler.pkl", "le_cat.pkl", "le_features.pkl", "feature_cols.pkl",
        "random_forest.pkl", "xgboost.pkl", "dnn_model.keras",
        "lstm_autoencoder.keras", "ae_threshold.npy"
    ]
    
    # Vérification de l'existence des fichiers
    missing_files = [f for f in required_files if not os.path.exists(os.path.join(models_path, f))]
    if missing_files:
        print(f"⚠️ Erreur au démarrage : Fichiers de modèles manquants : {missing_files}")
        print("Veuillez d'abord exécuter le script d'entraînement 'soc_nootbook.py'.")
        # Ne pas lever d'exception pour permettre le démarrage de l'API même si les modèles ne sont pas encore prêts,
        # mais marquer que les modèles ne sont pas chargés.
        return
        
    try:
        print("📥 Chargement des modèles et des encodeurs...")
        MODELS["scaler"] = joblib.load(os.path.join(models_path, "scaler.pkl"))
        MODELS["le_cat"] = joblib.load(os.path.join(models_path, "le_cat.pkl"))
        MODELS["le_features"] = joblib.load(os.path.join(models_path, "le_features.pkl"))
        MODELS["feature_cols"] = joblib.load(os.path.join(models_path, "feature_cols.pkl"))
        
        # Charger les modèles ML
        MODELS["rf"] = joblib.load(os.path.join(models_path, "random_forest.pkl"))
        MODELS["xgb"] = joblib.load(os.path.join(models_path, "xgboost.pkl"))
        
        # Initialiser SHAP Explainer pour le Random Forest
        import shap
        MODELS["explainer"] = shap.TreeExplainer(MODELS["rf"])
        
        # Charger les modèles DL
        MODELS["dnn"] = tf.keras.models.load_model(os.path.join(models_path, "dnn_model.keras"))
        MODELS["ae"] = tf.keras.models.load_model(os.path.join(models_path, "lstm_autoencoder.keras"))
        MODELS["ae_threshold"] = np.load(os.path.join(models_path, "ae_threshold.npy"))[0]
        
        print("✅ Tous les modèles ont été chargés avec succès !")
    except Exception as e:
        print(f"❌ Erreur lors du chargement des modèles : {str(e)}")


class NetworkEvent(BaseModel):
    # Dictionnaire flexible contenant les colonnes du paquet
    data: Dict[str, Any]
    # Champ optionnel pour la vérité terrain (étiquette réelle du dataset pour audit/SIEM)
    true_label: str = "unknown"
    # Données géographiques pour l'analyste IA
    geo_data: Dict[str, Any] = {}
    # Indicateur de simulation pour désactiver les notifications
    is_simulation: bool = False

@app.get("/health")
def health_check():
    """Vérifie l'état de l'API et si les modèles sont correctement chargés."""
    is_ready = all(k in MODELS for k in ["scaler", "rf", "xgb", "dnn", "ae"])
    return {
        "status": "healthy" if is_ready else "degraded",
        "models_loaded": is_ready,
        "loaded_components": list(MODELS.keys())
    }

# -------------------------------------------------------------
# Fonctions V3 : Copilote GenAI, MITRE ATT&CK, Threat Intel
# -------------------------------------------------------------
import random as _random

MITRE_MAPPING = {
    "dos": {
        "tactic": "TA0040 - Impact",
        "technique": "T1498 - Network Denial of Service",
        "severity": "CRITICAL",
        "description": "Attaque visant à saturer les ressources réseau ou applicatives pour rendre le service indisponible.",
        "countermeasure": "Activer le rate-limiting sur le WAF, bloquer l'IP source via iptables, et contacter l'ISP en amont pour un filtrage BGP."
    },
    "probe": {
        "tactic": "TA0043 - Reconnaissance",
        "technique": "T1595 - Active Scanning",
        "severity": "HIGH",
        "description": "Phase de reconnaissance : l'attaquant cartographie les ports et services ouverts pour identifier des vulnérabilités.",
        "countermeasure": "Désactiver les réponses ICMP, renforcer les règles de firewall, et déployer un honeypot pour traquer l'attaquant."
    },
    "r2l": {
        "tactic": "TA0001 - Initial Access",
        "technique": "T1190 - Exploit Public-Facing Application",
        "severity": "HIGH",
        "description": "Tentative d'accès non autorisé depuis un hôte distant exploitant une faille applicative ou un mot de passe faible.",
        "countermeasure": "Activer l'authentification multi-facteurs (MFA), auditer les comptes compromis, patcher immédiatement les CVE ouvertes."
    },
    "u2r": {
        "tactic": "TA0004 - Privilege Escalation",
        "technique": "T1068 - Exploitation for Privilege Escalation",
        "severity": "CRITICAL",
        "description": "Escalade de privilèges : un utilisateur local tente d'obtenir les droits root/administrateur via un exploit kernel.",
        "countermeasure": "Isoler immédiatement la machine compromise, vérifier les logs sudo/su, appliquer les patches kernel en urgence."
    },
    "normal": {
        "tactic": "N/A", "technique": "N/A", "severity": "INFO",
        "description": "Trafic légitime.", "countermeasure": "Aucune action requise."
    },
    "unknown": {
        "tactic": "TA0040 - Impact",
        "technique": "T1498 - Network Denial of Service",
        "severity": "MEDIUM",
        "description": "Comportement anormal non catégorisé. Analyse forensique recommandée.",
        "countermeasure": "Placer l'IP en quarantaine et déclencher une investigation manuelle."
    }
}

# Simulated Threat Intelligence Database
THREAT_INTEL_DB = {
    "104.244.42.1":  {"reputation": "Malicious", "country": "US", "org": "Twitter Inc.", "threat_type": "Botnet C2", "first_seen": "2024-03-15"},
    "185.60.216.35": {"reputation": "Suspicious", "country": "GB", "org": "Facebook Ireland", "threat_type": "Phishing Relay", "first_seen": "2024-07-22"},
    "220.181.38.148": {"reputation": "Malicious", "country": "CN", "org": "Beijing Baidu", "threat_type": "APT Group (Volt Typhoon)", "first_seen": "2023-11-01"},
    "178.23.11.90":  {"reputation": "Malicious", "country": "RU", "org": "Moscow Datacenter", "threat_type": "Ransomware Operator", "first_seen": "2024-01-10"},
    "45.12.33.11":   {"reputation": "Suspicious", "country": "BR", "org": "Sao Paulo Hosting", "threat_type": "Cryptominer", "first_seen": "2024-09-05"},
    "8.8.8.8":       {"reputation": "Clean", "country": "US", "org": "Google LLC", "threat_type": "N/A", "first_seen": "N/A"},
}

def get_attack_family(true_label: str) -> str:
    """Mappe les labels NSL-KDD aux familles d'attaque MITRE."""
    label = true_label.lower()
    if label == "normal": return "normal"
    if label in ["neptune", "smurf", "pod", "teardrop", "land", "back", "apache2", "udpstorm", "processtable", "mailbomb"]: return "dos"
    if label in ["ipsweep", "portsweep", "nmap", "satan", "saint", "mscan"]: return "probe"
    if label in ["ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient", "warezmaster", "snmpgetattack", "snmpguess", "httptunnel", "named", "sendmail", "xlock", "xsnoop"]: return "r2l"
    if label in ["buffer_overflow", "loadmodule", "perl", "rootkit", "ps", "sqlattack", "xterm"]: return "u2r"
    return "unknown"

def get_threat_intel(src_ip: str) -> dict:
    """Interroge la base de Threat Intelligence simulée."""
    return THREAT_INTEL_DB.get(src_ip, {"reputation": "Unknown", "country": "??", "org": "Unknown", "threat_type": "Unclassified", "first_seen": "N/A"})

def generate_ai_report(prediction: str, confidence: float, top_shap: dict, geo: dict, true_label: str, protocol: str, service: str, action_taken: str = "Alert Only") -> str:
    """Génère un rapport contextuel riche simulant un LLM Analyste SOC."""
    if prediction == "NORMAL":
        return "Le trafic réseau analysé est bénin. Les comportements correspondent à une utilisation standard des services."
    
    family = get_attack_family(true_label)
    mitre = MITRE_MAPPING.get(family, MITRE_MAPPING["unknown"])
    src_ip = geo.get("src_ip", "Inconnue")
    intel = get_threat_intel(src_ip)
    
    # Extraire les features principales
    top_features_list = list(top_shap.keys())
    primary = top_features_list[0] if len(top_features_list) > 0 else "inconnue"
    secondary = top_features_list[1] if len(top_features_list) > 1 else "inconnue"
    
    report = f"--- RAPPORT D'INCIDENT SOC ---\n"
    report += f"Sévérité : {mitre['severity']} | Famille : {family.upper()}\n\n"
    report += f"ANALYSE :\n"
    report += f"{mitre['description']}\n"
    report += f"L'attaque provient de {src_ip} ({intel['country']}, {intel['org']}) et cible le service {service}/{protocol}. "
    report += f"Certitude du modèle : {confidence*100:.1f}%.\n\n"
    report += f"EXPLICABILITE (XAI) :\n"
    report += f"Les variables `{primary}` et `{secondary}` sont les marqueurs principaux de cette intrusion selon l'analyse SHAP.\n\n"
    report += f"THREAT INTELLIGENCE :\n"
    report += f"Reputation IP : {intel['reputation']} | Type de menace : {intel['threat_type']} | Premiere observation : {intel['first_seen']}\n\n"
    report += f"MITIGATION (IPS) :\n"
    if action_taken == "Blocked at Firewall":
        report += f"🚨 DECISION AUTONOME : Sévérité critique atteinte. L'adresse IP {src_ip} a été bloquée au niveau du pare-feu Windows.\n\n"
    else:
        report += f"L'alerte a été consignée. Aucune action bloquante automatique entreprise.\n\n"
    report += f"RECOMMANDATION :\n"
    report += f"{mitre['countermeasure']}\n"
    report += f"Ref. MITRE ATT&CK : {mitre['tactic']} / {mitre['technique']}"
    
    return report

@app.post("/predict")
def predict(event: NetworkEvent):
    """
    Reçoit un événement réseau brut, effectue le prétraitement,
    calcule la prédiction avec chaque modèle et retourne le résultat de l'ensemble.
    """
    # Vérification que les modèles sont chargés
    if not MODELS:
        raise HTTPException(status_code=503, detail="Les modèles ne sont pas encore chargés sur l'API.")

    try:
        # 1. Convertir les données en DataFrame pour correspondre au format d'entraînement
        df = pd.DataFrame([event.data])
        
        # Vérifier que toutes les colonnes requises sont présentes
        feature_cols = MODELS["feature_cols"]
        missing_cols = [col for col in feature_cols if col not in df.columns]
        if missing_cols:
            raise HTTPException(
                status_code=400, 
                detail=f"Colonnes manquantes dans l'événement réseau : {missing_cols}"
            )
            
        # Ordonner les colonnes exactement comme à l'entraînement
        df = df[feature_cols]
        
        # 2. Encodage des features catégorielles
        le_features = MODELS["le_features"]
        for feat, le in le_features.items():
            val = df[feat].values[0]
            # Gestion des catégories inconnues (fallback sur la première classe si inconnu)
            if val not in le.classes_:
                df[feat] = le.transform([le.classes_[0]])[0]
            else:
                df[feat] = le.transform([val])[0]
                
        # 3. Normalisation (StandardScaler)
        X_raw = df.values.astype(float)
        X_scaled = MODELS["scaler"].transform(X_raw)
        
        # 4. Inférence des modèles
        # Random Forest
        p_rf = float(MODELS["rf"].predict_proba(X_scaled)[0, 1])
        
        # XGBoost
        p_xgb = float(MODELS["xgb"].predict_proba(X_scaled)[0, 1])
        
        # DNN (Deep Neural Network)
        p_dnn = float(MODELS["dnn"].predict(X_scaled, verbose=0).ravel()[0])
        
        # LSTM Autoencoder (détection d'anomalies)
        # Reshape : (1, 1, n_features)
        X_lstm = X_scaled.reshape(1, 1, -1)
        recon = MODELS["ae"].predict(X_lstm, verbose=0)
        error = float(np.mean(np.power(X_lstm - recon, 2)))
        
        # Normalisation du score de reconstruction par rapport au seuil
        threshold = MODELS["ae_threshold"]
        p_ae = min(error / (threshold + 1e-9), 1.0)
        
        # 5. Vote pondéré (Ensemble)
        # Pondération : RF(35%) + XGB(35%) + DNN(20%) + LSTM-AE(10%)
        score = 0.35 * p_rf + 0.35 * p_xgb + 0.20 * p_dnn + 0.10 * p_ae
        
        is_attack = score > 0.50
        prediction_label = "ATTACK" if is_attack else "NORMAL"
        confidence = score if is_attack else (1.0 - score)
        
        # 6. Explicabilité (SHAP)
        # On calcule les valeurs SHAP pour le Random Forest (très rapide via TreeExplainer)
        shap_values = MODELS["explainer"].shap_values(X_scaled)
        # shap_values pour RandomForest retourne une liste de arrays (un par classe) ou un array (n_samples, n_features, n_classes).
        # On extrait l'importance pour la classe 1 (Attaque)
        if isinstance(shap_values, list):
            sv = shap_values[1][0] # shap_values pour la classe 1, 1er échantillon
        else:
            if len(shap_values.shape) == 3:
                sv = shap_values[0, :, 1]
            else:
                sv = shap_values[0]

        # Associer les valeurs SHAP aux noms de features
        feature_impacts = {feat: float(val) for feat, val in zip(MODELS["feature_cols"], sv)}
        # Trier par impact absolu décroissant
        sorted_impacts = sorted(feature_impacts.items(), key=lambda x: abs(x[1]), reverse=True)
        top_shap = dict(sorted_impacts[:5]) # Garder le Top 5 des features les plus influentes
        
        # Détails des scores pour le SIEM
        detail_scores = {
            "Random_Forest": round(p_rf, 4),
            "XGBoost": round(p_xgb, 4),
            "DNN": round(p_dnn, 4),
            "LSTM_Autoencoder_Error": round(error, 6),
            "LSTM_Autoencoder_Score": round(p_ae, 4),
            "threshold": round(threshold, 6)
        }
        
        # 7. Copilote GenAI, Mapping MITRE, et Action IPS
        family = get_attack_family(event.true_label)
        mitre_info = MITRE_MAPPING.get(family, MITRE_MAPPING["unknown"]) if prediction_label == "ATTACK" else MITRE_MAPPING["normal"]
        intel = get_threat_intel(event.geo_data.get("src_ip", "")) if prediction_label == "ATTACK" else {}
        
        action_taken = "Alert Only"
        if prediction_label == "ATTACK" and mitre_info.get("severity") in ["CRITICAL", "HIGH"]:
            src_ip = event.geo_data.get("src_ip", "")
            if src_ip:
                block_ip_windows(src_ip)
                action_taken = "Blocked at Firewall"
                
                # Déclenchement de la notification Windows (Pop-up) uniquement si ce n'est pas une simulation
                if not event.is_simulation:
                    try:
                        from plyer import notification
                        notification.notify(
                            title="🚨 CyberShield IPS",
                            message=f"Attaque {mitre_info.get('severity')} bloquée !\nIP source : {src_ip}\nTactique : {mitre_info.get('tactic')}",
                            app_name="CyberShield",
                            timeout=5
                        )
                    except Exception as e:
                        print(f"⚠️ Erreur notification Windows : {e}")
        
        ai_report_text = generate_ai_report(
            prediction=prediction_label,
            confidence=confidence,
            top_shap=top_shap,
            geo=event.geo_data,
            true_label=event.true_label,
            protocol=event.data.get("protocol_type", "inconnu"),
            service=event.data.get("service", "inconnu"),
            action_taken=action_taken
        )
        
        return {
            "prediction": prediction_label,
            "confidence": round(confidence, 4),
            "ensemble_score": round(score, 4),
            "true_label": event.true_label,
            "details": detail_scores,
            "top_shap_features": top_shap,
            "ai_report": ai_report_text,
            "mitre": mitre_info,
            "threat_intel": intel,
            "action_taken": action_taken
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur d'inférence : {str(e)}")

if __name__ == "__main__":
    import uvicorn
    # Lancer l'API en local sur le port 8000
    uvicorn.run("inference_api:app", host="127.0.0.1", port=8000, reload=False)
