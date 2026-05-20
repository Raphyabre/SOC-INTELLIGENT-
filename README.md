# 🛡️ CyberShield SOC (V3 Ultimate)
**AI-Powered Security Operations Center & Intrusion Prevention System (IPS)**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-00a393)
![Streamlit](https://img.shields.io/badge/Streamlit-1.25%2B-FF4B4B)
![Machine Learning](https://img.shields.io/badge/AI-Ensemble_Learning-8A2BE2)
![Status](https://img.shields.io/badge/Status-Production_Ready-success)

CyberShield est un Centre Opérationnel de Sécurité (SOC) intelligent de bout en bout. Il remplace les règles statiques traditionnelles par une architecture **Ensemble Learning** combinant Machine Learning classique et Deep Learning (Autoencodeurs) pour détecter, expliquer, et bloquer les cyberattaques en temps réel.

---

## ✨ Fonctionnalités Principales

- 🧠 **Détection par Ensemble Learning** : Vote pondéré entre 4 algorithmes (Random Forest, XGBoost, DNN, LSTM-Autoencoder) assurant une très haute précision sur le dataset NSL-KDD.
- 🕵️‍♂️ **Intelligence Explicable (XAI)** : Intégration de SHAP pour justifier mathématiquement chaque décision de l'IA (transparence des modèles).
- 🤖 **Copilote GenAI Analyste** : Un LLM simulé rédige un rapport forensique détaillé pour chaque alerte, classifiant la menace selon le framework **MITRE ATT&CK**.
- ⚔️ **Mitigation Active (Mode IPS)** : L'IA ne fait pas qu'alerter ; si la menace est "CRITICAL", le système exécute une commande système pour bloquer l'IP via le Pare-feu Windows de façon autonome.
- 🔌 **Double Capteur Réseau** :
  - *Mode Simulation* : Injecte des vagues d'attaques massives.
  - *Mode Live Sniffer* : Utilise Scapy pour analyser votre **véritable trafic réseau local** en temps réel.
- 📊 **Dashboard Next-Gen** : Interface de classe Enterprise avec Threat Map 3D dynamique (Streamlit + Plotly).

---

## 🛠️ Architecture du Système

```mermaid
graph TD;
    A[Trafic Réseau] -->|Live Sniffer (Scapy)| B(API FastAPI);
    S[Simulateur NSL-KDD] -->|Trafic Mocké| B;
    B --> C{Ensemble ML/DL};
    C -->|Prédiction & SHAP| D[Générateur Rapport GenAI];
    D -->|MITRE & Threat Intel| E[(Base de Données SQLite)];
    E --> F[Dashboard Streamlit];
    C -->|Si CRITICAL| G[Pare-Feu Windows (IPS)];
```

---

## 🚀 Installation

### Prérequis
1. **Python 3.8+**
2. (Windows uniquement) **Npcap** : Nécessaire pour l'écoute du trafic en direct. À télécharger sur [npcap.com](https://npcap.com/#download) (Cochez "Install Npcap in WinPcap API-compatible Mode"). *Si vous avez Wireshark, c'est déjà installé.*

### Déploiement
1. Clonez ce dépôt :
   ```bash
   git clone https://github.com/votre-nom/CyberShield-SOC.git
   cd CyberShield-SOC
   ```
2. Créez un environnement virtuel et installez les dépendances :
   ```bash
   python -m venv .venv
   .venv\Scripts\activate
   pip install -r requirements.txt
   ```

---

## 🖥️ Utilisation

Pour lancer le SOC complet (API + Dashboard), exécutez le script d'orchestration **en tant qu'Administrateur** (requis pour la mitigation active IPS) :

Double-cliquez sur : `run_soc.bat` (Cilc Droit -> Exécuter en tant qu'administrateur).

### Contrôle de la Sonde
Une fois le Dashboard ouvert dans votre navigateur :
- Allez dans le panneau latéral de gauche.
- Cliquez sur **🔴 Lancer Simu** pour lancer une vague d'attaque synthétique (idéal pour les démos).
- Cliquez sur **🔵 Lancer Live** pour brancher l'IA sur votre propre carte réseau et analyser vos connexions web en direct !

---

## 🧹 Nettoyage 
L'IA bloquant activement les IP malveillantes dans votre pare-feu, vous pouvez remettre votre système à zéro à tout moment :
1. Faites un clic droit sur `clean_firewall.bat`
2. **Exécuter en tant qu'administrateur**

---
*Projet de fin d'études - Intelligence Artificielle appliquée à la Cybersécurité.*
