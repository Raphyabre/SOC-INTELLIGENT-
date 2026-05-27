import os
import sys
import time
import sqlite3
import json
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import pydeck as pdk
import subprocess
import psutil
from fpdf import FPDF
from datetime import datetime

# Fix Windows encoding
sys.stdout.reconfigure(encoding='utf-8')

# Configuration de la page Streamlit
st.set_page_config(
    page_title="CyberShield SOC | Next-Gen SIEM",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Constantes
DB_FILE = "soc_events.db"
RESULTS_FILE = "models/results.json"

# =====================================================================
# CSS PREMIUM — Design Cyber-SOC Classe Entreprise
# =====================================================================
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap');
    
    /* === GLOBAL THEME === */
    .stApp {
        background: linear-gradient(135deg, #0a0e17 0%, #0d1321 50%, #0a0e17 100%);
        color: #e6edf3;
        font-family: 'Inter', -apple-system, sans-serif;
    }
    
    /* === HEADER === */
    .soc-header {
        text-align: center;
        padding: 1.5rem 0;
        margin-bottom: 1rem;
        background: linear-gradient(135deg, rgba(88,166,255,0.08) 0%, rgba(188,140,255,0.08) 100%);
        border: 1px solid rgba(88,166,255,0.15);
        border-radius: 16px;
        position: relative;
        overflow: hidden;
    }
    .soc-header::before {
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent, #58a6ff, #bc8cff, #58a6ff, transparent);
        animation: headerGlow 3s ease-in-out infinite;
    }
    @keyframes headerGlow {
        0%, 100% { opacity: 0.5; }
        50% { opacity: 1; }
    }
    .soc-header h1 {
        font-family: 'Inter', sans-serif !important;
        font-size: 1.8rem !important;
        font-weight: 800 !important;
        background: linear-gradient(135deg, #58a6ff, #bc8cff, #f0883e);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        letter-spacing: -0.5px;
        margin: 0 !important;
    }
    .soc-header .subtitle {
        color: #8b949e;
        font-size: 0.85rem;
        font-weight: 400;
        margin-top: 0.3rem;
        font-family: 'JetBrains Mono', monospace;
    }
    .soc-header .status-dot {
        display: inline-block;
        width: 8px; height: 8px;
        border-radius: 50%;
        background: #3fb950;
        box-shadow: 0 0 8px #3fb950;
        animation: blink 2s infinite;
        margin-right: 6px;
    }
    @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }
    
    /* === HEADERS === */
    h1, h2, h3 {
        font-family: 'Inter', sans-serif !important;
        font-weight: 700 !important;
    }
    h2 { color: #58a6ff !important; font-size: 1.2rem !important; }
    h3 { color: #8b949e !important; font-size: 1rem !important; }
    
    /* === KPI CARDS === */
    .kpi-grid {
        display: grid;
        grid-template-columns: repeat(5, 1fr);
        gap: 0.8rem;
        margin-bottom: 1.5rem;
    }
    .kpi-card {
        background: linear-gradient(145deg, #161b22, #1c2333);
        border: 1px solid #21262d;
        border-radius: 12px;
        padding: 1.2rem;
        text-align: center;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        overflow: hidden;
    }
    .kpi-card::after {
        content: '';
        position: absolute;
        bottom: 0; left: 0; right: 0;
        height: 3px;
        border-radius: 0 0 12px 12px;
    }
    .kpi-card:hover {
        transform: translateY(-3px);
        box-shadow: 0 8px 25px rgba(0,0,0,0.4);
    }
    .kpi-card .kpi-label {
        font-size: 0.7rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 0.4rem;
    }
    .kpi-card .kpi-value {
        font-size: 2rem;
        font-weight: 800;
        font-family: 'JetBrains Mono', monospace;
        line-height: 1;
    }
    .kpi-blue .kpi-label { color: #58a6ff; }
    .kpi-blue .kpi-value { color: #58a6ff; }
    .kpi-blue::after { background: linear-gradient(90deg, #58a6ff, transparent); }
    .kpi-green .kpi-label { color: #3fb950; }
    .kpi-green .kpi-value { color: #3fb950; text-shadow: 0 0 20px rgba(63,185,80,0.3); }
    .kpi-green::after { background: linear-gradient(90deg, #3fb950, transparent); }
    .kpi-red .kpi-label { color: #f85149; }
    .kpi-red .kpi-value { color: #f85149; text-shadow: 0 0 20px rgba(248,81,73,0.3); }
    .kpi-red::after { background: linear-gradient(90deg, #f85149, transparent); }
    .kpi-yellow .kpi-label { color: #d29922; }
    .kpi-yellow .kpi-value { color: #d29922; }
    .kpi-yellow::after { background: linear-gradient(90deg, #d29922, transparent); }
    .kpi-purple .kpi-label { color: #bc8cff; }
    .kpi-purple .kpi-value { color: #bc8cff; }
    .kpi-purple::after { background: linear-gradient(90deg, #bc8cff, transparent); }
    
    /* === SEVERITY BADGES === */
    .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.65rem; font-weight: 700; font-family: 'JetBrains Mono', monospace; letter-spacing: 0.5px; }
    .badge-critical { background: rgba(248,81,73,0.2); color: #f85149; border: 1px solid rgba(248,81,73,0.4); }
    .badge-high { background: rgba(210,153,34,0.2); color: #d29922; border: 1px solid rgba(210,153,34,0.4); }
    .badge-medium { background: rgba(88,166,255,0.2); color: #58a6ff; border: 1px solid rgba(88,166,255,0.4); }
    .badge-info { background: rgba(63,185,80,0.15); color: #3fb950; border: 1px solid rgba(63,185,80,0.3); }
    .badge-mitre { background: rgba(188,140,255,0.15); color: #bc8cff; border: 1px solid rgba(188,140,255,0.3); }
    
    /* === ALERT ROWS === */
    .alert-row {
        background: linear-gradient(135deg, #161b22, #1c2333);
        border: 1px solid #21262d;
        border-radius: 8px;
        padding: 0.8rem 1rem;
        margin-bottom: 0.5rem;
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.78rem;
        transition: all 0.2s;
    }
    .alert-row:hover { border-color: #30363d; }
    .alert-danger {
        border-left: 4px solid #f85149;
        background: linear-gradient(135deg, rgba(248,81,73,0.06), #161b22);
    }
    .alert-success {
        border-left: 4px solid #3fb950;
        background: linear-gradient(135deg, rgba(63,185,80,0.04), #161b22);
    }
    .alert-critical {
        border-left: 4px solid #f85149;
        background: linear-gradient(135deg, rgba(248,81,73,0.1), #161b22);
        animation: criticalPulse 2s infinite;
    }
    @keyframes criticalPulse {
        0% { box-shadow: 0 0 0 0 rgba(248,81,73,0.3); }
        70% { box-shadow: 0 0 0 6px rgba(248,81,73,0); }
        100% { box-shadow: 0 0 0 0 rgba(248,81,73,0); }
    }
    
    /* === AI REPORT === */
    .ai-report {
        background: linear-gradient(135deg, rgba(188,140,255,0.08), rgba(88,166,255,0.05));
        border: 1px solid rgba(188,140,255,0.2);
        border-radius: 12px;
        padding: 1.2rem;
        font-family: 'Inter', sans-serif;
        font-size: 0.85rem;
        line-height: 1.6;
        color: #c9d1d9;
        white-space: pre-wrap;
    }
    .ai-report-header {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.7rem;
        color: #bc8cff;
        letter-spacing: 1px;
        text-transform: uppercase;
        margin-bottom: 0.8rem;
        display: flex;
        align-items: center;
        gap: 8px;
    }
    
    /* === THREAT INTEL CARD === */
    .intel-card {
        background: linear-gradient(135deg, #161b22, #1c2333);
        border: 1px solid #21262d;
        border-radius: 10px;
        padding: 1rem;
        margin-top: 0.5rem;
    }
    .intel-card .intel-header {
        font-size: 0.7rem;
        color: #d29922;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 1px;
        margin-bottom: 0.5rem;
        font-family: 'JetBrains Mono', monospace;
    }
    .intel-row {
        display: flex;
        justify-content: space-between;
        padding: 0.3rem 0;
        border-bottom: 1px solid #21262d;
        font-size: 0.8rem;
    }
    .intel-row:last-child { border-bottom: none; }
    .intel-label { color: #8b949e; }
    .intel-value { color: #e6edf3; font-weight: 600; font-family: 'JetBrains Mono', monospace; }
    .rep-malicious { color: #f85149; }
    .rep-suspicious { color: #d29922; }
    .rep-clean { color: #3fb950; }
    
    /* === MITRE TABLE === */
    .mitre-cell {
        background: #161b22;
        border: 1px solid #21262d;
        border-radius: 8px;
        padding: 0.6rem;
        text-align: center;
        font-size: 0.75rem;
        transition: all 0.2s;
    }
    .mitre-cell:hover { border-color: #58a6ff; }
    .mitre-active {
        background: rgba(248,81,73,0.15);
        border-color: #f85149;
        box-shadow: 0 0 10px rgba(248,81,73,0.2);
    }
    .mitre-tactic-header {
        font-family: 'JetBrains Mono', monospace;
        font-size: 0.65rem;
        font-weight: 700;
        color: #bc8cff;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    /* === MISC === */
    .section-divider {
        height: 1px;
        background: linear-gradient(90deg, transparent, #21262d, transparent);
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# =====================================================================
# DATA LAYER
# =====================================================================
def get_live_stats(mode="all"):
    """Récupère les statistiques agrégées depuis SQLite en fonction du mode (Simulation vs Live)."""
    if not os.path.exists(DB_FILE):
        return pd.DataFrame(), 0, 0, 0.0, pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query("SELECT * FROM events ORDER BY id DESC", conn)
        conn.close()
        if df.empty:
            return pd.DataFrame(), 0, 0, 0.0, pd.DataFrame()
            
        # Filtrage intelligent selon l'origine des données
        if mode == "sim":
            # NSL-KDD a des vrais labels comme 'normal', 'neptune', etc.
            df = df[~df['true_label'].isin(['unknown', 'attack'])]
        elif mode == "live":
            # Le Live Sniffer utilise 'unknown', le Honeypot utilise 'attack'
            df = df[df['true_label'].isin(['unknown', 'attack'])]
            
        if df.empty:
            return pd.DataFrame(), 0, 0, 0.0, pd.DataFrame()
            
        total = len(df)
        attacks = len(df[df["prediction"] == "ATTACK"])
        attack_rate = (attacks / total) * 100 if total > 0 else 0.0
        recent_df = df.head(50).copy()
        return df, total, attacks, attack_rate, recent_df
    except Exception as e:
        if "no such column" in str(e).lower():
            os.remove(DB_FILE)
        return pd.DataFrame(), 0, 0, 0.0, pd.DataFrame()

# =====================================================================
# PDF REPORT GENERATOR (Option 3)
# =====================================================================
def generate_pdf_report(df, total, attacks):
    if df.empty:
        return None
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", 'B', 16)
        pdf.cell(0, 10, "Rapport d'Incident SOC - CyberShield", new_x="LMARGIN", new_y="NEXT", align='C')
        
        pdf.set_font("helvetica", '', 12)
        pdf.cell(0, 10, f"Date d'export : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT", align='C')
        pdf.ln(10)
        
        pdf.set_font("helvetica", 'B', 12)
        pdf.cell(0, 10, "Resume Global des Alertes :", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", '', 11)
        pdf.cell(0, 8, f"- Total evenements analyses : {total}", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"- Total attaques bloquees : {attacks}", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(10)
        
        if attacks > 0:
            pdf.set_font("helvetica", 'B', 12)
            pdf.cell(0, 10, "Top 10 Dernieres Attaques Bloquees :", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("helvetica", 'B', 10)
            
            pdf.cell(45, 10, "Heure", border=1)
            pdf.cell(40, 10, "IP Source", border=1)
            pdf.cell(60, 10, "Tactique MITRE", border=1)
            pdf.cell(30, 10, "Severite", border=1, new_x="LMARGIN", new_y="NEXT")
            
            pdf.set_font("helvetica", '', 9)
            atk_df = df[df["prediction"] == "ATTACK"].head(10)
            for _, row in atk_df.iterrows():
                mitre_tactic = str(row.get("mitre_tactic", "N/A"))[:25]
                severity = "CRITICAL" if row.get("confidence", 0) > 0.9 else "HIGH"
                
                pdf.cell(45, 8, str(row["timestamp"]), border=1)
                pdf.cell(40, 8, str(row["src_ip"]), border=1)
                pdf.cell(60, 8, mitre_tactic, border=1)
                pdf.cell(30, 8, severity, border=1, new_x="LMARGIN", new_y="NEXT")
                
        return pdf.output()
    except Exception as e:
        print(f"Erreur lors de la generation du PDF: {e}")
        return None

def clear_db():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
        st.sidebar.success("Base de données effacée !")
        time.sleep(1)
        st.rerun()

def get_process_status():
    """Vérifie quels scripts d'acquisition tournent."""
    sim_running = False
    live_running = False
    honey_running = False
    for p in psutil.process_iter(['name', 'cmdline']):
        try:
            cmd = " ".join(p.info['cmdline'] or [])
            if 'traffic_generator.py' in cmd and 'python' in p.info['name'].lower():
                sim_running = True
            elif 'live_sniffer.py' in cmd and 'python' in p.info['name'].lower():
                live_running = True
            elif 'honeypot.py' in cmd and 'python' in p.info['name'].lower():
                honey_running = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return sim_running, live_running, honey_running

def kill_process(script_name):
    """Tue un script spécifique."""
    for p in psutil.process_iter(['name', 'cmdline']):
        try:
            cmd = " ".join(p.info['cmdline'] or [])
            if script_name in cmd and 'python' in p.info['name'].lower():
                p.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

# =====================================================================
# AUTHENTICATION (Option 2)
# =====================================================================
if 'authenticated' not in st.session_state:
    st.session_state['authenticated'] = False

if not st.session_state['authenticated']:
    st.markdown("<br><br><br>", unsafe_allow_html=True)
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown("""
        <div style="text-align:center; padding: 2.5rem; background: linear-gradient(135deg, #161b22, #1c2333); border: 1px solid #30363d; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
            <div style="font-size: 4rem; margin-bottom: 1rem;">🔐</div>
            <h2 style="margin-bottom: 0.5rem; color: #58a6ff;">Portail SOC CyberShield</h2>
            <p style="color: #8b949e; margin-bottom: 2rem; font-family: 'JetBrains Mono', monospace;">Accès restreint au personnel autorisé</p>
        </div>
        """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            username = st.text_input("Identifiant Administrateur", placeholder="Ex: admin")
            password = st.text_input("Mot de passe", type="password", placeholder="Ex: soc_admin_2026")
            submit = st.form_submit_button("S'authentifier", use_container_width=True)
            
            if submit:
                if username == "admin" and password == "soc_admin_2026":
                    st.session_state['authenticated'] = True
                    st.rerun()
                else:
                    st.error("❌ Identifiants incorrects. Accès refusé.")
    st.stop()  # Stoppe le rendu du dashboard si non connecté !

# =====================================================================
# SIDEBAR
# =====================================================================
st.sidebar.markdown("""
<div style="text-align:center; padding: 1rem 0;">
    <div style="font-size: 2.5rem;">🛡️</div>
    <div style="font-family: 'Inter', sans-serif; font-size: 1.1rem; font-weight: 800; 
                background: linear-gradient(135deg, #58a6ff, #bc8cff); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
        CyberShield SOC
    </div>
    <div style="font-family: 'JetBrains Mono', monospace; font-size: 0.65rem; color: #8b949e; margin-top: 2px;">
        v3.0 Ultimate | AI-Powered SIEM
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("---")

# Statut API
st.sidebar.markdown("##### Statut des Services")
try:
    import requests
    response = requests.get("http://127.0.0.1:8000/health", timeout=1)
    if response.status_code == 200:
        st.sidebar.markdown("🟢 **Moteur IA** : Opérationnel")
    else:
        st.sidebar.markdown("🟡 **Moteur IA** : Dégradé")
except Exception:
    st.sidebar.markdown("🔴 **Moteur IA** : Hors ligne")

# --- CONTRÔLE DE LA SONDE ---
st.sidebar.markdown("---")
st.sidebar.markdown("##### 🔌 Sondes & Pièges")
sim_status, live_status, honey_status = get_process_status()

if sim_status:
    st.sidebar.success("Mode actif : **Simulation (NSL-KDD)**")
elif live_status:
    st.sidebar.info("Mode actif : **Écoute Réseau (Live Sniffer)**")
else:
    st.sidebar.warning("Mode actif : **Aucun (En veille)**")

if honey_status:
    st.sidebar.error("🍯 **Honeypot FTP** : ACTIF (Port 21)")

col1, col2 = st.sidebar.columns(2)
with col1:
    if st.button("🔴 Simu", help="Injecte le trafic NSL-KDD"):
        kill_process("live_sniffer.py")
        if not sim_status:
            subprocess.Popen([sys.executable, "traffic_generator.py", "--interval", "0.3"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)
            st.rerun()

with col2:
    if st.button("🔵 Live", help="Écoute la carte réseau via Scapy"):
        kill_process("traffic_generator.py")
        if not live_status:
            subprocess.Popen([sys.executable, "live_sniffer.py"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)
            st.rerun()

if not honey_status:
    if st.sidebar.button("🍯 Déployer Honeypot (FTP)", use_container_width=True):
        subprocess.Popen([sys.executable, "honeypot.py"], creationflags=subprocess.CREATE_NEW_CONSOLE)
        time.sleep(1)
        st.rerun()

if sim_status or live_status or honey_status:
    if st.sidebar.button("⏹️ Tout Stopper", use_container_width=True):
        kill_process("traffic_generator.py")
        kill_process("live_sniffer.py")
        kill_process("honeypot.py")
        time.sleep(1)
        st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("##### Configuration")
refresh_rate = st.sidebar.slider("Rafraîchissement (s)", 1, 10, 2)
enable_refresh = st.sidebar.checkbox("Auto-refresh", value=True)
show_only_attacks = st.sidebar.checkbox("Attaques uniquement", value=False)

st.sidebar.markdown("---")
st.sidebar.markdown("##### 👁️ Vue des Données")

options_view = ["Toutes les données", "Simulation Uniquement", "Sondes Réelles (Live/Honeypot)"]

if "data_view_mode" not in st.session_state:
    st.session_state.data_view_mode = "Toutes les données"

# Switch automatique de la vue uniquement au démarrage d'une sonde
if sim_status and not st.session_state.get("was_sim_running", False):
    st.session_state.data_view_mode = "Simulation Uniquement"
elif (live_status or honey_status) and not st.session_state.get("was_live_running", False):
    st.session_state.data_view_mode = "Sondes Réelles (Live/Honeypot)"

st.session_state.was_sim_running = sim_status
st.session_state.was_live_running = live_status or honey_status

try:
    current_index = options_view.index(st.session_state.data_view_mode)
except ValueError:
    current_index = 0

data_view = st.sidebar.radio(
    "Filtrer l'historique :",
    options_view,
    index=current_index
)

st.session_state.data_view_mode = data_view

st.sidebar.markdown("---")
st.sidebar.markdown("##### Actions")
if st.sidebar.button("🗑️ Reset SIEM", use_container_width=True):
    clear_db()

# =====================================================================
# MAIN HEADER
# =====================================================================
st.markdown("""
<div class="soc-header">
    <h1>CYBERSHIELD — NEXT-GEN SOC</h1>
    <div class="subtitle"><span class="status-dot"></span>SYSTÈME OPÉRATIONNEL | MONITORING EN TEMPS RÉEL</div>
</div>
""", unsafe_allow_html=True)

# =====================================================================
# DATA
# =====================================================================
if data_view == "Simulation Uniquement":
    mode = "sim"
elif data_view == "Sondes Réelles (Live/Honeypot)":
    mode = "live"
else:
    mode = "all"

df_all, total_events, attack_events, rate, recent_events = get_live_stats(mode)
normal_events = total_events - attack_events

# Injection du bouton PDF dans la sidebar (Option 3)
st.sidebar.markdown("---")
st.sidebar.markdown("##### Rapports (PDF)")
pdf_bytes = generate_pdf_report(df_all, total_events, attack_events)
if pdf_bytes:
    st.sidebar.download_button(
        label="📄 Exporter Rapport PDF",
        data=bytes(pdf_bytes),
        file_name=f"Rapport_SOC_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
        mime="application/pdf",
        use_container_width=True
    )

# =====================================================================
# TABS
# =====================================================================
tab_live, tab_threat, tab_xai, tab_mitre, tab_models, tab_batch = st.tabs([
    "🌍 Live Operations", "🔍 Threat Intel", "🧠 XAI Forensics", "🗺️ MITRE ATT&CK", "🎓 Apprentissage (Projet)", "📂 Batch Forensics"
])

# =====================================================================
# TAB 1 : LIVE OPERATIONS
# =====================================================================
with tab_live:
    if df_all.empty or "src_lat" not in df_all.columns:
        st.info("En attente de trafic réseau... Lancez `run_soc.bat` pour démarrer.")
    else:
        # --- KPI CARDS ---
        st.markdown(f"""
        <div class="kpi-grid">
            <div class="kpi-card kpi-blue">
                <div class="kpi-label">Paquets Analysés</div>
                <div class="kpi-value">{total_events:,}</div>
            </div>
            <div class="kpi-card kpi-green">
                <div class="kpi-label">Trafic Normal</div>
                <div class="kpi-value">{normal_events:,}</div>
            </div>
            <div class="kpi-card kpi-red">
                <div class="kpi-label">Attaques Bloquées</div>
                <div class="kpi-value">{attack_events:,}</div>
            </div>
            <div class="kpi-card kpi-yellow">
                <div class="kpi-label">Taux d'Intrusion</div>
                <div class="kpi-value">{rate:.1f}%</div>
            </div>
            <div class="kpi-card kpi-purple">
                <div class="kpi-label">Confiance Moyenne</div>
                <div class="kpi-value">{df_all['confidence'].mean()*100:.0f}%</div>
            </div>
        </div>
        """, unsafe_allow_html=True)
        
        # --- THREAT MAP + SCORE ---
        col_map, col_score = st.columns([3, 2])
        
        with col_map:
            st.markdown("## 🌍 Threat Map — Attaques Mondiales")
            map_data = recent_events[recent_events["prediction"] == "ATTACK"].copy()
            if not map_data.empty:
                arc_layer = pdk.Layer(
                    "ArcLayer", data=map_data,
                    get_width=3,
                    get_source_position=["src_lon", "src_lat"],
                    get_target_position=["dst_lon", "dst_lat"],
                    get_tilt=15,
                    get_source_color=[248, 81, 73, 220],
                    get_target_color=[88, 166, 255, 220],
                    pickable=True, auto_highlight=True,
                )
                scatter_src = pdk.Layer(
                    "ScatterplotLayer", data=map_data,
                    get_position=["src_lon", "src_lat"],
                    get_fill_color=[248, 81, 73, 200],
                    get_radius=80000,
                    radiusMinPixels=4, radiusMaxPixels=15,
                )
                # SOC marker (Paris)
                soc_df = pd.DataFrame([{"lat": 48.8566, "lon": 2.3522}])
                scatter_soc = pdk.Layer(
                    "ScatterplotLayer", data=soc_df,
                    get_position=["lon", "lat"],
                    get_fill_color=[88, 166, 255, 255],
                    get_radius=120000,
                    radiusMinPixels=6, radiusMaxPixels=20,
                )
                view = pdk.ViewState(latitude=25, longitude=10, zoom=1.2, pitch=40)
                deck = pdk.Deck(
                    layers=[arc_layer, scatter_src, scatter_soc],
                    initial_view_state=view,
                    map_style="mapbox://styles/mapbox/dark-v10",
                    tooltip={"text": "Source: {src_ip}\nProtocol: {protocol_type}\nService: {service}"}
                )
                st.pydeck_chart(deck)
            else:
                st.success("Aucune attaque détectée récemment.")
                
        with col_score:
            st.markdown("## 📡 Score d'Intrusion (Live)")
            chart_df = recent_events.iloc[::-1].copy()
            fig = go.Figure()
            
            normal_df = chart_df[chart_df["prediction"] == "NORMAL"]
            attack_df = chart_df[chart_df["prediction"] == "ATTACK"]
            
            fig.add_trace(go.Scatter(x=normal_df["timestamp"], y=normal_df["ensemble_score"],
                mode="markers+lines", name="Normal", line=dict(color="#3fb950", width=1.5),
                marker=dict(size=5, color="#3fb950")))
            fig.add_trace(go.Scatter(x=attack_df["timestamp"], y=attack_df["ensemble_score"],
                mode="markers+lines", name="Attack", line=dict(color="#f85149", width=2),
                marker=dict(size=7, color="#f85149", symbol="x")))
            fig.add_hline(y=0.5, line_dash="dot", line_color="#d29922", line_width=1,
                annotation_text="Seuil 0.50", annotation_font_color="#d29922")
            fig.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(22,27,34,0.3)',
                font=dict(color='#8b949e', family='Inter'), margin=dict(l=10, r=10, t=10, b=10),
                height=380, legend=dict(orientation="h", y=-0.15),
                xaxis=dict(showgrid=False, title=""), yaxis=dict(showgrid=True, gridcolor='#161b22', range=[0, 1.05], title="")
            )
            st.plotly_chart(fig, use_container_width=True)
            
            # Attack family distribution (mini donut)
            if "mitre_tactic" in df_all.columns:
                attacks_df = df_all[df_all["prediction"] == "ATTACK"]
                if not attacks_df.empty:
                    tactic_counts = attacks_df["mitre_tactic"].value_counts().reset_index()
                    tactic_counts.columns = ["Tactic", "Count"]
                    fig_donut = px.pie(tactic_counts, values="Count", names="Tactic", hole=0.55,
                        color_discrete_sequence=["#f85149", "#d29922", "#58a6ff", "#bc8cff", "#3fb950"])
                    fig_donut.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)', font=dict(color='#8b949e', family='Inter', size=10),
                        margin=dict(l=5, r=5, t=5, b=5), height=180, showlegend=True,
                        legend=dict(font=dict(size=9), orientation="h")
                    )
                    fig_donut.update_traces(textinfo='percent', textfont_size=9)
                    st.plotly_chart(fig_donut, use_container_width=True)
        
        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        
        # --- ALERT LOG ---
        st.markdown("## 🚨 Journal des Alertes en Temps Réel")
        display_df = recent_events
        if show_only_attacks:
            display_df = display_df[display_df["prediction"] == "ATTACK"]
            
        for _, row in display_df.head(15).iterrows():
            is_atk = row["prediction"] == "ATTACK"
            
            # Severity badge
            severity = row.get("mitre_tactic", "N/A")
            if "Impact" in str(severity) or "Privilege" in str(severity):
                sev_class = "badge-critical"
                sev_text = "CRITICAL"
                alert_class = "alert-critical" if is_atk else "alert-success"
            elif "Reconnaissance" in str(severity):
                sev_class = "badge-high"
                sev_text = "HIGH"
                alert_class = "alert-danger" if is_atk else "alert-success"
            elif is_atk:
                sev_class = "badge-medium"
                sev_text = "MEDIUM"
                alert_class = "alert-danger"
            else:
                sev_class = "badge-info"
                sev_text = "INFO"
                alert_class = "alert-success"
            
            mitre_badge = f'<span class="badge badge-mitre">{row.get("mitre_technique", "")}</span>' if is_atk else ""
            
            # IPS Blockage Detection
            report_text = str(row.get("ai_report", ""))
            ips_badge = ""
            if "DECISION AUTONOME" in report_text or "Bloquée" in report_text or "bloquée" in report_text:
                ips_badge = '<span class="badge badge-critical" style="background: rgba(248,81,73,0.1); border: 1px solid #f85149; box-shadow: 0 0 10px rgba(248,81,73,0.4);">🛡️ IPS BLOCKED</span>'
                
            icon = "🚨" if is_atk else "✅"
            
            st.markdown(f"""
            <div class="alert-row {alert_class}">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span>{icon} <strong>{row['timestamp']}</strong> &nbsp; 
                        <span class="badge {sev_class}">{sev_text}</span> {mitre_badge} {ips_badge}
                    </span>
                    <span style="color:#8b949e; font-size:0.72rem;">Conf: {row['confidence']*100:.0f}%</span>
                </div>
                <div style="margin-top:4px; color:#8b949e; font-size:0.75rem;">
                    {row['src_ip']} → {row['dst_ip']} | {row['protocol_type']}/{row['service']} | 
                    {row['src_bytes']}B→{row['dst_bytes']}B | Score: {row['ensemble_score']:.3f}
                </div>
            </div>
            """, unsafe_allow_html=True)

# =====================================================================
# TAB 2 : THREAT INTELLIGENCE
# =====================================================================
with tab_threat:
    st.markdown("## 🔍 Threat Intelligence — Enrichissement des Sources d'Attaque")
    st.markdown("Analyse de la réputation des adresses IP observées dans les alertes via notre base de Renseignements sur les Menaces (CTI).")
    
    if not df_all.empty and "src_ip" in df_all.columns:
        attacks_only = df_all[df_all["prediction"] == "ATTACK"]
        if not attacks_only.empty:
            # Stats par IP source
            ip_stats = attacks_only.groupby("src_ip").agg(
                nb_attaques=("id", "count"),
                confiance_moy=("confidence", "mean"),
                derniere_vue=("timestamp", "max")
            ).reset_index().sort_values("nb_attaques", ascending=False)
            
            # Threat Intel Database (same as API)
            THREAT_INTEL = {
                "104.244.42.1":  {"reputation": "Malicious", "country": "🇺🇸 US", "org": "Twitter Inc.", "threat_type": "Botnet C2"},
                "185.60.216.35": {"reputation": "Suspicious", "country": "🇬🇧 GB", "org": "Facebook Ireland", "threat_type": "Phishing Relay"},
                "220.181.38.148": {"reputation": "Malicious", "country": "🇨🇳 CN", "org": "Beijing Baidu", "threat_type": "APT (Volt Typhoon)"},
                "178.23.11.90":  {"reputation": "Malicious", "country": "🇷🇺 RU", "org": "Moscow Datacenter", "threat_type": "Ransomware"},
                "45.12.33.11":   {"reputation": "Suspicious", "country": "🇧🇷 BR", "org": "Sao Paulo Hosting", "threat_type": "Cryptominer"},
                "8.8.8.8":       {"reputation": "Clean", "country": "🇺🇸 US", "org": "Google LLC", "threat_type": "N/A"},
            }
            
            for _, ip_row in ip_stats.iterrows():
                ip = ip_row["src_ip"]
                intel = THREAT_INTEL.get(ip, {"reputation": "Unknown", "country": "??", "org": "Unknown", "threat_type": "Unclassified"})
                rep = intel["reputation"]
                rep_class = "rep-malicious" if rep == "Malicious" else ("rep-suspicious" if rep == "Suspicious" else "rep-clean")
                
                st.markdown(f"""
                <div class="intel-card">
                    <div class="intel-header">🔎 IP Source : {ip}</div>
                    <div class="intel-row"><span class="intel-label">Pays / Organisation</span><span class="intel-value">{intel['country']} — {intel['org']}</span></div>
                    <div class="intel-row"><span class="intel-label">Réputation</span><span class="intel-value {rep_class}">{rep}</span></div>
                    <div class="intel-row"><span class="intel-label">Type de Menace</span><span class="intel-value">{intel['threat_type']}</span></div>
                    <div class="intel-row"><span class="intel-label">Nombre d'Attaques</span><span class="intel-value" style="color:#f85149;">{int(ip_row['nb_attaques'])}</span></div>
                    <div class="intel-row"><span class="intel-label">Confiance Moyenne</span><span class="intel-value">{ip_row['confiance_moy']*100:.1f}%</span></div>
                    <div class="intel-row"><span class="intel-label">Dernière Observation</span><span class="intel-value">{ip_row['derniere_vue']}</span></div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("Aucune attaque enregistrée.")
    else:
        st.info("En attente de données...")

# =====================================================================
# TAB 3 : XAI FORENSICS (SHAP + GenAI Copilot)
# =====================================================================
with tab_xai:
    st.markdown("## 🧠 Analyse Forensique IA — Explicabilité & Copilote GenAI")
    
    if not df_all.empty and "shap_json" in df_all.columns:
        attacks_only = df_all[df_all["prediction"] == "ATTACK"]
        if attacks_only.empty:
            st.success("Aucune attaque à analyser.")
        else:
            selected = st.selectbox("Sélectionnez un incident :", attacks_only["timestamp"].head(15).tolist())
            event = attacks_only[attacks_only["timestamp"] == selected].iloc[0]
            
            col_info, col_shap = st.columns([2, 3])
            
            with col_info:
                # Packet details
                st.markdown(f"""
                <div class="intel-card">
                    <div class="intel-header">📋 Détails du Paquet</div>
                    <div class="intel-row"><span class="intel-label">IP Source</span><span class="intel-value">{event.get('src_ip','?')}</span></div>
                    <div class="intel-row"><span class="intel-label">IP Cible</span><span class="intel-value">{event.get('dst_ip','?')}</span></div>
                    <div class="intel-row"><span class="intel-label">Protocole</span><span class="intel-value">{event.get('protocol_type','?')}</span></div>
                    <div class="intel-row"><span class="intel-label">Service</span><span class="intel-value">{event.get('service','?')}</span></div>
                    <div class="intel-row"><span class="intel-label">Score Ensemble</span><span class="intel-value" style="color:#f85149;">{event['ensemble_score']*100:.1f}%</span></div>
                    <div class="intel-row"><span class="intel-label">MITRE Technique</span><span class="intel-value" style="color:#bc8cff;">{event.get('mitre_technique','N/A')}</span></div>
                    <div class="intel-row"><span class="intel-label">Vérité Terrain</span><span class="intel-value">{event.get('true_label','?')}</span></div>
                </div>
                """, unsafe_allow_html=True)
                
                # AI Report
                ai_report = event.get("ai_report", "")
                if ai_report:
                    st.markdown(f"""
                    <div class="ai-report" style="margin-top: 0.8rem;">
                        <div class="ai-report-header">🤖 Rapport du Copilote GenAI</div>
                        {ai_report}
                    </div>
                    """, unsafe_allow_html=True)
            
            with col_shap:
                shap_str = event.get("shap_json", "{}")
                try:
                    shap_dict = json.loads(shap_str)
                    if shap_dict:
                        df_shap = pd.DataFrame(list(shap_dict.items()), columns=['Feature', 'SHAP Value'])
                        df_shap = df_shap.sort_values(by="SHAP Value", key=abs, ascending=True)
                        
                        colors = ['#f85149' if v > 0 else '#58a6ff' for v in df_shap['SHAP Value']]
                        
                        fig_shap = go.Figure(go.Bar(
                            x=df_shap["SHAP Value"], y=df_shap["Feature"],
                            orientation='h', marker_color=colors,
                            text=[f"{v:.4f}" for v in df_shap["SHAP Value"]],
                            textposition='outside', textfont=dict(size=11, color='#c9d1d9')
                        ))
                        fig_shap.update_layout(
                            title=dict(text="Top Features — SHAP Explainer", font=dict(size=14, color='#bc8cff')),
                            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(22,27,34,0.3)',
                            font=dict(color='#8b949e', family='Inter'), height=350,
                            margin=dict(l=10, r=80, t=40, b=10),
                            xaxis=dict(showgrid=True, gridcolor='#161b22', title="Impact SHAP"),
                            yaxis=dict(showgrid=False)
                        )
                        st.plotly_chart(fig_shap, use_container_width=True)
                        
                        # Radar chart of model scores
                        st.markdown("### 🎯 Consensus des Modèles")
                        categories = ['Random Forest', 'XGBoost', 'Deep Neural Net', 'LSTM AutoEncoder']
                        # Try to get from recent columns, fallback to ensemble
                        rf_s = float(event.get('rf_score', event['ensemble_score']))
                        xgb_s = float(event.get('xgb_score', event['ensemble_score']))
                        dnn_s = float(event.get('dnn_score', event['ensemble_score']))
                        ae_s = float(event.get('ae_score', event['ensemble_score']))
                        values = [rf_s, xgb_s, dnn_s, ae_s]
                        
                        fig_radar = go.Figure(go.Scatterpolar(
                            r=values + [values[0]],
                            theta=categories + [categories[0]],
                            fill='toself',
                            fillcolor='rgba(248,81,73,0.15)',
                            line=dict(color='#f85149', width=2),
                            marker=dict(size=6, color='#f85149')
                        ))
                        fig_radar.update_layout(
                            polar=dict(
                                bgcolor='rgba(22,27,34,0.3)',
                                radialaxis=dict(visible=True, range=[0, 1], gridcolor='#21262d', color='#8b949e'),
                                angularaxis=dict(gridcolor='#21262d', color='#8b949e')
                            ),
                            paper_bgcolor='rgba(0,0,0,0)', font=dict(color='#8b949e', family='Inter'),
                            height=300, margin=dict(l=40, r=40, t=20, b=20), showlegend=False
                        )
                        st.plotly_chart(fig_radar, use_container_width=True)
                    else:
                        st.info("Données SHAP indisponibles.")
                except Exception as e:
                    st.error(f"Erreur SHAP : {e}")
    else:
        st.info("En attente de données XAI...")

# =====================================================================
# TAB 4 : MITRE ATT&CK
# =====================================================================
with tab_mitre:
    st.markdown("## 🗺️ Matrice MITRE ATT&CK — Cartographie des Tactiques Observées")
    st.markdown("Vue d'ensemble des tactiques et techniques d'attaque détectées par le SOC, mappées sur le framework MITRE ATT&CK.")
    
    # MITRE Matrix data
    mitre_tactics = [
        {"id": "TA0043", "name": "Reconnaissance", "techniques": ["T1595 Active Scanning", "T1592 Gather Victim Host Info"]},
        {"id": "TA0001", "name": "Initial Access", "techniques": ["T1190 Exploit Public App", "T1133 External Remote Services"]},
        {"id": "TA0002", "name": "Execution", "techniques": ["T1059 Command Line", "T1204 User Execution"]},
        {"id": "TA0004", "name": "Privilege Escalation", "techniques": ["T1068 Exploitation", "T1548 Abuse Elevation"]},
        {"id": "TA0005", "name": "Defense Evasion", "techniques": ["T1070 Indicator Removal", "T1027 Obfuscated Files"]},
        {"id": "TA0040", "name": "Impact", "techniques": ["T1498 Network DoS", "T1489 Service Stop"]},
    ]
    
    # Determine active tactics from data
    active_techniques = set()
    if not df_all.empty and "mitre_technique" in df_all.columns:
        attacks_df = df_all[df_all["prediction"] == "ATTACK"]
        if not attacks_df.empty:
            for t in attacks_df["mitre_technique"].dropna().unique():
                # Extract technique ID
                tid = t.split(" - ")[0].strip() if " - " in t else t.split()[0] if t else ""
                active_techniques.add(tid)
    
    # Render MITRE matrix
    cols = st.columns(len(mitre_tactics))
    for i, tactic in enumerate(mitre_tactics):
        with cols[i]:
            st.markdown(f"<div class='mitre-tactic-header'>{tactic['id']}<br>{tactic['name']}</div>", unsafe_allow_html=True)
            for tech in tactic["techniques"]:
                tid = tech.split()[0]
                is_active = tid in active_techniques
                active_cls = "mitre-active" if is_active else ""
                count = 0
                if is_active and not df_all.empty:
                    count = len(attacks_df[attacks_df["mitre_technique"].str.contains(tid, na=False)])
                count_str = f"<br><strong style='color:#f85149;'>{count} hits</strong>" if is_active else ""
                st.markdown(f"<div class='mitre-cell {active_cls}'>{tech}{count_str}</div>", unsafe_allow_html=True)

    # Summary stats
    if not df_all.empty and "mitre_tactic" in df_all.columns:
        st.markdown('<div class="section-divider"></div>', unsafe_allow_html=True)
        
        attacks_df = df_all[df_all["prediction"] == "ATTACK"]
        if not attacks_df.empty:
            col_m1, col_m2 = st.columns(2)
            with col_m1:
                st.markdown("### Distribution des Tactiques")
                tactic_dist = attacks_df["mitre_tactic"].value_counts().reset_index()
                tactic_dist.columns = ["Tactic", "Count"]
                fig_td = px.bar(tactic_dist, x="Count", y="Tactic", orientation='h',
                    color_discrete_sequence=["#bc8cff"])
                fig_td.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(22,27,34,0.3)',
                    font=dict(color='#8b949e', family='Inter'), height=250,
                    margin=dict(l=10, r=10, t=10, b=10), xaxis=dict(showgrid=True, gridcolor='#161b22'),
                    yaxis=dict(showgrid=False)
                )
                st.plotly_chart(fig_td, use_container_width=True)
            with col_m2:
                st.markdown("### Timeline des Attaques")
                attacks_df_copy = attacks_df.copy()
                attacks_df_copy["ts_parsed"] = pd.to_datetime(attacks_df_copy["timestamp"], errors='coerce')
                if not attacks_df_copy["ts_parsed"].isna().all():
                    attacks_df_copy["minute"] = attacks_df_copy["ts_parsed"].dt.strftime("%H:%M")
                    timeline = attacks_df_copy.groupby("minute").size().reset_index(name="count")
                    fig_tl = px.area(timeline, x="minute", y="count", color_discrete_sequence=["#f85149"])
                    fig_tl.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(22,27,34,0.3)',
                        font=dict(color='#8b949e', family='Inter'), height=250,
                        margin=dict(l=10, r=10, t=10, b=10),
                        xaxis=dict(showgrid=False, title=""), yaxis=dict(showgrid=True, gridcolor='#161b22', title="Attaques/min")
                    )
                    st.plotly_chart(fig_tl, use_container_width=True)

# =====================================================================
# TAB 5 : APPRENTISSAGE (PROJET)
# =====================================================================
with tab_models:
    st.markdown("## 🎓 Rapport d'Apprentissage & Projet")
    st.markdown("""
    Cette section présente le déroulement complet de l'entraînement de notre Intelligence Artificielle, conformément au cahier des charges du projet **SOC Intelligent basé sur l'IA**.
    """)
    
    st.markdown("### 📌 Section 1 : Comprendre les données")
    st.markdown("""
    - **Dataset utilisé :** `NSL-KDD` (Le standard de référence pour la détection d'intrusions réseau).
    - **Taille des données :** 125 973 lignes (Entraînement) / 22 544 lignes (Test).
    - **Types de colonnes :** 41 Features (38 Numériques, 3 Catégorielles : `protocol_type`, `service`, `flag`).
    - **Variable cible :** `label` (NORMAL vs ATTACK).
    """)
    if os.path.exists("figures/section1_eda.png"):
        st.image("figures/section1_eda.png", use_container_width=True)

    st.markdown("### ⚙️ Section 2 : Préparation des données")
    st.markdown("""
    - **Nettoyage :** Suppression des valeurs manquantes et des doublons inutiles.
    - **Encodage :** Utilisation de `LabelEncoder` pour transformer les 3 variables catégorielles en valeurs numériques compréhensibles par nos modèles ML/DL.
    - **Normalisation :** Application de `StandardScaler` pour centrer-réduire (μ=0, σ=1) les 41 features et optimiser la convergence du réseau de neurones.
    """)

    st.markdown("### 🧠 Section 3 : Modèle de détection (ML & DL)")
    st.markdown("""
    Nous sommes allés au-delà de la consigne en choisissant **4 modèles complémentaires** au lieu de 2, combinés dans une architecture *Ensemble Learning* :
    1. **Random Forest** (Machine Learning Classique)
    2. **XGBoost** (Gradient Boosting)
    3. **DNN - Deep Neural Network** (Deep Learning supervisé)
    4. **LSTM Autoencoder** (Deep Learning non-supervisé pour la détection d'anomalies inédites)
    
    - **Split des données :** Le dataset d'entraînement a été divisé en 80% Train / 20% Validation. L'évaluation a été faite sur le dataset de test indépendant `KDDTest+`.
    """)
    
    if not os.path.exists(RESULTS_FILE):
        st.warning("Résultats JSON non trouvés. Exécutez le script d'entraînement au préalable.")
    else:
        with open(RESULTS_FILE, "r") as f:
            results = json.load(f)
        
        # Metrics table
        metrics_data = []
        for name, m in results.items():
            metrics_data.append({
                "Modèle": name,
                "Accuracy": f"{m['accuracy']*100:.2f}%",
                "Précision": f"{m['precision']*100:.2f}%",
                "Recall": f"{m['recall']*100:.2f}%",
                "F1-Score": f"{m['f1']*100:.2f}%"
            })
        st.table(pd.DataFrame(metrics_data))
        
        # Charts
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.markdown("#### Matrices de Confusion")
            selected_model = st.selectbox("Sélectionnez un modèle pour voir sa matrice", list(results.keys()))
            cm = np.array(results[selected_model]["cm"])
            fig_cm = px.imshow(cm, text_auto=True, aspect="auto",
                labels=dict(x="Classe Prédite", y="Classe Réelle", color="Nombre"),
                x=["Normal", "Attaque"], y=["Normal", "Attaque"],
                color_continuous_scale="Blues")
            fig_cm.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', font=dict(color='#c9d1d9'),
                height=350, margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig_cm, use_container_width=True)

        with col_c2:
            st.markdown("#### Comparatif F1 & Accuracy")
            comp_df = pd.DataFrame([{"Modèle": k, "Accuracy": v["accuracy"], "F1": v["f1"]} for k, v in results.items()])
            fig_c = px.bar(comp_df, x="Modèle", y=["Accuracy", "F1"], barmode="group",
                color_discrete_sequence=["#58a6ff", "#bc8cff"])
            fig_c.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(22,27,34,0.3)',
                font=dict(color='#8b949e', family='Inter'),
                yaxis=dict(range=[0.7, 1.02], gridcolor='#161b22')
            )
            st.plotly_chart(fig_c, use_container_width=True)

    if os.path.exists("figures/section3_models.png"):
        st.markdown("#### Courbes d'apprentissage & Performances détaillées")
        st.image("figures/section3_models.png", use_container_width=True)

    if os.path.exists("figures/section3_feature_importance.png"):
        st.markdown("#### Importance des Variables (Feature Importance)")
        st.image("figures/section3_feature_importance.png", use_container_width=True)

    st.markdown("### ⏱️ Section 4 : Simulation temps réel")
    st.markdown("""
    Le mode **🔴 Simu** du panneau latéral gauche répond à cette exigence.  
    Il crée une boucle qui extrait des paquets aléatoires, les envoie au moteur IA, et le Dashboard affiche la prédiction (`NORMAL` ou `ATTACK`) instantanément.
    """)

    st.markdown("### 📊 Section 5 : Visualisation")
    st.markdown("""
    Nous avons choisi d'utiliser **Streamlit** pour offrir une expérience SOC complète. L'onglet `Live Operations` affiche le nombre d'événements et le nombre d'attaques en direct, enrichi d'une cartographie mondiale et de graphes dynamiques.
    """)

def auto_parse_logs(df):
    """ETL Intelligent : Tente de mapper un CSV inconnu vers les 41 features NSL-KDD."""
    required_cols = [
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
    
    # Check if it's already a perfect NSL-KDD file
    if all(col in df.columns for col in required_cols):
        return df, False
        
    mapped_df = pd.DataFrame()
    cols_lower = {str(c).lower(): c for c in df.columns}
    
    # Protocol
    if 'protocol' in cols_lower: mapped_df['protocol_type'] = df[cols_lower['protocol']]
    elif 'proto' in cols_lower: mapped_df['protocol_type'] = df[cols_lower['proto']]
    else: mapped_df['protocol_type'] = "tcp"
    
    # Bytes
    if 'src_bytes' in cols_lower: mapped_df['src_bytes'] = df[cols_lower['src_bytes']]
    elif 'length' in cols_lower: mapped_df['src_bytes'] = df[cols_lower['length']]
    elif 'bytes' in cols_lower: mapped_df['src_bytes'] = df[cols_lower['bytes']]
    else: mapped_df['src_bytes'] = 0
    
    # Duration
    if 'duration' in cols_lower: mapped_df['duration'] = df[cols_lower['duration']]
    elif 'time' in cols_lower: mapped_df['duration'] = df[cols_lower['time']]
    else: mapped_df['duration'] = 0
    
    # Service / Port
    if 'service' in cols_lower: 
        mapped_df['service'] = df[cols_lower['service']]
    elif 'port' in cols_lower or 'dst_port' in cols_lower:
        port_col = cols_lower.get('dst_port', cols_lower.get('port'))
        port_map = {80: "http", 443: "http", 21: "ftp", 22: "ssh", 25: "smtp", 53: "domain_u"}
        mapped_df['service'] = df[port_col].map(lambda x: port_map.get(x, "other") if pd.notnull(x) else "other")
    else:
        mapped_df['service'] = "other"
        
    # Default Fillers
    for col in required_cols:
        if col not in mapped_df.columns:
            if col == 'flag': mapped_df['flag'] = "SF"
            else: mapped_df[col] = 0.0
            
    # Label
    if 'label' in cols_lower:
        mapped_df['label'] = df[cols_lower['label']]
        
    return mapped_df, True

# =====================================================================
# TAB 6 : BATCH FORENSICS (PCAP & CSV)
# =====================================================================
with tab_batch:
    st.markdown("## 📂 Investigation Forensique Post-Mortem")
    st.markdown("Importez un fichier PCAP (Wireshark) ou CSV contenant des logs réseau pour que l'IA analyse l'historique complet.")
    
    uploaded_file = st.file_uploader("Choisissez un fichier réseau (.pcap ou .csv)", type=["csv", "pcap", "cap"])
    
    if uploaded_file is not None:
        file_ext = uploaded_file.name.split('.')[-1].lower()
        
        if file_ext in ['pcap', 'cap']:
            st.info("🔄 Analyse des trames PCAP en cours...")
            try:
                from scapy.all import rdpcap, IP, TCP, UDP
                with open("temp.pcap", "wb") as f:
                    f.write(uploaded_file.getbuffer())
                
                packets = rdpcap("temp.pcap")
                results_batch = []
                
                for pkt in packets[:200]: # Limité aux 200 premiers pour fluidité web
                    if IP in pkt:
                        src_ip = pkt[IP].src
                        dst_ip = pkt[IP].dst
                        protocol = "tcp" if TCP in pkt else ("udp" if UDP in pkt else "icmp")
                        service = "other"
                        if TCP in pkt:
                            port = pkt[TCP].dport
                            if port in [80, 443]: service = "http"
                            elif port == 21: service = "ftp"
                            elif port == 22: service = "ssh"
                            elif port == 23: service = "telnet"
                            
                        payload = {
                            "data": {
                                "protocol_type": protocol, "service": service, "flag": "SF",
                                "src_bytes": len(pkt), "dst_bytes": 0, "count": 1, "srv_count": 1,
                                "serror_rate": 0.0, "same_srv_rate": 1.0, "diff_srv_rate": 0.0,
                                "dst_host_count": 1, "dst_host_srv_count": 1
                            },
                            "true_label": "unknown",
                            "geo_data": {"src_ip": src_ip, "src_lat": 0, "src_lon": 0, "dst_ip": dst_ip, "dst_lat": 0, "dst_lon": 0},
                            "is_simulation": True
                        }
                        
                        try:
                            resp = requests.post("http://127.0.0.1:8000/predict", json=payload, timeout=1)
                            if resp.status_code == 200:
                                pred = resp.json()
                                results_batch.append({
                                    "Source": src_ip,
                                    "Destination": dst_ip,
                                    "Protocole": protocol,
                                    "Service": service,
                                    "Taille": len(pkt),
                                    "Décision IA": pred.get("prediction", "UNKNOWN"),
                                    "Confiance": f"{pred.get('confidence', 0)*100:.1f}%",
                                    "Mitre": pred.get("mitre", {}).get("tactic", "")
                                })
                        except:
                            pass
                
                if results_batch:
                    df_pcap = pd.DataFrame(results_batch)
                    st.success(f"✅ Analyse terminée : {len(df_pcap)} paquets IP traités.")
                    
                    colA, colB = st.columns([1, 2])
                    with colA:
                        nb_atk = len(df_pcap[df_pcap['Décision IA'] == 'ATTACK'])
                        st.metric("Total Paquets", len(df_pcap))
                        st.metric("Attaques Trouvées", nb_atk, delta_color="inverse")
                    
                    with colB:
                        st.markdown("### Rapport PCAP")
                        def color_decision(val):
                            return 'background-color: rgba(248,81,73,0.2)' if val == 'ATTACK' else 'background-color: rgba(63,185,80,0.1)'
                        
                        st.dataframe(df_pcap.style.applymap(color_decision, subset=['Décision IA']), use_container_width=True)
                else:
                    st.warning("Aucun paquet IPv4 valide ou API IA hors ligne.")
                    
            except Exception as e:
                st.error(f"Erreur PCAP : {e}")
                
        elif file_ext == 'csv':
            try:
                # Lecture initiale
                df_raw = pd.read_csv(uploaded_file)
                
                # Passage dans l'Auto-Parser (ETL)
                df_import, was_parsed = auto_parse_logs(df_raw)
                
                st.success(f"Fichier `{uploaded_file.name}` chargé ({len(df_import)} logs).")
                
                if was_parsed:
                    st.warning("⚠️ **Format Inconnu Détecté** : L'Auto-Parser a restructuré vos colonnes et généré les variables manquantes pour permettre l'analyse par l'IA.")
                    
                if st.button("🚀 Lancer l'Analyse IA Forensique", type="primary"):
                    progress_text = "Analyse des logs par le moteur Ensemble Learning..."
                    my_bar = st.progress(0, text=progress_text)
                    
                    results_batch = []
                    total_rows = len(df_import)
                    
                    # Simulation d'un geo-ip fixe pour les logs importés
                    geo_mock = {"src_ip": "ImportedLog", "src_lat": 0, "src_lon": 0, "dst_ip": "Local", "dst_lat": 0, "dst_lon": 0}
                    
                    # Traitement ligne par ligne via l'API
                    for idx, row in df_import.iterrows():
                        # Conversion de la row en dict pour l'API
                        row_dict = row.to_dict()
                        payload = {
                            "data": row_dict,
                            "true_label": str(row.get("label", "unknown")),
                            "geo_data": geo_mock,
                            "is_simulation": True
                        }
                        
                        try:
                            resp = requests.post("http://127.0.0.1:8000/predict", json=payload, timeout=2)
                            if resp.status_code == 200:
                                pred = resp.json()
                                results_batch.append({
                                    "Ligne": idx + 1,
                                    "Protocole": row.get("protocol_type", ""),
                                    "Service": row.get("service", ""),
                                    "Octets envoyés": row.get("src_bytes", 0),
                                    "Décision IA": pred.get("prediction", "ERROR"),
                                    "Confiance": f"{pred.get('confidence', 0)*100:.1f}%",
                                    "Sévérité": pred.get("mitre", {}).get("severity", "INFO"),
                                    "Action": pred.get("action_taken", "Alert Only")
                                })
                        except Exception as e:
                            pass # Ignore les erreurs de timeout pour un batch
                        
                        # Maj barre de progression
                        my_bar.progress((idx + 1) / total_rows, text=f"Analyse en cours : {idx + 1}/{total_rows} logs traités.")
                    
                    my_bar.empty()
                    st.success("✅ Analyse Forensique Terminée.")
                    
                    if results_batch:
                        res_df = pd.DataFrame(results_batch)
                        
                        colA, colB = st.columns([1, 2])
                        with colA:
                            nb_atk = len(res_df[res_df['Décision IA'] == 'ATTACK'])
                            st.metric("Total Logs", len(res_df))
                            st.metric("Attaques Trouvées", nb_atk, delta_color="inverse")
                        
                        with colB:
                            st.markdown("### Rapport des Menaces Identifiées")
                            def color_decision_csv(val):
                                return 'background-color: rgba(248,81,73,0.2)' if val == 'ATTACK' else 'background-color: rgba(63,185,80,0.1)'
                            
                            styled_df = res_df.style.applymap(color_decision_csv, subset=['Décision IA'])
                            st.dataframe(styled_df, use_container_width=True)
                            
                            # Bouton de téléchargement
                            csv_data = res_df.to_csv(index=False).encode('utf-8')
                            st.download_button(
                                label="📥 Télécharger le Rapport Forensique (CSV)",
                                data=csv_data,
                                file_name=f'forensic_report_{int(time.time())}.csv',
                                mime='text/csv',
                            )
            except Exception as e:
                st.error(f"Erreur de lecture du fichier : {e}. Assurez-vous qu'il s'agit d'un CSV compatible.")

# =====================================================================
# AUTO-REFRESH
# =====================================================================
if enable_refresh:
    time.sleep(refresh_rate)
    st.rerun()
