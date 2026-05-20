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
def get_live_stats():
    """Récupère les statistiques agrégées depuis SQLite."""
    if not os.path.exists(DB_FILE):
        return pd.DataFrame(), 0, 0, 0.0, pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_FILE)
        df = pd.read_sql_query("SELECT * FROM events ORDER BY id DESC", conn)
        conn.close()
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
    for p in psutil.process_iter(['name', 'cmdline']):
        try:
            cmd = " ".join(p.info['cmdline'] or [])
            if 'traffic_generator.py' in cmd and 'python' in p.info['name'].lower():
                sim_running = True
            elif 'live_sniffer.py' in cmd and 'python' in p.info['name'].lower():
                live_running = True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    return sim_running, live_running

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
st.sidebar.markdown("##### 🔌 Sonde d'Acquisition")
sim_status, live_status = get_process_status()

if sim_status:
    st.sidebar.success("Mode actif : **Simulation (NSL-KDD)**")
elif live_status:
    st.sidebar.info("Mode actif : **Écoute Réseau (Live Sniffer)**")
else:
    st.sidebar.warning("Mode actif : **Aucun (En veille)**")

col1, col2 = st.sidebar.columns(2)
with col1:
    if st.button("🔴 Lancer Simu", help="Injecte le trafic NSL-KDD"):
        kill_process("live_sniffer.py")
        if not sim_status:
            subprocess.Popen([sys.executable, "traffic_generator.py", "--interval", "0.3"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)
            st.rerun()

with col2:
    if st.button("🔵 Lancer Live", help="Écoute la carte réseau via Scapy"):
        kill_process("traffic_generator.py")
        if not live_status:
            subprocess.Popen([sys.executable, "live_sniffer.py"], creationflags=subprocess.CREATE_NEW_CONSOLE)
            time.sleep(1)
            st.rerun()

if sim_status or live_status:
    if st.sidebar.button("⏹️ Stopper l'Acquisition", use_container_width=True):
        kill_process("traffic_generator.py")
        kill_process("live_sniffer.py")
        time.sleep(1)
        st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("##### Configuration")
refresh_rate = st.sidebar.slider("Rafraîchissement (s)", 1, 10, 2)
enable_refresh = st.sidebar.checkbox("Auto-refresh", value=True)
show_only_attacks = st.sidebar.checkbox("Attaques uniquement", value=False)

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
df_all, total_events, attack_events, rate, recent_events = get_live_stats()
normal_events = total_events - attack_events

# =====================================================================
# TABS
# =====================================================================
tab_live, tab_threat, tab_xai, tab_mitre, tab_models = st.tabs([
    "🌍 Live Operations", "🔍 Threat Intel", "🧠 XAI Forensics", "🗺️ MITRE ATT&CK", "📊 Model Benchmarks"
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
# TAB 5 : MODEL BENCHMARKS
# =====================================================================
with tab_models:
    st.markdown("## 📊 Benchmarks & Performances des Modèles IA")
    
    if not os.path.exists(RESULTS_FILE):
        st.warning("Résultats non disponibles. Entraînez les modèles d'abord.")
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
            st.markdown("### Comparatif F1 & Accuracy")
            comp_df = pd.DataFrame([{"Modèle": k, "Accuracy": v["accuracy"], "F1": v["f1"]} for k, v in results.items()])
            fig_c = px.bar(comp_df, x="Modèle", y=["Accuracy", "F1"], barmode="group",
                color_discrete_sequence=["#58a6ff", "#bc8cff"])
            fig_c.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(22,27,34,0.3)',
                font=dict(color='#8b949e', family='Inter'),
                yaxis=dict(range=[0.7, 1.02], gridcolor='#161b22')
            )
            st.plotly_chart(fig_c, use_container_width=True)
        with col_c2:
            st.markdown("### Matrices de Confusion")
            selected_model = st.selectbox("Modèle", list(results.keys()))
            cm = np.array(results[selected_model]["cm"])
            fig_cm = px.imshow(cm, text_auto=True, aspect="auto",
                labels=dict(x="Prédit", y="Réel", color="N"),
                x=["Normal", "Attaque"], y=["Normal", "Attaque"],
                color_continuous_scale="Blues")
            fig_cm.update_layout(
                paper_bgcolor='rgba(0,0,0,0)', font=dict(color='#c9d1d9'),
                height=300, margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig_cm, use_container_width=True)

# =====================================================================
# AUTO-REFRESH
# =====================================================================
if enable_refresh:
    time.sleep(refresh_rate)
    st.rerun()
