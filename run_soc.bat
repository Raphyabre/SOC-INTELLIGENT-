@echo off
chcp 65001 >nul 2>&1
title CyberShield SOC V3 - Lancement des Services
echo =====================================================================
echo   CYBERSHIELD SOC V3 - NEXT-GEN SECURITY OPERATIONS CENTER
echo   IA Explicable (SHAP) + MITRE ATT^&CK + Copilote GenAI
echo =====================================================================
echo.

:: Vérification du venv
if not exist .venv (
    echo [ERROR] L'environnement virtuel '.venv' n'existe pas.
    echo Veuillez lancer : python -m venv .venv
    echo Puis : .venv\Scripts\pip install -r requirements.txt
    pause
    exit /b
)

:: Suppression de l'ancienne base pour un demarrage propre
if exist soc_events.db (
    echo [CLEAN] Suppression de l'ancienne base de donnees...
    del /f /q soc_events.db >nul 2>&1
)

:: 1. Lancement de FastAPI (Moteur IA + SHAP + MITRE + GenAI)
echo [1/3] Demarrage du Moteur d'Inference IA sur http://127.0.0.1:8000...
start "FastAPI - CyberShield Engine" cmd /k "title CyberShield - Moteur IA && .venv\Scripts\python inference_api.py"

:: Attendre que l'API charge les modeles
echo Attente de 15 secondes pour le chargement des modeles IA...
timeout /t 15 /nobreak > nul

:: 2. Lancement du Dashboard SIEM V3
echo [2/3] Demarrage du Dashboard SIEM sur http://localhost:8501...
start "Streamlit - CyberShield Dashboard" cmd /k "title CyberShield - Dashboard SIEM && .venv\Scripts\streamlit run dashboard.py --server.headless true"

:: Attendre le dashboard
timeout /t 3 /nobreak > nul

:: 3. Lancement du Generateur de Flux Reseau
echo [3/3] Demarrage du Simulateur de Trafic Reseau...
start "Simulateur - Flux Reseau" cmd /k "title CyberShield - Simulateur Reseau && .venv\Scripts\python traffic_generator.py --interval 0.3"

echo.
echo =====================================================================
echo   TOUS LES COMPOSANTS SONT OPERATIONNELS
echo =====================================================================
echo.
echo   Dashboard SIEM   : http://localhost:8501
echo   API FastAPI      : http://127.0.0.1:8000/health
echo   API Docs (Swagger): http://127.0.0.1:8000/docs
echo.
echo   Pour arreter un service, fermez sa fenetre de terminal.
echo.
pause
