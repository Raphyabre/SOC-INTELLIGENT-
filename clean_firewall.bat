@echo off
chcp 65001 >nul 2>&1
title CyberShield - Nettoyage du Pare-feu
echo =====================================================================
echo   NETTOYAGE DES REGLES DE PARE-FEU CYBERSHIELD
echo =====================================================================
echo.

echo Verification des droits Administrateur...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Ce script doit etre execute en tant qu'Administrateur !
    echo Faites un clic droit sur clean_firewall.bat -^> Executer en tant qu'administrateur.
    pause
    exit /b
)

echo.
echo Suppression des regles "CyberShield_Block_IP"...
netsh advfirewall firewall delete rule name="CyberShield_Block_IP" >nul 2>&1

if %errorlevel% equ 0 (
    echo [SUCCES] Toutes les regles de blocage CyberShield ont ete supprimees du systeme.
) else (
    echo [INFO] Aucune regle CyberShield n'a ete trouvee. Le pare-feu est propre.
)

echo.
pause
