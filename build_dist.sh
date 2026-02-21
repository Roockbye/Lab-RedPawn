#!/bin/bash
# =====================================================
# RedPawn SOC Lab — Script de build pour distribution
# =====================================================
# Ce script crée un package distribuable avec les fichiers
# Python compilés (.pyc) pour empêcher la lecture des réponses.
#
# Usage : ./build_dist.sh
# Résultat : dossier dist/ prêt à distribuer (zip ou copie)
# =====================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DIST_DIR="$SCRIPT_DIR/dist/Lab-RedPawn"

echo ""
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   🔨 RedPawn SOC Lab — Build Distribution    ║"
echo "  ╚══════════════════════════════════════════════╝"
echo ""

# Nettoyer le dossier dist précédent
rm -rf "$SCRIPT_DIR/dist"
mkdir -p "$DIST_DIR"

echo "  [1/5] Copie des fichiers de configuration..."
cp "$SCRIPT_DIR/config.py" "$DIST_DIR/"
cp "$SCRIPT_DIR/database.py" "$DIST_DIR/"
cp "$SCRIPT_DIR/security.py" "$DIST_DIR/"
cp "$SCRIPT_DIR/app.py" "$DIST_DIR/"
cp "$SCRIPT_DIR/requirements.txt" "$DIST_DIR/"

echo "  [2/5] Compilation des challenges en .pyc (anti-triche)..."
mkdir -p "$DIST_DIR/challenges"

# Compiler les challenges en bytecode Python
python3 -m compileall -b -q "$SCRIPT_DIR/challenges/"

# Copier UNIQUEMENT les .pyc (pas les .py source)
cp "$SCRIPT_DIR/challenges/__init__.py" "$DIST_DIR/challenges/"
cp "$SCRIPT_DIR/challenges/registry.py" "$DIST_DIR/challenges/"

for pyc in "$SCRIPT_DIR/challenges/"*.pyc; do
    if [ -f "$pyc" ]; then
        cp "$pyc" "$DIST_DIR/challenges/"
    fi
done

# Nettoyer les .pyc du dossier source
rm -f "$SCRIPT_DIR/challenges/"*.pyc

echo "  [3/5] Copie des templates et assets..."
cp -r "$SCRIPT_DIR/templates" "$DIST_DIR/"
cp -r "$SCRIPT_DIR/static" "$DIST_DIR/"

echo "  [4/5] Création du script de lancement..."
cat > "$DIST_DIR/start.sh" << 'STARTSCRIPT'
#!/bin/bash
# RedPawn SOC Lab — Script de lancement
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "  🛡️  RedPawn SOC Lab — Démarrage"
echo ""

# Vérifier Python
if ! command -v python3 &> /dev/null; then
    echo "  ❌ Python 3 n'est pas installé !"
    echo "  → Installez Python 3.8+ depuis https://python.org"
    exit 1
fi

# Créer un venv si nécessaire
if [ ! -d ".venv" ]; then
    echo "  📦 Création de l'environnement virtuel..."
    python3 -m venv .venv
fi

# Activer et installer les dépendances
source .venv/bin/activate
pip install -q -r requirements.txt

echo ""
echo "  🚀 Lancement du lab..."
echo "  → Ouvrez http://127.0.0.1:5050 dans votre navigateur"
echo ""

python3 app.py
STARTSCRIPT
chmod +x "$DIST_DIR/start.sh"

# Script Windows
cat > "$DIST_DIR/start.bat" << 'BATSCRIPT'
@echo off
title RedPawn SOC Lab
echo.
echo   Shield RedPawn SOC Lab - Demarrage
echo.

:: Verifier Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo   X Python 3 n'est pas installe !
    echo   - Installez Python 3.8+ depuis https://python.org
    pause
    exit /b 1
)

:: Creer venv si necessaire
if not exist ".venv" (
    echo   Creation de l'environnement virtuel...
    python -m venv .venv
)

:: Activer et installer
call .venv\Scripts\activate.bat
pip install -q -r requirements.txt

echo.
echo   Lancement du lab...
echo   - Ouvrez http://127.0.0.1:5050 dans votre navigateur
echo.

python app.py
pause
BATSCRIPT

echo "  [5/5] Création de l'archive ZIP..."
cd "$SCRIPT_DIR/dist"
zip -rq "Lab-RedPawn.zip" "Lab-RedPawn/"
cd "$SCRIPT_DIR"

echo ""
echo "  ✅ Build terminé !"
echo ""
echo "  📁 Dossier : dist/Lab-RedPawn/"
echo "  📦 ZIP     : dist/Lab-RedPawn.zip"
echo ""
echo "  Distribution :"
echo "  1. Envoyez dist/Lab-RedPawn.zip à chaque participant"
echo "  2. Ils dézippe et lancent ./start.sh (Linux/Mac) ou start.bat (Windows)"
echo "  3. Le lab s'ouvre sur http://127.0.0.1:5050"
echo ""
echo "  🔒 Les fichiers challenges sont compilés (.pyc)"
echo "     → Les réponses ne sont pas lisibles en clair"
echo ""
