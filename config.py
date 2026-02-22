import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

SECRET_KEY = secrets.token_hex(32)
DATABASE = os.path.join(BASE_DIR, "instance", "soc_lab.db")
ARTIFACTS_DIR = os.path.join(BASE_DIR, "artifacts")
FLAG_PREFIX = "REDPAWN"
MAX_HINTS = 3

# ── Scoreboard réseau ──
# URL du serveur central (ex: "http://192.168.1.100:5050")
# Laisser vide pour un mode local (scoreboard uniquement local)
SCOREBOARD_SERVER = os.environ.get("SCOREBOARD_SERVER", "")

# Niveaux de difficulté
LEVELS = {
    1: {"name": "Analyste Junior", "color": "#00e676", "icon": "🟢"},
    2: {"name": "Analyste Confirmé", "color": "#ffea00", "icon": "🟡"},
    3: {"name": "Analyste Senior", "color": "#ff9100", "icon": "🟠"},
    4: {"name": "Expert SOC", "color": "#ff1744", "icon": "🔴"},
    5: {"name": "Threat Hunter", "color": "#d500f9", "icon": "🟣"},
}

# Catégories
CATEGORIES = {
    "log_analysis": {"name": "Analyse de Logs", "icon": "📋"},
    "phishing": {"name": "Analyse de Phishing", "icon": "🎣"},
    "network": {"name": "Forensics Réseau", "icon": "🌐"},
    "malware": {"name": "Analyse Malware", "icon": "🦠"},
    "siem": {"name": "Triage SIEM", "icon": "🔔"},
    "incident_response": {"name": "Réponse à Incident", "icon": "🚨"},
    "threat_intel": {"name": "Threat Intelligence", "icon": "🕵️"},
    "forensics": {"name": "Forensics Système", "icon": "🔬"},
    "memory_forensics": {"name": "Forensics Mémoire", "icon": "🧠"},
    "cloud_security": {"name": "Sécurité Cloud", "icon": "☁️"},
    "reverse_engineering": {"name": "Reverse Engineering", "icon": "⚙️"},
    "threat_hunting": {"name": "Threat Hunting", "icon": "🎯"},
}
