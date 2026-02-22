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
  EN ATTENTE : 6 alertes non triées
================================================================================

──────────────── ALERTE #1 ── SIEM-2026-4401 ── MEDIUM ────────────────

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

──────────────── ALERTE #2 ── SIEM-2026-4402 ── LOW ───────────────────

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

──────────────── ALERTE #3 ── SIEM-2026-4403 ── CRITICAL ──────────────

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

──────────────── ALERTE #4 ── SIEM-2026-4404 ── HIGH ──────────────────

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

──────────────── ALERTE #5 ── SIEM-2026-4405 ── MEDIUM ────────────────

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

──────────────── ALERTE #6 ── SIEM-2026-4406 ── LOW ───────────────────

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

================================================================================
  FIN DU RAPPORT — 6 alertes en attente de triage
================================================================================
"""

CHALLENGE = {
    "id": "c03_siem_triage",
    "title": "🔔 La Queue d'Alertes du Lundi",
    "category": "siem",
    "level": 1,
    "points_total": 300,
    "estimated_time": "25-40 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 11h30  
**Priorité :** NORMALE  
**Source :** Tâche courante — Triage des alertes SIEM

---

Vous prenez votre shift en tant qu'analyste SOC N1. Le dashboard SIEM affiche **6 alertes non triées** de la matinée.

Votre mission : trier chaque alerte, déterminer sa classification (Vrai Positif, Faux Positif, ou Bénin Vrai Positif), et identifier les actions de remédiation prioritaires.

> *"Allez, on commence le triage. Pour chaque alerte, dis-moi si c'est un True Positive, False Positive ou Benign True Positive, et pourquoi. Hiérarchise ensuite les investigations."*

### Rappel des classifications

| Classification | Abréviation | Signification | Exemple |
|---|---|---|---|
| **True Positive** | **TP** | L'alerte détecte une **vraie menace** qui nécessite investigation et action immédiate. | Mimikatz détecté sur un serveur → attaque réelle en cours |
| **False Positive** | **FP** | L'alerte se déclenche **à tort** — il n'y a aucune menace réelle. Le comportement détecté est inoffensif. | Un scan de vulnérabilité planifié déclenche une alerte IDS |
| **Benign True Positive** | **BTP** | L'alerte détecte un **vrai comportement** correspondant à la règle, mais l'activité est **légitime et autorisée**. Pas de menace. | Un admin modifie une GPO avec un ticket de changement approuvé |
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
            "text": "Alerte #1 (Scheduled Task via CLI) — Quelle est la classification ? (TP, FP, ou BTP)",
            "answer": "TP",
            "flag": "FLAG{TP}",
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
            "text": "Alerte #2 (DNS Query Newly Registered Domain) — Quelle est la classification ? (TP, FP, ou BTP)",
            "answer": "BTP",
            "flag": "FLAG{BTP}",
            "points": 40,
            "max_attempts": 2,
            "hints": [
                "Le domaine a 0 détections sur VT et a été visité via Chrome (navigation web)",
                "Une visite unique via publicité sans téléchargement = activité bénigne"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Alerte #3 (Mimikatz Pattern) — Quelle est la classification ? (TP, FP, ou BTP)",
            "answer": "TP",
            "flag": "FLAG{TP}",
            "points": 40,
            "max_attempts": 2,
            "hints": [
                "Mimikatz sur un Domain Controller est TOUJOURS critique",
                "Le compte de service est utilisé en dehors de ses heures normales"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Alerte #6 (GPO Modified) — Quelle est la classification ? (TP, FP, ou BTP)",
            "answer": "BTP",
            "flag": "FLAG{BTP}",
            "points": 40,
            "max_attempts": 2,
            "hints": [
                "Vérifiez s'il existe un ticket de changement associé",
                "Le changement est fait par l'admin légitime, approuvé par le RSSI"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Quelle alerte doit être investiguée EN PREMIER ? (donnez le numéro #)",
            "answer": "3",
            "flag": "FLAG{3}",
            "points": 50,
            "hints": [
                "Quelle alerte a la plus haute sévérité ET le plus grand impact potentiel ?",
                "Mimikatz sur un Domain Controller = compromission de tout le domaine AD"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "Les alertes #1 et #5 semblent liées. Quel est l'élément commun qui les relie ?",
            "answer": "10.0.3.45",
            "flag": "FLAG{10.0.3.45}",
            "points": 50,
            "hints": [
                "Comparez les machines sources des deux alertes",
                "L'alerte #5 mentionne que PsExec a été lancé depuis l'IP de WKS-COMPTA-PC03"
            ],
            "hint_cost": 17
        },
        {
            "id": "q7",
            "text": "Dans l'alerte #4 (Tor), quel ratio upload/download suggère une exfiltration de données ?",
            "answer": "15:1",
            "flag": "FLAG{15:1}",
            "points": 40,
            "hints": [
                "Regardez les volumes de données dans l'alerte #4",
                "2.3 MB envoyés vs 156 KB reçus"
            ],
            "hint_cost": 13
        }
    ]
}
