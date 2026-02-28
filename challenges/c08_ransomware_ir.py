"""
Challenge 8 — Réponse à Incident Ransomware
Niveau : 3 (Analyste Senior)
Catégorie : Incident Response
"""

ARTIFACT_RANSOM_NOTE = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║              ██████╗ ██╗  ██╗ ██████╗ ███╗   ██╗            ║
║              ██╔══██╗██║  ██║██╔═══██╗████╗  ██║            ║
║              ██████╔╝███████║██║   ██║██╔██╗ ██║            ║
║              ██╔═══╝ ██╔══██║██║   ██║██║╚██╗██║            ║
║              ██║     ██║  ██║╚██████╔╝██║ ╚████║            ║
║              ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝            ║
║                                                              ║
║                  YOUR FILES ARE ENCRYPTED                    ║
║                                                              ║
╠══════════════════════════════════════════════════════════════╣
║                                                              ║
║  All your important files have been encrypted with           ║
║  military-grade AES-256 + RSA-4096 encryption.              ║
║                                                              ║
║  WHAT HAPPENED?                                              ║
║  Your network has been compromised. All files on:            ║
║  - SRV-FILE-02 (File Server)                                ║
║  - SRV-DB-01 (Database Server)                              ║
║  - SRV-BACKUP-01 (Backup Server — yes, those too)           ║
║  have been encrypted with extension .ph0n                    ║
║                                                              ║
║  HOW TO RECOVER?                                             ║
║  1. Send 5 BTC to: bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh ║
║  2. Email proof to: ph0n-support@protonmail.com              ║
║  3. Receive decryption key within 24h                        ║
║                                                              ║
║  WARNING:                                                    ║
║  - Price doubles after 72 hours                              ║
║  - Files deleted after 7 days                                ║
║  - Do NOT contact law enforcement                            ║
║  - Do NOT try to decrypt yourself                            ║
║                                                              ║
║  PROOF: We can decrypt 2 files for free.                     ║
║  Send them to the email above.                               ║
║                                                              ║
║  Unique ID: RPWN-2026-0218-A7F3B2C1                         ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""

ARTIFACT_TIMELINE = r"""
=== TIMELINE DE L'INCIDENT — Reconstitution forensic ===
=== Analyste: [VOTRE NOM] — Date: 18/02/2026 ===
=== Classification: CONFIDENTIEL — TLP:AMBER ===
=== Référence Incident: INC-2026-0218-001 ===

────────────────────────────────────────────────────────────
  PHASE 1 — INITIAL ACCESS (T-7 jours)
────────────────────────────────────────────────────────────

[T-7 jours] 11/02/2026 09:00 UTC
  Source: Windows Update — SRV-AD-01
  Event: Windows Update KB5034441 installée
  Detail: Mise à jour cumulative mensuelle (planifiée)
  Status: LÉGITIME — Maintenance planifiée

[T-7 jours] 11/02/2026 10:30 UTC
  Source: Email Gateway
  Event: 47 emails entrants traités normalement
  Detail: Trafic email normal, 3 emails avec PJ Office bloqués par sandbox (faux positifs)
  Status: LÉGITIME — Opération normale

[T-7 jours] 11/02/2026 14:23 UTC
  Source: Email Gateway (ProofPoint)
  Event: Email de phishing reçu par j.martin@redpawn-corp.com
  Detail: Pièce jointe "Facture_Fevrier2026.xlsm" (macro malveillante)
  Sender: facturation@redpawn-c0rp.com (typosquatting: o→0)
  Headers: X-Mailer: Microsoft Outlook 16.0 (spoofé)
  SPF: SOFTFAIL (domaine c0rp.com n'a pas de record SPF)
  DKIM: NONE
  DMARC: NONE (pas de politique pour c0rp.com)
  ProofPoint Score: 42/100 (sous le seuil de 65 = non bloqué)
  *** CRITIQUE: Email non bloqué car score insuffisant ***

[T-7 jours] 11/02/2026 14:28 UTC
  Source: Proxy — WKS-COMPTA-PC03
  Event: Accès normal à SharePoint et OneDrive par j.martin
  Detail: Téléchargement de fichiers Excel légitimes (budget Q1)
  Status: LÉGITIME — Activité normale de comptabilité

[T-7 jours] 11/02/2026 14:31 UTC
  Source: EDR (CrowdStrike) — WKS-COMPTA-PC03
  Event: EXCEL.EXE (PID:4120) → cmd.exe (PID:6732) → powershell.exe (PID:7844)
  Detail: Macro VBA Auto_Open exécutée — téléchargement du stage 1
  IOC: hxxp://185.234.72[.]19:8080/stager.ps1
  SHA256_macro: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  CrowdStrike Alert: SuspiciousOfficeChildProcess — Severity: HIGH
  *** CrowdStrike en mode DETECT-ONLY (pas de blocage) ***

[T-7 jours] 11/02/2026 14:33 UTC
  Source: Proxy (Zscaler) — WKS-COMPTA-PC03
  Event: Connexion HTTP sortante vers 185.234.72.19:8080
  Detail: GET /stager.ps1 — User-Agent: "Mozilla/5.0 (compatible)"
  Response: 200 OK, Content-Length: 4832 bytes
  Category: Uncategorized (pas encore dans base de réputation)

[T-7 jours] 11/02/2026 14:35 UTC
  Source: EDR — WKS-COMPTA-PC03
  Event: Persistence établie via registre Run
  Detail: HKCU\...\CurrentVersion\Run\GoogleChromeAutoUpdate → update_checker.ps1
  IOC: C:\Users\j.martin\AppData\Local\Temp\update_checker.ps1

[T-7 jours] 11/02/2026 17:00 UTC
  Source: EDR — WKS-COMPTA-PC03
  Event: CrowdStrike weekly scan completed
  Detail: 0 malware détecté (update_checker.ps1 non flagged — obfuscation)
  Status: FAUX NÉGATIF — Script obfusqué non détecté par signatures

────────────────────────────────────────────────────────────
  PHASE 2 — C2 & RECONNAISSANCE (T-5 à T-3 jours)
────────────────────────────────────────────────────────────

[T-6 jours] 12/02/2026 06:00 UTC
  Source: Scheduled Tasks — SRV-BACKUP-01
  Event: Backup quotidien Veeam exécuté normalement
  Detail: Job "Daily-Full-Backup" — Duration: 2h14m — 847 GB sauvegardés
  Status: LÉGITIME — Backup planifié

[T-6 jours] 12/02/2026 08:30 UTC
  Source: SIEM (Splunk)
  Event: 12 alertes basse priorité générées (noise)
  Detail: Failed logons (policy lockout), antivirus updates, certificate renewal
  Status: LÉGITIME — Bruit opérationnel normal

[T-5 jours] 13/02/2026 02:15 UTC
  Source: DNS Logs (Infoblox)
  Event: Première exfiltration DNS depuis WKS-COMPTA-PC03
  Detail: 47 requêtes TXT vers *.data.c2-update-service[.]xyz en 28 secondes
  IOC: c2-update-service[.]xyz (registré le 05/02/2026 via Njalla)
  Volume: Reconnaissance système (hostname, username, OS, domaine, IP)

[T-5 jours] 13/02/2026 06:00 UTC
  Source: Scheduled Tasks — SRV-BACKUP-01
  Event: Backup Veeam quotidien — succès
  Status: LÉGITIME

[T-4 jours] 14/02/2026 03:00 UTC
  Source: SIEM
  Event: Scan de vulnérabilité Nessus planifié (mensuel)
  Detail: Scan réseau 10.0.0.0/8 — 1247 hosts scannés — 23 critiques trouvées
  Status: LÉGITIME — Scan de conformité planifié

[T-4 jours] 14/02/2026 09:15 UTC
  Source: DNS Logs
  Event: Requêtes DNS inhabituelles depuis WKS-COMPTA-PC03
  Detail: Résolution de noms de domaines internes (SRV-AD-01, SRV-FILE-02, SRV-DB-01)
  *** Reconnaissance Active Directory par l'attaquant ***

[T-3 jours] 15/02/2026 06:00 UTC
  Source: Scheduled Tasks — SRV-BACKUP-01
  Event: Backup Veeam quotidien — succès
  Status: LÉGITIME

[T-3 jours] 15/02/2026 22:00 UTC
  Source: DNS Logs
  Event: Exfiltration de credentials via DNS tunneling
  Detail: 156 requêtes TXT en 3 minutes — volume anormal
  Data encoded: Mots de passe DB (hr_portal), MySQL root, VPN PSK, API keys
  Impact: 6 sets de credentials compromis

[T-2 jours] 16/02/2026 08:00 UTC
  Source: Active Directory — SRV-AD-01
  Event: Changement de mot de passe j.martin (politique 90 jours expirée)
  Detail: Changement automatique selon GPO — nouveau MDP conforme
  Status: LÉGITIME — Rotation normale

[T-2 jours] 16/02/2026 14:00 UTC
  Source: Proxy — WKS-COMPTA-PC03
  Event: Connexion HTTPS vers checkip.amazonaws.com
  Detail: L'attaquant vérifie l'IP publique de l'organisation
  *** Reconnaissance réseau externe ***

[T-1 jour] 17/02/2026 03:30 UTC
  Source: DNS Logs
  Event: Nouvelle salve d'exfiltration DNS
  Detail: 89 requêtes TXT — exfiltration de la topologie réseau
  Data: Routes, sous-réseaux, noms de serveurs, partages réseau

[T-1 jour] 17/02/2026 06:00 UTC
  Source: Scheduled Tasks — SRV-BACKUP-01
  Event: Backup Veeam quotidien — succès
  Detail: Job "Daily-Full-Backup" — 851 GB — dernier backup sain avant l'attaque
  *** DERNIER BACKUP VALIDE (RPO) ***

────────────────────────────────────────────────────────────
  PHASE 3 — LATERAL MOVEMENT & ESCALATION (T-0)
────────────────────────────────────────────────────────────

[T-0] 18/02/2026 06:00 UTC
  Source: Scheduled Tasks — SRV-BACKUP-01
  Event: Backup Veeam quotidien — DÉMARRÉ normalement
  Status: LÉGITIME (sera interrompu par le chiffrement)

[T-0] 18/02/2026 07:30 UTC
  Source: VPN Gateway
  Event: Connexion VPN de admin.rsi depuis son domicile (IP: 82.64.xxx.xxx)
  Detail: Authentification MFA réussie — session maintenance planifiée
  Status: LÉGITIME

[T-0] 18/02/2026 08:15 UTC
  Source: SIEM (corr. Firewall + IDS)
  Event: Brute force SSH sur SRV-WEB-01 depuis 10.0.3.45
  Detail: 47 tentatives en 3 minutes (root, admin, www-data, deploy, ubuntu)
  IDS Alert: ET SCAN SSH BruteForce (sid:2001219) — 6 fois
  *** Source: WKS-COMPTA-PC03 (10.0.3.45) — machine déjà compromise ***

[T-0] 18/02/2026 08:22 UTC
  Source: EDR — SRV-WEB-01
  Event: Webshell cmd.php accédé depuis 10.0.3.45
  Detail: POST /uploads/cmd.php — RCE via passthru()
  *** Le webshell avait été uploadé lors du scan initial (c04) ***

[T-0] 18/02/2026 08:33 UTC
  Source: Windows Events — SRV-AD-01
  Event: Mouvement latéral vers le Domain Controller
  Detail: Logon Type 3 (NTLM) — svc-backup depuis 10.0.3.45 (IP anormale)
  Séquence: svc-backup → Mimikatz (sekurlsa::logonpasswords) → admin.rsi hash
  *** admin.rsi légitime est connecté en VPN MAIS le hash est utilisé pass-the-hash ***

[T-0] 18/02/2026 08:37 UTC
  Source: Sysmon — SRV-AD-01
  Event: d3d11.dll chargée dans lsass.exe (credential dumping)
  Detail: SHA256: a1b2c3d4e5f6...

[T-0] 18/02/2026 08:42 UTC
  Source: Windows Events — SRV-AD-01
  Event: Extraction NTDS.dit via ntdsutil IFM
  Detail: ntdsutil "ac i ntds" "ifm" "create full C:\Windows\Temp\dump" q q
  Files: ntds.dit (47 MB) + SYSTEM hive (12 MB)
  Impact: Hashes de 342 comptes du domaine compromis

[T-0] 18/02/2026 08:45 UTC
  Source: Windows Events — SRV-AD-01
  Event: Compte backdoor créé: support_it
  Detail: net user support_it P@ssw0rd2026! /add /domain
          net group "Domain Admins" support_it /add
  *** Compte avec privilèges maximaux ***

[T-0] 18/02/2026 08:50 UTC
  Source: EDR — SRV-AD-01
  Event: csvde.exe -f C:\Windows\Temp\ad_export.csv
  Detail: Export complet de l'annuaire AD (342 comptes, 89 groupes, 12 OUs)
  *** LOLBin — outil légitime Microsoft utilisé malicieusement ***

[T-0] 18/02/2026 09:00 UTC
  Source: SIEM
  Event: Alerte "Anomaly: Unusual RDP connections" — admin.rsi
  Detail: RDP vers SRV-FILE-02 et SRV-DB-01 depuis SRV-AD-01
  *** admin.rsi n'a jamais fait de RDP inter-serveurs auparavant ***
  *** ALERTE IGNORÉE par l'analyste N1 (classée comme faux positif) ***

[T-0] 18/02/2026 10:00 UTC
  Source: Firewall (Palo Alto)
  Event: Exfiltration massive via Tor
  Detail: 
    - Source: WKS-RH-PC01 (10.0.5.15) — pas la machine initiale!
    - Protocol: TCP/9001 (Tor guard node)
    - Dest: 185.220.101.34 (Known Tor exit — Tor Project)
    - Volume: 63.4 MB uploadés / 4.2 MB reçus (ratio 15:1)
    - Duration: 34 minutes
  *** L'attaquant a pivoté vers WKS-RH-PC01 pour l'exfiltration ***
  *** Contenu probable: ntds.dit + ad_export.csv + credentials ***

[T-0] 18/02/2026 10:15 UTC
  Source: VPN Gateway
  Event: Déconnexion VPN de admin.rsi (session maintenance terminée)
  Status: LÉGITIME — mais session compromise simultanément

────────────────────────────────────────────────────────────
  PHASE 4 — RANSOMWARE DEPLOYMENT (T-0)
────────────────────────────────────────────────────────────

[T-0] 18/02/2026 11:15 UTC
  Source: EDR — SRV-AD-01
  Event: outil PsExec uploadé sur C:\Windows\Temp\
  Detail: SHA256: 27304b246c7d5b4e149124d5f93c5b01e04e93c97e49c1dcb82be0e0b28b0554
  Signé: Microsoft Sysinternals (outil légitime, usage malveillant)

[T-0] 18/02/2026 11:22 UTC
  Source: Firewall
  Event: Connexions SMB (TCP/445) depuis SRV-AD-01 → SRV-FILE-02, SRV-DB-01, SRV-BACKUP-01
  Detail: Transfert de ransomware.exe via partage Admin$ (C$)
  IOC ransomware: SHA256: 8f14e45fceea167a5a36dedd4bea254304b8e5b05e4a3b9e8a7d3f6c8b5a1d2e
  Taille: 2,847,744 bytes (2.7 MB)
  Compilation: 10/02/2026 22:14:33 UTC (compilé 1 jour avant l'envoi du phishing)

[T-0] 18/02/2026 11:25 UTC
  Source: EDR — SRV-FILE-02
  Event: PsExec exécution à distance — compte support_it
  Command: psexec \\SRV-FILE-02 -u REDPAWN\support_it -p P@ssw0rd2026! -c ransomware.exe
  CrowdStrike: Alert "RansomwareFileModification" — Severity CRITICAL
  *** ENCORE EN DETECT-ONLY — PAS DE BLOCAGE ***

[T-0] 18/02/2026 11:26 UTC
  Source: EDR — SRV-DB-01
  Event: PsExec exécution sur SRV-DB-01
  Detail: ransomware.exe — chiffrement démarré

[T-0] 18/02/2026 11:27 UTC
  Source: EDR — SRV-BACKUP-01
  Event: PsExec exécution sur SRV-BACKUP-01
  Detail: ransomware.exe — chiffrement des backups Veeam
  *** BACKUP VEEAM QUOTIDIEN (06:00) INTERROMPU ET CHIFFRÉ ***
  *** Pas de copie hors-site (air-gapped) des backups ***

[T-0] 18/02/2026 11:28 UTC
  Source: EDR — Multiple
  Event: Suppression des shadow copies sur les 3 serveurs
  Command: vssadmin delete shadows /all /quiet
  *** Empêche la restauration via Volume Shadow Copy ***

[T-0] 18/02/2026 11:30 UTC
  Source: EDR — Multiple servers
  Event: Chiffrement en cours — fichiers renommés en .ph0n
  Detail: 
    - SRV-FILE-02: 47,832 fichiers chiffrés (312 GB)
    - SRV-DB-01: 1,247 fichiers chiffrés (89 GB), dont bases MySQL et backups SQL
    - SRV-BACKUP-01: 2,341 fichiers chiffrés (847 GB), dont Veeam .vbk et .vib
  IOC: Extension .ph0n, ransom note "README_RESTORE.txt" dans chaque répertoire
  Vitesse: ~1.2 GB/min par serveur (disques SSD NVMe)

────────────────────────────────────────────────────────────
  PHASE 5 — DETECTION & RESPONSE
────────────────────────────────────────────────────────────

[T-0] 18/02/2026 11:42 UTC
  Source: Monitoring Zabbix
  Event: Alerte performance critique — SRV-FILE-02 CPU 100%, I/O saturé
  Detail: Processus ransomware.exe consomme toutes les ressources
  Status: Alerte envoyée à l'équipe infra (pas au SOC)

[T-0] 18/02/2026 11:45 UTC
  Source: Helpdesk (ServiceNow)
  Event: 3 tickets ouverts en 3 minutes
  Detail: 
    - INC0012847: "Mes fichiers ont une extension bizarre .ph0n" — m.petit
    - INC0012848: "Lecteur S:\ inaccessible, fichiers corrompus" — a.bernard
    - INC0012849: "Message effrayant sur mon bureau" — l.mercier

[T-0] 18/02/2026 11:52 UTC
  Source: SOC — Analyste N1
  Event: Corrélation des tickets helpdesk + alertes EDR
  Detail: L'analyste N1 fait le lien entre les tickets et les alertes CrowdStrike

[T-0] 18/02/2026 12:00 UTC
  Source: SOC — SOC Manager
  Event: Incident déclaré — Sévérité P1 — RANSOMWARE
  Detail: Activation du plan IR — CERT ANSSI notifié
  Actions immédiates:
    - Isolement réseau de SRV-FILE-02, SRV-DB-01, SRV-BACKUP-01
    - Blocage de 185.234.72.19 et c2-update-service.xyz sur firewall
    - Isolement de WKS-COMPTA-PC03 et WKS-RH-PC01
    - Désactivation du compte support_it
    - Capture mémoire des serveurs chiffrés
    - Notification au DPO (données RH potentiellement exfiltrées)

[T-0] 18/02/2026 12:15 UTC
  Source: RSSI
  Event: Cellule de crise activée — COMEX informé
  Decision: PAS de paiement de rançon (politique groupe)
  Decision: Notification CNIL dans les 72h (données personnelles RH)
  Decision: Communication interne restreinte (TLP:AMBER)

[T-0] 18/02/2026 14:00 UTC
  Source: CERT
  Event: Analyse forensique démarrée
  Detail: Images disques en cours d'acquisition
  Constat: Dernier backup sain = 17/02 06:00 (T-1 jour)
  RPO effectif: 29 heures de données perdues
"""

ARTIFACT_DISK_FORENSICS = r"""
=== RAPPORT D'ANALYSE FORENSIQUE DISQUE ===
=== Serveur: SRV-FILE-02 — Image: SRV-FILE-02.E01 ===
=== Outil: Autopsy 4.21 + Sleuth Kit ===
=== Date acquisition: 18/02/2026 13:15 UTC ===
=== Hash image MD5: a4f2c8e1b3d5f6a7c9e0b2d4f6a8c1e3 ===

───────── ANALYSE MFT (Master File Table) ─────────

Fichiers créés le 18/02/2026 (filtrés, triés par heure):

06:00:12  C:\Windows\System32\Tasks\VeeamBackup              [LÉGITIME — tâche Veeam]
06:00:14  D:\Backups\Daily\2026-02-18_full.vbk                [LÉGITIME — backup quotidien]
07:15:33  C:\Windows\Temp\WindowsUpdate.log                   [LÉGITIME — Windows Update]
08:47:22  C:\Windows\Temp\svchost_update.dll                  [SUSPECT — nom trompeur]
11:15:01  C:\Windows\Temp\PsExec.exe                          [MALVEILLANT — outil de déploiement]
11:15:03  C:\Windows\Temp\ransomware.exe                      [MALVEILLANT — payload ransomware]
11:25:04  C:\Windows\Temp\YOURFILES.bat                       [MALVEILLANT — script de chiffrement]
11:25:05  D:\Partage\Comptabilite\README_RESTORE.txt          [MALVEILLANT — ransom note]
11:25:05  D:\Partage\RH\README_RESTORE.txt                    [MALVEILLANT — ransom note]
11:25:06  D:\Partage\Direction\README_RESTORE.txt             [MALVEILLANT — ransom note]
11:25:06  D:\Partage\IT\README_RESTORE.txt                    [MALVEILLANT — ransom note]
11:28:02  C:\Windows\Temp\vss_cleanup.bat                     [MALVEILLANT — suppression VSS]

Fichiers supprimés récupérés (carving):
11:26:44  D:\Partage\Comptabilite\Budget_2026_Q1.xlsx         [SUPPRIMÉ puis recréé en .ph0n]
11:26:45  D:\Partage\RH\Salaires_Fevrier2026.pdf              [SUPPRIMÉ puis recréé en .ph0n]
11:26:47  D:\Partage\RH\Contrats\CDI_dupont_jean.pdf          [SUPPRIMÉ puis recréé en .ph0n]

───────── ANALYSE PREFETCH ─────────

Prefetch files (C:\Windows\Prefetch\):

PSEXESVC.EXE-A3F2B1C4.pf
  - First run: 18/02/2026 11:25:01 UTC
  - Last run:  18/02/2026 11:25:01 UTC
  - Run count: 1
  - Files loaded: C:\Windows\Temp\PsExec.exe
  - Note: PsExec service-side (déployé par PsExec depuis SRV-AD-01)

RANSOMWARE.EXE-D4E5F6A7.pf
  - First run: 18/02/2026 11:25:04 UTC
  - Last run:  18/02/2026 11:25:04 UTC
  - Run count: 1
  - Files loaded: 
    * C:\Windows\Temp\ransomware.exe
    * C:\Windows\System32\bcrypt.dll         (bibliothèque crypto Windows)
    * C:\Windows\System32\ncrypt.dll         (bibliothèque crypto native)
    * C:\Windows\System32\advapi32.dll       (API crypto avancée)
  - Volume: D:\ (Partage)

VSSADMIN.EXE-8B12C3D4.pf
  - First run: 18/02/2026 11:28:02 UTC
  - Last run:  18/02/2026 11:28:02 UTC
  - Run count: 1
  - Note: Suppression des shadow copies

CMD.EXE-AC113AA8.pf
  - Last run: 18/02/2026 11:28:02 UTC
  - Run count: 847       (utilisation normale + malveillante — difficile à distinguer)

SCHTASKS.EXE-1F34B2C1.pf
  - First run: 06/01/2026 08:00:00 UTC (ancien usage légitime)
  - Last run:  18/02/2026 11:24:58 UTC  (*** suspecte — juste avant PsExec)
  - Run count: 12

───────── REGISTRE — Run Keys ─────────

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run:
  - VeeamAgent          = "C:\Program Files\Veeam\Agent\VeeamAgent.exe"          [LÉGITIME]
  - SecurityHealthSystray = "C:\Windows\System32\SecurityHealthSystray.exe"      [LÉGITIME]
  - CrowdStrike         = "C:\Program Files\CrowdStrike\CSFalconService.exe"     [LÉGITIME]

HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce:
  ** VIDE ** (nettoyé après chiffrement?)

HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon:
  - Userinit = "C:\Windows\System32\userinit.exe,"                               [LÉGITIME]
  - Shell    = "explorer.exe"                                                    [LÉGITIME]

───────── SRUM DATABASE (System Resource Usage Monitor) ─────────

Application Resource Usage — 18/02/2026:

  ransomware.exe (SID: S-1-5-21-...-support_it)
    - CPU Time: 847 seconds
    - Bytes Read:  348,127,445,082  (324 GB — lecture de tous les fichiers)
    - Bytes Written: 337,892,156,928  (315 GB — écriture fichiers chiffrés)
    - Network Sent: 0 bytes
    - Network Recv: 0 bytes
    - Foreground: No
    - Start Time: 11:25:04
    - Note: RATIO READ/WRITE ~1:1 confirme chiffrement (lecture→chiffrement→écriture)

  PsExeSvc.exe (SID: S-1-5-18 SYSTEM)
    - CPU Time: 3 seconds
    - Network Sent: 2,847,744 bytes (ransomware.exe transfert)
    - Start Time: 11:25:01

───────── AMCACHE ─────────

AmCache entries (C:\Windows\AppCompat\Programs\Amcache.hve):

  ransomware.exe:
    - SHA256: 8f14e45fceea167a5a36dedd4bea254304b8e5b05e4a3b9e8a7d3f6c8b5a1d2e
    - Size: 2,847,744 bytes
    - CompileTime: 10/02/2026 22:14:33 UTC
    - Publisher: (none — non signé)
    - OriginalFilename: crypt0r.exe     *** NOM ORIGINAL DU MALWARE ***
    - ProductName: (none)
    - FileVersion: 1.3.7

  PsExec.exe:
    - SHA256: 27304b246c7d5b4e149124d5f93c5b01e04e93c97e49c1dcb82be0e0b28b0554
    - Publisher: Microsoft Corporation — Sysinternals
    - OriginalFilename: PsExec.exe
    - ProductName: Sysinternals PsExec
    - FileVersion: 2.43
"""

ARTIFACT_NETWORK_FORENSICS = r"""
=== ANALYSE RÉSEAU — FIREWALL & IDS ===
=== Source: Palo Alto PA-5260 + Suricata IDS ===
=== Période: 18/02/2026 08:00 — 12:30 UTC ===

───────── FIREWALL LOGS (extraits pertinents) ─────────

# Trafic légitime normal (contexte / bruit)
08:01:22 ALLOW TCP 10.0.4.10 → 10.0.1.10:3389  (admin.rsi VPN → SRV-AD-01 RDP) [LÉGITIME]
08:02:15 ALLOW TCP 10.0.4.10 → 10.0.1.20:445   (admin.rsi → SRV-FILE-02 SMB) [LÉGITIME]
08:05:33 ALLOW TCP 10.0.5.22 → 10.0.2.80:443   (WKS-DEV-01 → GitLab HTTPS) [LÉGITIME]
08:10:14 ALLOW UDP 10.0.1.10 → 10.0.1.5:53     (SRV-AD-01 → DNS interne) [LÉGITIME]

# Reconnaissance et brute force
08:15:01 ALLOW TCP 10.0.3.45 → 10.0.2.50:22    (WKS-COMPTA-PC03 → SRV-WEB-01 SSH)
08:15:02 ALLOW TCP 10.0.3.45 → 10.0.2.50:22    (tentative #2)
08:15:03 ALLOW TCP 10.0.3.45 → 10.0.2.50:22    (tentative #3)
... (47 tentatives en 3 minutes)
08:18:01 ALLOW TCP 10.0.3.45 → 10.0.2.50:22    (tentative #47 — dernier échec)

# Exploitation webshell
08:22:15 ALLOW TCP 10.0.3.45 → 10.0.2.50:80    (accès webshell cmd.php)
08:22:18 ALLOW TCP 10.0.3.45 → 10.0.2.50:80    (commande RCE)
08:22:45 ALLOW TCP 10.0.3.45 → 10.0.2.50:80    (commande RCE)

# Trafic légitime intercalé
08:25:00 ALLOW TCP 10.0.5.15 → 104.16.xx.xx:443  (WKS-RH-PC01 → Office365) [LÉGITIME]
08:27:33 ALLOW TCP 10.0.4.10 → 10.0.1.10:88    (admin.rsi → Kerberos auth) [LÉGITIME]
08:30:12 ALLOW UDP 10.0.0.0/8 → 10.0.1.5:53    (DNS broadcast normal) [LÉGITIME]

# Mouvement latéral vers DC
08:33:01 ALLOW TCP 10.0.3.45 → 10.0.1.10:445   (SMB vers SRV-AD-01) [MALVEILLANT]
08:33:02 ALLOW TCP 10.0.3.45 → 10.0.1.10:135   (RPC vers SRV-AD-01) [MALVEILLANT]
08:33:05 ALLOW TCP 10.0.3.45 → 10.0.1.10:389   (LDAP vers SRV-AD-01) [MALVEILLANT]

# Exfiltration Tor
09:26:00 ALLOW TCP 10.0.5.15 → 185.220.101.34:9001  (Tor guard node) [MALVEILLANT]
09:26:01 ALLOW TCP 10.0.5.15 → 185.220.101.34:9001
... (session Tor maintenue 34 minutes)
10:00:00 CLOSE TCP 10.0.5.15 → 185.220.101.34:9001

# Trafic légitime intercalé pendant exfiltration
09:30:00 ALLOW TCP 10.0.5.22 → 10.0.2.80:443   (GitLab) [LÉGITIME]
09:45:12 ALLOW TCP 10.0.3.50 → 10.0.2.50:443   (navigation interne) [LÉGITIME]

# Déploiement ransomware via PsExec (SMB latéral)
11:22:01 ALLOW TCP 10.0.1.10 → 10.0.1.20:445   (SRV-AD-01 → SRV-FILE-02 SMB) [MALVEILLANT]
11:22:02 ALLOW TCP 10.0.1.10 → 10.0.1.25:445   (SRV-AD-01 → SRV-DB-01 SMB) [MALVEILLANT]
11:22:03 ALLOW TCP 10.0.1.10 → 10.0.1.30:445   (SRV-AD-01 → SRV-BACKUP-01 SMB) [MALVEILLANT]

# Aucune connexion sortante de ransomware.exe (chiffrement offline)
# => Le ransomware ne communique PAS avec un C2 pendant le chiffrement

───────── SURICATA IDS ALERTS ─────────

02/18/2026-08:15:03  [**] [1:2001219:20] ET SCAN Potential SSH Brute Force [**]
  [Classification: Attempted Administrator Privilege Gain] [Priority: 1]
  {TCP} 10.0.3.45:49832 -> 10.0.2.50:22
  Alert count: 6 (rate-based rule)

02/18/2026-08:22:15  [**] [1:2024897:4] ET WEB_SERVER Possible PHP Webshell Activity [**]
  [Classification: Web Application Attack] [Priority: 1]
  {TCP} 10.0.3.45:50123 -> 10.0.2.50:80

02/18/2026-08:33:02  [**] [1:2013926:5] ET POLICY SMB2 NT Create AndX Request For an Exe File [**]
  [Classification: Potential Corporate Privacy Violation] [Priority: 1]
  {TCP} 10.0.3.45:51234 -> 10.0.1.10:445

02/18/2026-09:26:00  [**] [1:2522918:3] ET POLICY Tor Known Guard/Authority Node Traffic [**]
  [Classification: Potential Corporate Privacy Violation] [Priority: 2]
  {TCP} 10.0.5.15:52345 -> 185.220.101.34:9001

02/18/2026-09:26:02  [**] [1:2025543:5] ET POLICY TLS SNI for Tor Guard Node [**]
  [Classification: Potential Corporate Privacy Violation] [Priority: 2]
  {TCP} 10.0.5.15:52345 -> 185.220.101.34:9001

02/18/2026-11:22:01  [**] [1:2013926:5] ET POLICY SMB2 NT Create AndX Request For an Exe File [**]
  [Classification: Potential Corporate Privacy Violation] [Priority: 1]
  {TCP} 10.0.1.10:53456 -> 10.0.1.20:445
  *** Transfert de ransomware.exe via SMB Admin$ ***

02/18/2026-11:25:05  [**] [1:2845517:2] ET RANSOMWARE Known Ransomware File Extension (.ph0n) [**]
  [Classification: A Network Trojan was detected] [Priority: 1]
  {SMB} SRV-FILE-02 local

02/18/2026-11:28:02  [**] [1:2019935:3] ET POLICY vssadmin Delete Shadows [**]
  [Classification: Potentially Bad Traffic] [Priority: 2]
  {local} SRV-FILE-02

───────── NETFLOW SUMMARY (Top talkers 08:00-12:00) ─────────

Source IP        Dest IP          Port   Proto  Bytes      Sessions  Notes
10.0.5.15        185.220.101.34   9001   TCP    66,528,256  1        Tor exfil (63.4MB up)
10.0.1.10        10.0.1.20        445    TCP    3,012,480   12       PsExec + ransomware
10.0.1.10        10.0.1.25        445    TCP    2,998,144   8        PsExec + ransomware
10.0.1.10        10.0.1.30        445    TCP    2,995,712   6        PsExec + ransomware
10.0.3.45        10.0.2.50        22     TCP    47,832      47       SSH brute force
10.0.3.45        10.0.2.50        80     TCP    12,456      5        Webshell
10.0.3.45        10.0.1.10        445    TCP    456,789     3        Lateral movement
10.0.4.10        10.0.1.10        3389   TCP    2,345,678   1        admin.rsi RDP [LÉGITIME]
10.0.5.22        10.0.2.80        443    TCP    1,234,567   14       GitLab [LÉGITIME]
"""

CHALLENGE = {
    "id": "c08_ransomware_ir",
    "title": "🚨 Code Rouge : Ransomware",
    "category": "incident_response",
    "level": 3,
    "points_total": 620,
    "estimated_time": "50-75 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 16h30  
**Priorité :** CRITIQUE — P1  
**Source :** Incident Response — Ransomware en cours

---

**SITUATION :** L'entreprise RedPawn Corp est sous attaque ransomware active. Trois serveurs ont été chiffrés. Le CERT a été activé et vous participez à la cellule de crise.

Vous avez accès à la note de rançon, à la timeline reconstituée, à l'analyse forensique disque et aux logs réseau de l'incident.

> *"Situation de crise. On a du ransomware sur 3 serveurs. Le COMEX veut des réponses : comment on s'est fait avoir, quel est l'impact réel, pourquoi nos défenses ont échoué, et quelles sont les actions immédiates. Tu as la timeline complète, la ransom note, l'analyse disque forensique et les logs réseau. Je veux une analyse complète avec les IoC, le TTPs, et une estimation du RPO."*

**Contexte d'équipe :** La timeline a été reconstituée grâce aux investigations des challenges précédents. Vous devez maintenant avoir une vision globale de bout en bout et identifier les défaillances de détection.

<details>
<summary>💡 Indice méthodologique (cliquez pour afficher)</summary>

Croisez les sources : la timeline donne la chronologie, le forensique disque donne les preuves matérielles, et les logs réseau montrent les flux. Cherchez les incohérences et les points de défaillance dans la chaîne de détection.

</details>
    """,
    "artifacts": [
        {
            "name": "README_RESTORE.txt",
            "type": "ransom_note",
            "content": ARTIFACT_RANSOM_NOTE,
            "description": "Note de rançon trouvée sur les serveurs chiffrés"
        },
        {
            "name": "incident_timeline.txt",
            "type": "timeline",
            "content": ARTIFACT_TIMELINE,
            "description": "Timeline complète de l'incident (phases 1-5)"
        },
        {
            "name": "disk_forensics_SRV-FILE-02.txt",
            "type": "forensics",
            "content": ARTIFACT_DISK_FORENSICS,
            "description": "Analyse forensique du disque SRV-FILE-02 (MFT, Prefetch, Registre, SRUM, AmCache)"
        },
        {
            "name": "network_forensics.txt",
            "type": "network",
            "content": ARTIFACT_NETWORK_FORENSICS,
            "description": "Logs Firewall Palo Alto + alertes Suricata IDS + NetFlow"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quel était le nom original du binaire ransomware avant qu'il soit renommé ? (visible dans l'AmCache)",
            "answer": "crypt0r.exe",
            "flag": "REDPAWN{crypt0r.exe}",
            "points": 50,
            "hints": [
                "L'AmCache enregistre le OriginalFilename du PE header",
                "Cherchez dans la section AmCache du rapport forensique"
            ],
            "hint_cost": 17
        },
        {
            "id": "q2",
            "text": "Combien de jours se sont écoulés entre la compromission initiale et le déploiement du ransomware (dwell time) ?",
            "answer": "7",
            "flag": "REDPAWN{7}",
            "points": 30,
            "hints": [
                "La compromission initiale est le 11/02, le ransomware le 18/02"
            ],
            "hint_cost": 10
        },
        {
            "id": "q3",
            "text": "Pourquoi CrowdStrike n'a-t-il PAS bloqué l'exécution du ransomware malgré la détection ?",
            "answer": "mode detect-only",
            "flag": "REDPAWN{detect-only}",
            "points": 50,
            "hints": [
                "Cherchez les mentions CrowdStrike dans la timeline",
                "Regardez la note entre crochets après les alertes CrowdStrike"
            ],
            "hint_cost": 17
        },
        {
            "id": "q4",
            "text": "Quelle est la date et heure du dernier backup Veeam sain (RPO) ? (format: JJ/MM/AAAA HH:MM)",
            "answer": "17/02/2026 06:00",
            "flag": "REDPAWN{17/02/2026 06:00}",
            "points": 40,
            "hints": [
                "Cherchez le dernier backup Veeam réussi AVANT l'attaque",
                "C'est marqué comme 'DERNIER BACKUP VALIDE' dans la timeline"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Quel volume total de données a été exfiltré via Tor (en MB, arrondi) ?",
            "answer": "63",
            "flag": "REDPAWN{63}",
            "points": 40,
            "hints": [
                "Regardez le NetFlow summary pour les connexions Tor",
                "Cherchez le volume en bytes pour l'IP 185.220.101.34"
            ],
            "hint_cost": 13
        },
        {
            "id": "q6",
            "text": "Depuis quelle machine (hostname) l'exfiltration Tor a-t-elle été effectuée ? Ce n'est PAS la machine compromise initiale.",
            "answer": "WKS-RH-PC01",
            "flag": "REDPAWN{WKS-RH-PC01}",
            "points": 40,
            "hints": [
                "L'attaquant a pivoté vers une autre machine pour l'exfiltration",
                "Cherchez l'IP 10.0.5.15 dans la timeline"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Selon le SRUM, combien de GB de données le ransomware a-t-il lu (arrondi à l'entier) ?",
            "answer": "324",
            "flag": "REDPAWN{324}",
            "points": 40,
            "hints": [
                "Le SRUM enregistre les Bytes Read par processus",
                "Convertissez les bytes en GB (÷ 1,073,741,824)"
            ],
            "hint_cost": 13
        },
        {
            "id": "q8",
            "text": "Pourquoi l'email de phishing initial n'a-t-il pas été bloqué par ProofPoint ? (raison technique)",
            "answer": "score insuffisant",
            "flag": "REDPAWN{score_insuffisant}",
            "points": 50,
            "hints": [
                "Regardez le ProofPoint Score dans l'événement T-7 jours",
                "Le score était 42/100, sous le seuil de blocage de 65"
            ],
            "hint_cost": 17
        },
        {
            "id": "q9",
            "text": "Une alerte SOC critique a été ignorée à 09:00. Quel type d'alerte était-ce ?",
            "answer": "Unusual RDP connections",
            "flag": "REDPAWN{unusual_rdp}",
            "points": 50,
            "hints": [
                "Cherchez l'événement de 09:00 UTC dans la timeline",
                "L'analyste N1 l'a classée comme faux positif"
            ],
            "hint_cost": 17
        },
        {
            "id": "q10",
            "text": "Le ransomware a été compilé combien de temps AVANT l'envoi de l'email de phishing ? (en jours)",
            "answer": "1",
            "flag": "REDPAWN{1}",
            "points": 40,
            "hints": [
                "Cherchez CompileTime dans l'AmCache et comparez avec la date du phishing",
                "Compilé le 10/02, phishing envoyé le 11/02"
            ],
            "hint_cost": 13
        },
        {
            "id": "q11",
            "text": "Combien de comptes du domaine Active Directory ont été compromis via le dump NTDS.dit ?",
            "answer": "342",
            "flag": "REDPAWN{342}",
            "points": 30,
            "hints": [
                "Cherchez dans la timeline l'événement NTDS.dit",
                "Le nombre de comptes est mentionné dans l'impact"
            ],
            "hint_cost": 10
        },
        {
            "id": "q12",
            "text": "Quelle commande a été utilisée pour empêcher la restauration via Volume Shadow Copy ?",
            "answer": "vssadmin delete shadows /all /quiet",
            "flag": "REDPAWN{vssadmin_delete_shadows}",
            "points": 40,
            "hints": [
                "Cherchez la suppression des shadow copies dans la timeline",
                "C'est un outil Windows légitime utilisé malicieusement"
            ],
            "hint_cost": 13
        },
        {
            "id": "q13",
            "text": "Combien de fichiers au total ont été chiffrés sur les 3 serveurs ?",
            "answer": "51420",
            "flag": "REDPAWN{51420}",
            "points": 30,
            "hints": [
                "Additionnez les fichiers chiffrés sur SRV-FILE-02, SRV-DB-01 et SRV-BACKUP-01",
                "47832 + 1247 + 2341"
            ],
            "hint_cost": 10
        },
        {
            "id": "q14",
            "text": "Quel est le RPO effectif de l'incident (données perdues) en heures ?",
            "answer": "29",
            "flag": "REDPAWN{29}",
            "points": 40,
            "hints": [
                "RPO = Recovery Point Objective = temps entre le dernier backup sain et l'incident",
                "Dernier backup sain: 17/02 06:00, chiffrement: 18/02 11:00"
            ],
            "hint_cost": 13
        },
        {
            "id": "q15",
            "text": "Selon le Prefetch, quelle bibliothèque crypto Windows le ransomware a-t-il chargé pour le chiffrement ?",
            "answer": "bcrypt.dll",
            "flag": "REDPAWN{bcrypt.dll}",
            "points": 40,
            "hints": [
                "Regardez les 'Files loaded' dans l'analyse Prefetch de ransomware.exe",
                "C'est la première bibliothèque crypto listée"
            ],
            "hint_cost": 13
        }
    ]
}
