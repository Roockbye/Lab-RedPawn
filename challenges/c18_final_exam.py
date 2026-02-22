"""
Challenge 18 — L'Examen Final : Reconstruction complète
Niveau : 5 (Threat Hunter)
Catégorie : Incident Response
"""

ARTIFACT_FINAL = r"""
========== EXAMEN FINAL — RECONSTRUCTION COMPLÈTE ==========
========== Opération PHANTOM CRANE : Clôture ==========
Classification : CONFIDENTIEL
Date : 20/02/2026

Vous devez reconstituer l'intégralité de l'attaque à partir de TOUTES les preuves
collectées pendant l'investigation. Ce document compile les éléments clés.

===== CHRONOLOGIE COMPLÈTE DE L'ATTAQUE =====

JOUR 0 — Préparation (estimé : début février 2026)
  - L'attaquant enregistre le domaine c2-update-service.xyz via NameCheap
  - Configuration de l'infrastructure C2 : 185.234.72.19 (primaire), 91.234.56.78 (exfil)
  - Compilation du malware health_check.exe (timestamp PE : 13/02/2026)
  - Compromission du compte GitHub "deploy-bot" pour la backdoor supply chain
  - Commit malveillant b7a3f2c1 sur le repo monitoring-agent (14/02/2026 03:15)

JOUR 1 — Lundi 17/02/2026 : Initial Access
  15:25 — Email de phishing envoyé à marie.dupont@redpawn-corp.com
          De: notifications-noreply@micros0ft-security.com
          Objet: [URGENT] Activité inhabituelle détectée sur compte
          PJ: security_report_2026.xlsm
  15:27 — Marie ouvre la pièce jointe dans Excel
  15:28 — Macro VBA exécute PowerShell encodé (Base64)
  15:30 — certutil.exe télécharge stager.ps1 depuis 185.234.72.19
  15:31 — Stager établit la persistance (HKCU\...\Run - GoogleUpdate)
  15:32 — Beacon HTTPS actif vers 185.234.72.19:443 (interval 60s)
  15:45 — Reconnaissance locale : whoami, systeminfo, ipconfig, net user

  22:14 — L'attaquant utilise les credentials AWS de svc-deploy-ci
          (probablement trouvés dans un fichier de config sur le poste)
  22:18 — Création d'une 2ème clé AWS pour persistance
  22:22 — Création du faux compte IAM aws-health-monitor (Admin)
  22:45 — Pivot vers une 2ème IP (45.89.127.33) pour opérations AWS
  22:48 — Début exfiltration S3 : 247 fichiers contrats (892 MB)
  23:20 — Exfiltration sauvegardes DB (3.2 GB)
  23:45 — Création Lambda malveillante (health-check-scheduler)

JOUR 2 — Mardi 18/02/2026 : Mouvement latéral & Impact
  08:16 — Reprise des beacons C2 après la nuit
  09:30 — Scan réseau interne depuis WKS-COMPTA-PC03 (10.0.3.45)
  09:45 — Découverte de 27 comptes via brute force SSH sur srv-web-01
          Source : 185.234.72.19 (directement depuis le C2)
  10:15 — Accès au DC via SMB (partages ADMIN$ et C$)
          Avec le compte compromis svc-backup
  10:16 — Upload de health_check.exe sur le DC dans C:\Windows\Temp\
          Lecture du fichier SAM pour récupérer les hashes locaux
  11:00 — ntdsutil.exe : dump complet de la base NTDS (Active Directory)
  11:30 — Mouvement latéral RDP vers 10.0.2.20 (SRV-FILE-01)
  12:03 — Installation du service malveillant WinDefHealthCheck sur le DC
  12:05 — Tâches planifiées de persistance (WinDefUpdate, SystemHealthReport)
  12:30 — Export CSV de l'annuaire AD complet
  12:45 — Début exfiltration données via HTTP (91.234.56.78:80)
  13:00 — Upload de data_export.7z (15 MB) vers gate.php
  13:15 — Création du compte backdoor support_it (Domain Admin)
  13:22 — Injection de processus sur le DC :
          - Faux lsass.exe (PID 5540) — PE injection
          - svchost.exe (PID 4012) — Cobalt Strike beacon
          - svchost.exe (PID 7896) — Reflective DLL injection
  13:45 — WMI Event Subscription pour persistance
  14:00 — Exécution de wmic remote pour reconnaissance supplémentaire
  14:15 — Préparation ransomware :
          PsExec utilisé pour distribuer le ransomware sur 5 serveurs
  14:30 — DÉCLENCHEMENT DU RANSOMWARE Ph0nLock
          Extension : .ph0n
          Serveurs chiffrés : SRV-FILE-01, SRV-APP-01, SRV-DB-01,
                              SRV-INTRANET-01, SRV-BACKUP-01
          Note de rançon déposée : !!_README_URGENT_!!.txt
          Montant : 15 BTC
          Contact : ph0n-support@protonmail.com
  14:45 — DNS exfiltration détectée (données encodées base64 dans TXT records)
  15:00 — Golden Ticket créé (krbtgt : RC4_HMAC_MD5)
  15:30 — Alerte SIEM déclenchée — SOC commence l'investigation

JOUR 3+ — Investigation, containment, remediation

===== MATRICE MITRE ATT&CK — CARTOGRAPHIE COMPLÈTE =====

PHASE               TECHNIQUE                          ID         PREUVES
────────────────────────────────────────────────────────────────────────────
Reconnaissance       Gather Victim Identity Info        T1589      Ciblage de Marie Dupont
Resource Development Register Infrastructure            T1583.001  c2-update-service.xyz, IPs
                     Develop Capabilities               T1587.001  health_check.exe custom
 
Initial Access       Phishing: Attachment               T1566.001  security_report_2026.xlsm
                     Supply Chain Compromise             T1195.002  Commit b7a3f2c1 (non activé)
                     Valid Accounts: Cloud               T1078.004  Credentials AWS svc-deploy-ci

Execution            Command Scripting: PowerShell      T1059.001  Stager PowerShell encodé
                     User Execution: Malicious File     T1204.002  Ouverture de la pièce jointe
                     Windows Management (WMI)           T1047      wmic /node process call

Persistence          Boot/Logon Autostart               T1547.001  Run keys (GoogleUpdate, WinDefUpdate)
                     Create Account: Domain             T1136.002  support_it (Domain Admin)
                     Scheduled Task                     T1053.005  WinDefUpdate, SystemHealthReport
                     Windows Service                    T1543.003  WinDefHealthCheck
                     WMI Event Subscription             T1546.003  Event Consumer persistence
                     Cloud Account                      T1136.003  aws-health-monitor (IAM)
                     Lambda Backdoor                    T1525      health-check-scheduler

Privilege Escalation Exploitation: Domain Policy        T1484      svc-backup → Domain Admin
                     Token Manipulation                 T1134      AdjustTokenPrivileges

Defense Evasion      Process Injection                  T1055      Early Bird APC, Reflective DLL
                     Masquerading                       T1036.005  Faux lsass.exe, svchost.exe
                     Indicator Removal                  T1070      Tentatives suppression CloudTrail
                     Obfuscated Files                   T1027.002  UPX packing, Base64 encoding
                     Disable/Modify Tools               T1562.001  Pas de détection par Defender

Credential Access    OS Credential Dumping: LSASS       T1003.001  mimikatz via health_check.exe
                     OS Credential Dumping: NTDS        T1003.003  ntdsutil IFM dump
                     OS Credential Dumping: SAM         T1003.002  Lecture SMB du fichier SAM
                     Steal Kerberos Tickets             T1558.001  Golden Ticket (krbtgt)

Discovery            Account Discovery                  T1087      net user /domain, net group
                     Remote System Discovery            T1018      Scan réseau 10.0.1.0/24
                     Domain Trust Discovery             T1482      nltest /dclist

Lateral Movement     Remote Services: SMB               T1021.002  ADMIN$, C$ shares
                     Remote Services: RDP               T1021.001  Session RDP vers SRV-FILE-01
                     Lateral Tool Transfer              T1570      PsExec pour distribuer payloads

Collection           Data from Local System             T1005      SAM, NTDS, AD export
                     Data Staged: Local                 T1074.001  C:\Temp\ntds_dump, data_export
                     Archive Collected Data             T1560      data_export.7z (chiffré)

Exfiltration         Exfil Over C2 Channel              T1041      HTTPS beacon data
                     Exfil Over Web Service              T1567      S3 download via AWS CLI
                     Exfil Over Alternative Protocol    T1048      DNS tunneling (TXT records)
                     Transfer to Cloud Account          T1537      Bucket policy → public

Impact               Data Encrypted for Impact          T1486      Ph0nLock ransomware (.ph0n)
                     Data Destruction                   T1485      Chiffrement des backups

===== INDICATEURS DE COMPROMISSION (IoC) =====

IPs malveillantes :
  185.234.72.19     — C2 primaire (Russie, AS48693)
  91.234.56.78      — Serveur d'exfiltration (Ukraine, AS15497)
  45.89.127.33      — VPS de pivot AWS (Pays-Bas)

Domaines :
  c2-update-service.xyz          — Domaine C2 principal
  health-check.phantomcrane.xyz  — Domaine secondaire
  cdn-static.microsft-update.com — Typosquatting
  micros0ft-security.com         — Domaine de phishing

Hashes :
  health_check.exe SHA256: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8...
  stager.ps1       SHA256: c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0...

Comptes compromis/créés :
  svc-backup         — Compte AD compromis (vol credentials)
  marie.dupont       — Utilisatrice du poste initial phishé (WKS-COMPTA-PC03)
  support_it         — Compte backdoor (Domain Admin)
  svc-deploy-ci      — Compte AWS compromis
  aws-health-monitor — Compte IAM créé (Admin)

Fichiers/Artefacts :
  health_check.exe, stager.ps1, d3d11.dll, logo-update.php (webshell)
  Mutex: PERS1ST_M0DUL3
  Named pipe: \\.\pipe\health_svc_pipe
  Service: WinDefHealthCheck
  Tâches planifiées: WinDefUpdate, SystemHealthReport

===== SCORE DE SÉVÉRITÉ =====
Classification : APT — Attaque ciblée multi-phases
Durée totale   : ~24 heures (17/02 15:25 → 18/02 15:30)
Données volées : ~4.1 GB (cloud) + ~15 MB (on-premise) + NTDS + SAM + AD export
Systèmes touchés : 7+ (1 poste, 5 serveurs, 1 compte cloud)
Niveau de sophistication : Élevé (custom malware, anti-analyse, supply chain, cloud)
"""

CHALLENGE = {
    "id": "c18_final_exam",
    "title": "🏆 L'Examen Final : Opération PHANTOM CRANE",
    "category": "incident_response",
    "level": 5,
    "points_total": 650,
    "estimated_time": "60-90 min",
    "story": """
## Briefing de Mission

**Date :** 20 février 2026, 09h00
**Priorité :** CRITIQUE
**Source :** CISO / Direction

---

L'investigation est terminée. Le CISO demande un rapport final de synthèse. Vous avez accès à la reconstitution complète de l'attaque, incluant la chronologie, la cartographie MITRE ATT&CK, et tous les IoCs.

> *"C'est l'examen final. On doit présenter au board un rapport clair de tout ce qui s'est passé. Montrez-moi que vous avez compris l'attaque dans son intégralité — du phishing initial jusqu'au ransomware. Chaque détail compte."*

Ce challenge de synthèse teste votre compréhension globale de TOUTE l'investigation. Les questions couvrent l'ensemble des challenges précédents.
    """,
    "artifacts": [
        {
            "name": "final_reconstruction.txt",
            "type": "report",
            "content": ARTIFACT_FINAL,
            "description": "Reconstruction complète — Opération PHANTOM CRANE"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quelle est la durée totale de l'attaque, de l'accès initial à la détection par le SOC ? (en heures, arrondi)",
            "answer": "24",
            "flag": "REDPAWN{24}",
            "points": 40,
            "hints": [
                "Du 17/02 15:25 au 18/02 15:30",
                "C'est environ 24 heures"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Combien de techniques MITRE ATT&CK distinctes sont cartographiées dans cette attaque ? (comptez les IDs T1xxx)",
            "answer": "42",
            "flag": "REDPAWN{42}",
            "points": 60,
            "hints": [
                "Comptez chaque ligne avec un ID T1xxx dans la matrice",
                "Attention aux sous-techniques (.001, .002, etc.) — elles comptent séparément"
            ],
            "hint_cost": 20
        },
        {
            "id": "q3",
            "text": "Combien d'IPs malveillantes distinctes sont listées dans les IoCs ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 30,
            "hints": [
                "Comptez dans la section IPs malveillantes"
            ],
            "hint_cost": 10
        },
        {
            "id": "q4",
            "text": "Quel est le volume TOTAL estimé de données volées (cloud + on-premise), en GB ?",
            "answer": "4.1",
            "flag": "REDPAWN{4.1}",
            "points": 40,
            "hints": [
                "Regardez le Score de Sévérité à la fin",
                "Les ~15 MB on-premise sont négligeables face aux 4.1 GB cloud"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Combien de mécanismes de persistance différents l'attaquant a-t-il mis en place au total ? (comptez dans la matrice ATT&CK, phase Persistence)",
            "answer": "7",
            "flag": "REDPAWN{7}",
            "points": 50,
            "hints": [
                "Comptez les techniques dans la phase 'Persistence' de la matrice",
                "Run keys, Create Account, Scheduled Task, Service, WMI, Cloud Account, Lambda"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "Quelle est l'heure exacte du premier contact C2 le Jour 1 ? (format HH:MM)",
            "answer": "15:32",
            "flag": "REDPAWN{15:32}",
            "points": 40,
            "hints": [
                "Cherchez 'Beacon HTTPS actif' dans la chronologie du Jour 1",
                "C'est après le téléchargement du stager"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Combien de serveurs ont été chiffrés par le ransomware Ph0nLock ?",
            "answer": "5",
            "flag": "REDPAWN{5}",
            "points": 30,
            "hints": [
                "Comptez les serveurs listés après 'Serveurs chiffrés :' dans la chronologie"
            ],
            "hint_cost": 10
        },
        {
            "id": "q8",
            "text": "Quelle technique (ID MITRE) correspond à l'utilisation du Golden Ticket ?",
            "answer": "T1558.001",
            "flag": "REDPAWN{T1558.001}",
            "points": 50,
            "hints": [
                "Cherchez 'Golden Ticket' dans la matrice ATT&CK",
                "C'est sous Credential Access → Steal Kerberos Tickets"
            ],
            "hint_cost": 17
        },
        {
            "id": "q9",
            "text": "Combien de phases de la kill chain MITRE ATT&CK sont couvertes par cette attaque ?",
            "answer": "13",
            "flag": "REDPAWN{13}",
            "points": 50,
            "hints": [
                "Comptez les grandes phases (titres en majuscules) dans la matrice",
                "Attention à ne pas en oublier — certaines phases sont moins évidentes"
            ],
            "hint_cost": 17
        },
        {
            "id": "q10",
            "text": "Combien de vecteurs d'exfiltration différents (techniques dans la phase Exfiltration de la matrice ATT&CK) l'attaquant utilise-t-il ?",
            "answer": "4",
            "flag": "REDPAWN{4}",
            "points": 50,
            "hints": [
                "Comptez les techniques dans la phase 'Exfiltration'",
                "C2 channel, Web Service, Alternative Protocol, Transfer to Cloud"
            ],
            "hint_cost": 17
        },
        {
            "id": "q11",
            "text": "Le vecteur supply chain (commit b7a3f2c1) a-t-il été activé pendant l'attaque ?",
            "answer": "non",
            "flag": "REDPAWN{non}",
            "points": 40,
            "hints": [
                "Regardez la mention du supply chain dans la chronologie",
                "Il est noté comme 'non activé'"
            ],
            "hint_cost": 13
        },
        {
            "id": "q12",
            "text": "À quelle heure exacte l'alerte SIEM a-t-elle finalement été déclenchée ? (format HH:MM)",
            "answer": "15:30",
            "flag": "REDPAWN{15:30}",
            "points": 40,
            "hints": [
                "C'est le dernier événement de la chronologie du Jour 2"
            ],
            "hint_cost": 13
        },
        {
            "id": "q13",
            "text": "Quel est le montant de la rançon demandée en BTC ?",
            "answer": "15",
            "flag": "REDPAWN{15}",
            "points": 30,
            "hints": [
                "Cherchez 'rançon' dans la chronologie du ransomware"
            ],
            "hint_cost": 10
        },
        {
            "id": "q14",
            "text": "Combien de systèmes au total (postes + serveurs + comptes cloud) sont identifiés comme touchés dans le score de sévérité ?",
            "answer": "7",
            "flag": "REDPAWN{7}",
            "points": 40,
            "hints": [
                "Regardez 'Systèmes touchés' dans le Score de Sévérité",
                "Le '7+' signifie au minimum 7"
            ],
            "hint_cost": 13
        }
    ]
}
