"""
Challenge 5 — Mouvement Latéral Active Directory
Niveau : 2 (Analyste Confirmé)
Catégorie : Forensics Système
"""

ARTIFACT_WINDOWS_EVENTS = r"""
=== WINDOWS EVENT LOGS — SRV-AD-01 (Domain Controller) ===
=== Export: wevtutil epl Security C:\forensic\security.evtx ===
=== Filtre: Security Events — 18/02/2026 06:00-13:00 ===
=== Total: 847 events bruts → 52 events filtrés (pertinents) ===

# ─── Activité normale du matin (avant l'attaque) ───

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T06:00:02.123Z
  Account: SYSTEM
  Source IP: ::1 (localhost)
  Logon Type: 5 (Service)
  Logon Process: Advapi
  Authentication Package: Negotiate

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T06:00:03.456Z
  Account: svc-backup
  Source IP: 10.0.1.30 (SRV-BACKUP-01)
  Logon Type: 3 (Network)
  Logon Process: NtLmSsp
  Authentication Package: NTLM
  Note: Sauvegarde planifiée quotidienne (06h00)

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T06:00:05.789Z
  Account: svc-backup
  Process: C:\Windows\System32\robocopy.exe
  Parent Process: C:\Windows\System32\svchost.exe
  Command Line: robocopy \\SRV-AD-01\SYSVOL E:\Backups\SYSVOL /MIR /LOG:E:\Logs\sysvol_backup.log

[Event ID: 4634 — Logoff]
  Time: 2026-02-18T06:05:12.012Z
  Account: svc-backup
  Logon Type: 3
  Note: Fin de la sauvegarde planifiée

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T07:02:33.345Z
  Account: admin.rsi
  Source IP: 10.0.4.10 (WKS-ADMIN-PC01)
  Logon Type: 10 (RemoteInteractive — RDP)
  Logon Process: User32
  Authentication Package: Negotiate
  Note: Connexion RDP administrative matinale (routine)

[Event ID: 4672 — Special Privileges Assigned]
  Time: 2026-02-18T07:02:33.678Z
  Account: admin.rsi
  Privileges: SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege, SeTakeOwnershipPrivilege

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T07:05:00.012Z
  Account: admin.rsi
  Process: C:\Windows\System32\mmc.exe
  Parent Process: C:\Windows\explorer.exe
  Command Line: mmc.exe "C:\Windows\System32\dnsmgmt.msc"
  Note: Console DNS management (tâche admin routine)

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T07:12:30.345Z
  Account: admin.rsi
  Process: C:\Windows\System32\gpupdate.exe
  Parent Process: C:\Windows\System32\cmd.exe
  Command Line: gpupdate /force
  Note: Mise à jour des stratégies de groupe (routine)

[Event ID: 4634 — Logoff]
  Time: 2026-02-18T07:45:00.678Z
  Account: admin.rsi
  Logon Type: 10

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T07:55:12.012Z
  Account: m.petit
  Source IP: 10.0.3.22 (WKS-HR-PC02)
  Logon Type: 3 (Network)
  Logon Process: Kerberos
  Authentication Package: Kerberos
  Note: Accès partage réseau normal (fichiers RH)

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T08:01:05.345Z
  Account: l.mercier
  Source IP: 10.0.3.15 (WKS-FIN-PC01)
  Logon Type: 3 (Network)
  Note: Accès aux partages financiers

[Event ID: 4625 — Logon Failure]
  Time: 2026-02-18T08:15:22.678Z
  Account: l.mercier
  Source IP: 10.0.3.15 (WKS-FIN-PC01)
  Logon Type: 3 (Network)
  Failure Reason: Unknown user name or bad password
  Sub Status: 0xC000006A
  Note: Mot de passe expiré — ticket HD-2026-0412 ouvert

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T08:20:45.012Z
  Account: svc-antivirus
  Source IP: 10.0.1.40 (SRV-AV-01)
  Logon Type: 3 (Network)
  Logon Process: NtLmSsp
  Note: Mise à jour définitions antivirus (planifié toutes les 4h)

# ─── DÉBUT DE L'ATTAQUE (mouvement latéral depuis WKS-COMPTA-PC03) ───

[Event ID: 4625 — Logon Failure]
  Time: 2026-02-18T08:32:15.123Z
  Account: Administrator
  Source IP: 10.0.3.45 (WKS-COMPTA-PC03)
  Logon Type: 3 (Network)
  Failure Reason: Unknown user name or bad password
  Sub Status: 0xC000006A (Wrong password)

[Event ID: 4625 — Logon Failure]
  Time: 2026-02-18T08:32:16.456Z
  Account: Administrator
  Source IP: 10.0.3.45 (WKS-COMPTA-PC03)
  Logon Type: 3 (Network)
  Failure Reason: Unknown user name or bad password

[Event ID: 4625 — Logon Failure]
  Time: 2026-02-18T08:32:17.789Z
  Account: admin
  Source IP: 10.0.3.45 (WKS-COMPTA-PC03)
  Logon Type: 3 (Network)
  Failure Reason: Unknown user name or bad password

[Event ID: 4625 — Logon Failure]
  Time: 2026-02-18T08:32:18.012Z
  Account: admin.rsi
  Source IP: 10.0.3.45 (WKS-COMPTA-PC03)
  Logon Type: 3 (Network)
  Failure Reason: Unknown user name or bad password

[Event ID: 4625 — Logon Failure]
  Time: 2026-02-18T08:32:19.345Z
  Account: root
  Source IP: 10.0.3.45 (WKS-COMPTA-PC03)
  Logon Type: 3 (Network)
  Failure Reason: No such user

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T08:33:01.234Z
  Account: svc-backup
  Source IP: 10.0.3.45 (WKS-COMPTA-PC03)
  Logon Type: 3 (Network)
  Logon Process: NtLmSsp
  Authentication Package: NTLM
  Elevated Token: Yes
  → NOTE: svc-backup se connecte normalement depuis SRV-BACKUP-01 (10.0.1.30), PAS depuis WKS-COMPTA-PC03

[Event ID: 4672 — Special Privileges Assigned]
  Time: 2026-02-18T08:33:01.567Z
  Account: svc-backup
  Privileges: SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:34:05.890Z
  Account: svc-backup
  Process: C:\Windows\System32\cmd.exe
  Parent Process: C:\Windows\System32\services.exe
  Command Line: cmd.exe /c "whoami && hostname && ipconfig /all"

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:34:30.123Z
  Account: svc-backup
  Process: C:\Windows\System32\cmd.exe
  Command Line: cmd.exe /c "systeminfo"

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:35:12.123Z
  Account: svc-backup
  Process: C:\Windows\System32\cmd.exe
  Command Line: cmd.exe /c "net group \"Domain Admins\" /domain"

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:35:45.456Z
  Account: svc-backup
  Process: C:\Windows\System32\cmd.exe
  Command Line: cmd.exe /c "net group \"Enterprise Admins\" /domain"

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:36:30.456Z
  Account: svc-backup
  Process: C:\Windows\System32\cmd.exe
  Command Line: cmd.exe /c "net user admin.rsi /domain"

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:36:55.789Z
  Account: svc-backup
  Process: C:\Windows\System32\cmd.exe
  Command Line: cmd.exe /c "nltest /dclist:redpawn.local"

# ─── Activité légitime intercalée (bruit) ───

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T08:37:00.012Z
  Account: a.bernard
  Source IP: 10.0.3.30 (WKS-DEV-PC05)
  Logon Type: 3 (Network)
  Note: Accès partage développement (normal)

# ─── Suite de l'attaque : Mimikatz ───

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:38:00.789Z
  Account: svc-backup
  Process: C:\Windows\System32\rundll32.exe
  Parent Process: C:\Windows\System32\cmd.exe
  Command Line: rundll32.exe C:\Windows\Temp\d3d11.dll,DllMain

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:38:05.012Z
  Account: svc-backup
  Process: C:\Windows\System32\rundll32.exe
  Command Line: rundll32.exe — injecting into lsass.exe (PID 672)
  → Sysmon: Process accessed lsass.exe with PROCESS_VM_READ

[Event ID: 4648 — Logon Using Explicit Credentials]
  Time: 2026-02-18T08:40:15.345Z
  Subject Account: svc-backup
  Target Account: admin.rsi
  Target Server: SRV-AD-01
  Process: C:\Windows\System32\sekurlsa.exe
  → NOTE: sekurlsa.exe n'est PAS un binaire Windows légitime

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T08:41:00.678Z
  Account: admin.rsi
  Source IP: 10.0.3.45 (WKS-COMPTA-PC03)
  Logon Type: 3 (Network)
  Logon Process: Kerberos
  Authentication Package: Kerberos
  Elevated Token: Yes
  → NOTE: admin.rsi a une session RDP légitime fermée à 07:45 depuis WKS-ADMIN-PC01
  → Cette connexion vient de WKS-COMPTA-PC03 — ANORMAL

[Event ID: 4672 — Special Privileges Assigned]
  Time: 2026-02-18T08:41:01.012Z
  Account: admin.rsi
  Privileges: SeDebugPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege, SeRestorePrivilege

# ─── Exploitation du compte DA ───

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:42:30.345Z
  Account: admin.rsi
  Process: C:\Windows\System32\ntdsutil.exe
  Parent Process: C:\Windows\System32\cmd.exe
  Command Line: ntdsutil.exe "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds_dump" quit quit
  → CRITIQUE: Dump de la base Active Directory (tous les hashes)

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:45:00.678Z
  Account: admin.rsi
  Process: C:\Windows\System32\cmd.exe
  Command Line: cmd.exe /c "net user support_it P@ssw0rd2026! /add /domain"

[Event ID: 4720 — User Account Created]
  Time: 2026-02-18T08:45:01.012Z
  Target Account: support_it
  Created By: admin.rsi
  Account Domain: REDPAWN

[Event ID: 4728 — Member Added to Security-Enabled Global Group]
  Time: 2026-02-18T08:45:15.345Z
  Group: Domain Admins
  Account Added: support_it
  Added By: admin.rsi

[Event ID: 4732 — Member Added to Security-Enabled Local Group]
  Time: 2026-02-18T08:45:20.678Z
  Group: Remote Desktop Users
  Account Added: support_it
  Added By: admin.rsi

# ─── Activité légitime intercalée ───

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T08:48:00.012Z
  Account: svc-antivirus
  Source IP: 10.0.1.40 (SRV-AV-01)
  Logon Type: 3 (Network)
  Note: Scan antivirus planifié

# ─── Compression et préparation exfiltration ───

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:50:00.678Z
  Account: admin.rsi
  Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Parent Process: C:\Windows\System32\cmd.exe
  Command Line: powershell.exe -c "Compress-Archive -Path C:\Windows\Temp\ntds_dump -DestinationPath C:\Windows\Temp\backup.zip"

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:52:00.012Z
  Account: admin.rsi
  Process: C:\Windows\System32\cmd.exe
  Command Line: cmd.exe /c "csvde -f C:\Windows\Temp\ad_export.csv -d \"DC=redpawn,DC=local\""
  → NOTE: Export CSV de tout l'annuaire Active Directory

# ─── Activité post-attaque normale ───

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T09:00:12.345Z
  Account: t.girard
  Source IP: 10.0.4.12 (WKS-ADMIN-PC02)
  Logon Type: 10 (RemoteInteractive — RDP)
  Note: Admin légitime, session RDP de maintenance

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T09:05:00.678Z
  Account: t.girard
  Process: C:\Windows\System32\ServerManager.exe
  Parent Process: C:\Windows\explorer.exe
  Note: Vérification état du serveur (routine)
"""

ARTIFACT_SYSMON_EVENTS = r"""
=== SYSMON EVENT LOGS — SRV-AD-01 (supplément) ===
=== Filtre: Sysmon Events — 18/02/2026 08:30-09:00 ===

[Sysmon Event ID: 1 — Process Create]
  Time: 2026-02-18T08:38:00.789Z
  User: REDPAWN\svc-backup
  Image: C:\Windows\System32\rundll32.exe
  CommandLine: rundll32.exe C:\Windows\Temp\d3d11.dll,DllMain
  ParentImage: C:\Windows\System32\cmd.exe
  Hashes: SHA256=b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4

[Sysmon Event ID: 10 — ProcessAccess]
  Time: 2026-02-18T08:38:05.012Z
  SourceImage: C:\Windows\System32\rundll32.exe
  TargetImage: C:\Windows\System32\lsass.exe
  GrantedAccess: 0x1010 (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION)
  → ALERT: Accès mémoire LSASS — probable credential dumping

[Sysmon Event ID: 11 — FileCreate]
  Time: 2026-02-18T08:38:01.234Z
  Image: C:\Windows\System32\cmd.exe
  TargetFilename: C:\Windows\Temp\d3d11.dll
  → NOTE: DLL créée dans Temp par cmd.exe — suspect

[Sysmon Event ID: 3 — Network Connection]
  Time: 2026-02-18T08:41:30.567Z
  Image: C:\Windows\System32\svchost.exe
  User: REDPAWN\admin.rsi
  DestinationIP: 185.234.72.19
  DestinationPort: 443
  Protocol: tcp
  → Connexion C2 depuis le compte DA compromis

[Sysmon Event ID: 1 — Process Create]
  Time: 2026-02-18T08:42:30.345Z
  User: REDPAWN\admin.rsi
  Image: C:\Windows\System32\ntdsutil.exe
  CommandLine: ntdsutil.exe "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds_dump" quit quit
  IntegrityLevel: High
  → CRITIQUE: IFM = Install From Media — extraction NTDS.dit + SYSTEM hive

[Sysmon Event ID: 11 — FileCreate]
  Time: 2026-02-18T08:43:15.678Z
  Image: C:\Windows\System32\ntdsutil.exe
  TargetFilename: C:\Windows\Temp\ntds_dump\Active Directory\ntds.dit
  → Fichier NTDS.dit extrait — contient TOUS les hashes du domaine

[Sysmon Event ID: 11 — FileCreate]
  Time: 2026-02-18T08:43:16.012Z
  Image: C:\Windows\System32\ntdsutil.exe
  TargetFilename: C:\Windows\Temp\ntds_dump\registry\SYSTEM
  → Fichier SYSTEM hive nécessaire pour déchiffrer les hashes NTDS
"""

CHALLENGE = {
    "id": "c05_lateral_movement",
    "title": "🏰 La Chute du Château Fort",
    "category": "forensics",
    "level": 2,
    "points_total": 520,
    "estimated_time": "40-60 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 14h30  
**Priorité :** CRITIQUE  
**Source :** Escalade N1 — Corrélation avec alerte Mimikatz (SIEM-2026-4403)

---

Suite à l'alerte Mimikatz détectée plus tôt sur le Domain Controller (SRV-AD-01), l'équipe N1 vous escalade l'investigation complète.

Les Event Logs Windows Security du DC ont été extraits avec `wevtutil`, et les logs Sysmon sont fournis en complément. La difficulté : le DC a de l'activité légitime (sauvegardes, admins, antivirus) qu'il faut différencier de l'attaque.

> *"C'est confirmé, on a une compromission du DC. J'ai extrait les event logs et les logs Sysmon. Le problème c'est qu'il y a du bruit — les sauvegardes automatiques, les admins qui bossent, l'antivirus... Tu dois trier tout ça et me dire exactement ce qui est malveillant vs légitime. Reconstitue toute la timeline : comment ils sont entrés, ce qu'ils ont fait, et SURTOUT s'ils ont extrait la base NTDS. C'est critique."*

<details>
<summary>💡 Rappel des Event IDs clés (cliquez pour afficher)</summary>

- **4624** : Logon réussi  
- **4625** : Logon échoué  
- **4634** : Logoff  
- **4648** : Logon avec credentials explicites  
- **4672** : Privilèges spéciaux assignés  
- **4688** : Création de processus  
- **4720** : Compte utilisateur créé  
- **4728** : Membre ajouté à un groupe global  
- **4732** : Membre ajouté à un groupe local

</details>
    """,
    "artifacts": [
        {
            "name": "security_events.evtx.txt",
            "type": "windows_events",
            "content": ARTIFACT_WINDOWS_EVENTS,
            "description": "Event Logs Windows Security de SRV-AD-01 (export wevtutil, 06:00-13:00)"
        },
        {
            "name": "sysmon_events.evtx.txt",
            "type": "sysmon",
            "content": ARTIFACT_SYSMON_EVENTS,
            "description": "Logs Sysmon de SRV-AD-01 (complément forensic, 08:30-09:00)"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Le compte svc-backup se connecte au DC à 06:00 ET à 08:33. Pourquoi la connexion de 08:33 est-elle suspecte alors que celle de 06:00 ne l'est pas ? (IP source suspecte)",
            "answer": "10.0.3.45",
            "flag": "REDPAWN{10.0.3.45}",
            "points": 50,
            "hints": [
                "Comparez les Source IP des deux connexions svc-backup",
                "La connexion légitime vient de SRV-BACKUP-01 (10.0.1.30), la suspecte de WKS-COMPTA-PC03 (10.0.3.45)"
            ],
            "hint_cost": 17
        },
        {
            "id": "q2",
            "text": "Combien de tentatives de logon échouées (4625) proviennent de l'IP de l'attaquant ?",
            "answer": "5",
            "flag": "REDPAWN{5}",
            "points": 40,
            "hints": [
                "Comptez les Event 4625 depuis 10.0.3.45",
                "Administrator (x2), admin, admin.rsi, root"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Quel type d'authentification est utilisé par la connexion malveillante de svc-backup (08:33) ? (NTLM ou Kerberos)",
            "answer": "NTLM",
            "flag": "REDPAWN{NTLM}",
            "points": 40,
            "hints": [
                "Regardez l'Authentication Package de la connexion suspecte",
                "NTLM est souvent utilisé dans les pass-the-hash"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Quel fichier DLL suspect a été exécuté via rundll32.exe pour lancer l'attaque Mimikatz ?",
            "answer": "d3d11.dll",
            "flag": "REDPAWN{d3d11.dll}",
            "points": 50,
            "hints": [
                "Cherchez les process creation avec rundll32.exe",
                "Le fichier est dans C:\\Windows\\Temp\\ et a un nom qui ressemble à un composant DirectX"
            ],
            "hint_cost": 17
        },
        {
            "id": "q5",
            "text": "Le Sysmon Event ID 10 (ProcessAccess) montre un accès suspect à quel processus critique ?",
            "answer": "lsass.exe",
            "flag": "REDPAWN{lsass.exe}",
            "points": 40,
            "hints": [
                "Regardez le TargetImage dans le Sysmon Event ID 10",
                "C'est le processus qui stocke les credentials en mémoire"
            ],
            "hint_cost": 13
        },
        {
            "id": "q6",
            "text": "Quel outil Windows natif a été utilisé pour extraire la base NTDS (dump Active Directory) ?",
            "answer": "ntdsutil.exe",
            "flag": "REDPAWN{ntdsutil}",
            "points": 50,
            "hints": [
                "Cherchez une commande liée à NTDS dans les process creation",
                "C'est un outil natif Windows pour la maintenance AD"
            ],
            "hint_cost": 17
        },
        {
            "id": "q7",
            "text": "Deux fichiers critiques sont créés par ntdsutil (visibles dans Sysmon). Quel fichier contient les hashes de tous les comptes du domaine ?",
            "answer": "ntds.dit",
            "flag": "REDPAWN{ntds.dit}",
            "points": 50,
            "hints": [
                "Regardez les Sysmon FileCreate events après ntdsutil",
                "C'est le fichier de base de données Active Directory"
            ],
            "hint_cost": 17
        },
        {
            "id": "q8",
            "text": "Quel est le nom du compte de backdoor créé par l'attaquant dans le domaine ?",
            "answer": "support_it",
            "flag": "REDPAWN{support_it}",
            "points": 40,
            "hints": [
                "Cherchez l'Event 4720 (User Account Created)",
                "Le nom du compte semble légitime pour le support IT"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Le compte backdoor a été ajouté à deux groupes. Citez le groupe le plus dangeureux.",
            "answer": "Domain Admins",
            "flag": "REDPAWN{Domain_Admins}",
            "points": 40,
            "hints": [
                "Cherchez les Events 4728 et 4732",
                "Domain Admins (global) et Remote Desktop Users (local)"
            ],
            "hint_cost": 13
        },
        {
            "id": "q10",
            "text": "Quel est le mot de passe du compte backdoor créé ?",
            "answer": "P@ssw0rd2026!",
            "flag": "REDPAWN{P@ssw0rd2026!}",
            "points": 30,
            "hints": [
                "Regardez la commande 'net user' complète avec le mot de passe en clair",
                "L'attaquant n'a pas été très original..."
            ],
            "hint_cost": 10
        },
        {
            "id": "q11",
            "text": "Quel outil LOLBin est utilisé pour exporter l'annuaire AD en CSV ?",
            "answer": "csvde",
            "flag": "REDPAWN{csvde}",
            "points": 50,
            "hints": [
                "Cherchez les commandes de l'attaquant après le dump NTDS",
                "C'est un outil natif Windows pour exporter AD en CSV"
            ],
            "hint_cost": 17
        },
        {
            "id": "q12",
            "text": "Le processus sekurlsa.exe mentionné dans l'Event 4648 est-il un binaire Windows légitime ?",
            "answer": "non",
            "flag": "REDPAWN{non}",
            "points": 40,
            "hints": [
                "sekurlsa est un module de Mimikatz, pas un outil Windows",
                "Il n'existe pas de fichier C:\\Windows\\System32\\sekurlsa.exe sur un système propre"
            ],
            "hint_cost": 13
        }
    ]
}
