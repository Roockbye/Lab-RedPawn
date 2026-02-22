"""
Challenge 5 — Mouvement Latéral Active Directory
Niveau : 2 (Analyste Confirmé)
Catégorie : Forensics Système
"""

ARTIFACT_WINDOWS_EVENTS = r"""
=== WINDOWS EVENT LOGS — SRV-AD-01 (Domain Controller) ===
=== Filtre: Security Events — 18/02/2026 08:00-12:00 ===

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
  Account: admin.rsi
  Source IP: 10.0.3.45 (WKS-COMPTA-PC03)
  Logon Type: 3 (Network)
  Failure Reason: Unknown user name or bad password

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T08:33:01.234Z
  Account: svc-backup
  Source IP: 10.0.3.45 (WKS-COMPTA-PC03)
  Logon Type: 3 (Network)
  Logon Process: NtLmSsp
  Authentication Package: NTLM
  Elevated Token: Yes

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
  Time: 2026-02-18T08:35:12.123Z
  Account: svc-backup
  Process: C:\Windows\System32\cmd.exe
  Command Line: cmd.exe /c "net group \"Domain Admins\" /domain"

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:36:30.456Z
  Account: svc-backup
  Process: C:\Windows\System32\cmd.exe
  Command Line: cmd.exe /c "net user admin.rsi /domain"

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:38:00.789Z
  Account: svc-backup
  Process: C:\Windows\System32\rundll32.exe
  Command Line: rundll32.exe C:\Windows\Temp\d3d11.dll,DllMain

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:38:05.012Z
  Account: svc-backup
  Process: C:\Windows\System32\rundll32.exe
  Command Line: rundll32.exe — injecting into lsass.exe (PID 672)

[Event ID: 4648 — Logon Using Explicit Credentials]
  Time: 2026-02-18T08:40:15.345Z
  Subject Account: svc-backup
  Target Account: admin.rsi
  Target Server: SRV-AD-01
  Process: C:\Windows\System32\sekurlsa.exe

[Event ID: 4624 — Successful Logon]
  Time: 2026-02-18T08:41:00.678Z
  Account: admin.rsi
  Source IP: 10.0.3.45 (WKS-COMPTA-PC03)
  Logon Type: 3 (Network)
  Logon Process: Kerberos
  Authentication Package: Kerberos
  Elevated Token: Yes

[Event ID: 4672 — Special Privileges Assigned]
  Time: 2026-02-18T08:41:01.012Z
  Account: admin.rsi
  Privileges: SeDebugPrivilege, SeTakeOwnershipPrivilege, SeBackupPrivilege, SeRestorePrivilege

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:42:30.345Z
  Account: admin.rsi
  Process: C:\Windows\System32\ntdsutil.exe
  Command Line: ntdsutil.exe "ac i ntds" "ifm" "create full C:\Windows\Temp\ntds_dump" quit quit

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:45:00.678Z
  Account: admin.rsi
  Process: C:\Windows\System32\cmd.exe
  Command Line: cmd.exe /c "net user support_it P@ssw0rd2026! /add /domain"

[Event ID: 4720 — User Account Created]
  Time: 2026-02-18T08:45:01.012Z
  Target Account: support_it
  Created By: admin.rsi

[Event ID: 4728 — Member Added to Security-Enabled Global Group]
  Time: 2026-02-18T08:45:15.345Z
  Group: Domain Admins
  Account Added: support_it
  Added By: admin.rsi

[Event ID: 4688 — Process Creation]
  Time: 2026-02-18T08:50:00.678Z
  Account: admin.rsi
  Process: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  Command Line: powershell.exe -c "Compress-Archive -Path C:\Windows\Temp\ntds_dump -DestinationPath C:\Windows\Temp\backup.zip"
"""

CHALLENGE = {
    "id": "c05_lateral_movement",
    "title": "🏰 La Chute du Château Fort",
    "category": "forensics",
    "level": 2,
    "points_total": 400,
    "estimated_time": "35-50 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 14h30  
**Priorité :** CRITIQUE  
**Source :** Escalade N1 — Corrélation avec alerte Mimikatz (SIEM-2026-4403)

---

Suite à l'alerte Mimikatz détectée plus tôt sur le Domain Controller (SRV-AD-01), l'équipe N1 vous escalade l'investigation complète.

Les Event Logs Windows du DC ont été extraits. Vous devez reconstituer la chaîne d'attaque complète :

> *"C'est confirmé, on a une compromission du DC. J'ai besoin que tu reconstitues toute la timeline : comment ils sont entrés, ce qu'ils ont fait, et SURTOUT s'ils ont extrait la base NTDS. C'est critique."*

**Rappel des Event IDs clés :**
- **4624** : Logon réussi  
- **4625** : Logon échoué  
- **4648** : Logon avec credentials explicites  
- **4672** : Privilèges spéciaux assignés  
- **4688** : Création de processus  
- **4720** : Compte utilisateur créé  
- **4728** : Membre ajouté à un groupe global
    """,
    "artifacts": [
        {
            "name": "security_events.log",
            "type": "windows_events",
            "content": ARTIFACT_WINDOWS_EVENTS,
            "description": "Event Logs Windows Security de SRV-AD-01 (filtrés 08:00-12:00)"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Depuis quelle machine (IP) l'attaquant a-t-il initié le mouvement latéral vers le DC ?",
            "answer": "10.0.3.45",
            "flag": "REDPAWN{10.0.3.45}",
            "points": 40,
            "hints": [
                "Regardez la Source IP des premières tentatives de connexion échouées",
                "C'est la machine WKS-COMPTA-PC03"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Quel compte de service a été compromis pour l'accès initial au DC ?",
            "answer": "svc-backup",
            "flag": "REDPAWN{svc-backup}",
            "points": 40,
            "hints": [
                "Cherchez le premier Event 4624 (Successful Logon) depuis l'IP attaquante",
                "C'est un compte de service pour les sauvegardes"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Quel type de logon (numéro) a été utilisé pour la connexion initiale ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 30,
            "hints": [
                "Logon Type 3 = Network logon",
                "Regardez le premier 4624 réussi"
            ],
            "hint_cost": 10
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
            "text": "Quel compte Domain Admin a été compromis après l'attaque Mimikatz ?",
            "answer": "admin.rsi",
            "flag": "REDPAWN{admin.rsi}",
            "points": 40,
            "hints": [
                "Cherchez l'Event 4648 (logon avec credentials explicites) après l'injection dans lsass",
                "Le Target Account est un compte d'administration"
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
            "id": "q8",
            "text": "À quel groupe le compte backdoor a-t-il été ajouté ?",
            "answer": "Domain Admins",
            "flag": "REDPAWN{Domain_Admins}",
            "points": 40,
            "hints": [
                "Cherchez l'Event 4728 (Member Added to Group)",
                "C'est le groupe d'administration le plus privilégié du domaine"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
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
            "id": "q10",
            "text": "Quel est le nom du fichier compressé contenant le dump NTDS ?",
            "answer": "C:\\Windows\\Temp\\backup.zip",
            "flag": "REDPAWN{backup.zip}",
            "points": 40,
            "hints": [
                "Cherchez la commande Compress-Archive (PowerShell)",
                "Le fichier est dans le dossier Temp"
            ],
            "hint_cost": 13
        }
    ]
}
