"""
Challenge 10 — Reconstruction de la Chaîne d'Attaque Complète
Niveau : 4 (Expert SOC)
Catégorie : Incident Response
"""

ARTIFACT_ATTACK_CHAIN = r"""
=== MATRICE ATT&CK — MAPPING DE L'INCIDENT REDPAWN-2026-0218 ===

Complétez cette matrice en identifiant les techniques utilisées à chaque étape.

┌────────────────────┬──────────────────────────────────────────────────────────┬───────────┐
│ PHASE              │ DESCRIPTION                                            │ TECHNIQUE │
├────────────────────┼──────────────────────────────────────────────────────────┼───────────┤
│ Initial Access     │ Email de phishing avec macro Excel (.xlsm)             │ T????     │
│ Execution          │ Macro VBA → PowerShell obfusqué                        │ T????     │
│ Persistence #1     │ Registre Run — GoogleChromeAutoUpdate                  │ T????     │
│ Persistence #2     │ Tâche planifiée — Faux GatherNetworkInfo               │ T????     │
│ Persistence #3     │ Service Windows — WinDefenderUpdate                    │ T????     │
│ Persistence #4     │ WMI Event Subscription                                 │ T????     │
│ Persistence #5     │ Golden Ticket Kerberos                                 │ T????     │
│ Defense Evasion    │ Obfuscation script + anti-VM + faux certificat         │ T????     │
│ Credential Access  │ Mimikatz (sekurlsa::logonpasswords)                    │ T????     │
│ Discovery          │ net group, net user, whoami, ipconfig                  │ T????     │
│ Lateral Movement   │ PsExec + Pass-the-Hash (NTLM)                         │ T????     │
│ Collection         │ ntdsutil IFM dump (NTDS.dit)                          │ T????     │
│ Exfiltration       │ DNS Tunneling + Tor                                    │ T????     │
│ Impact             │ Ransomware (chiffrement AES-256 + RSA-4096)           │ T????     │
└────────────────────┴──────────────────────────────────────────────────────────┴───────────┘

=== INDICATEURS DE COMPROMISSION (IoC) — LISTE COMPLÈTE ===

TYPE          | VALEUR                                        | CONTEXTE
──────────────┼───────────────────────────────────────────────┼──────────────────────
IP            | 185.234.72.19                                 | C2 principal, SSH brute force, hosting webshell
IP            | 91.234.56.78                                  | Serveur d'envoi phishing
IP            | 45.33.21.99                                   | Serveur secondaire (update-service-cdn.xyz)
IP            | 185.220.101.34                                | Noeud Tor — exfiltration
Domain        | micros0ft-security.com                        | Domaine de phishing
Domain        | c2-update-service.xyz                         | C2 DNS tunneling
Domain        | update-service-cdn.xyz                        | Domaine secondaire
Domain        | redpawn-c0rp.com                              | Typosquatting email (phishing initial)
Email         | facturation@redpawn-c0rp.com                  | Expéditeur phishing initial
Email         | ph0n-support@protonmail.com                   | Contact ransomware
BTC           | bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh   | Wallet ransomware
File          | Facture_Fevrier2026.xlsm                      | Document piégé initial
File          | update_checker.ps1                            | Stage 1 PowerShell
File          | logo-update.php                               | Webshell PHP
File          | stager.ps1                                    | Stage 2 payload
File          | svc.exe                                       | Backdoor service
File          | updater.exe                                   | Backdoor registre (faux cert)
File          | ntevt.dll                                     | Custom implant DLL
File          | shell.elf                                     | Reverse shell Linux
File          | d3d11.dll                                     | Mimikatz DLL (masquée)
Hash SHA256   | 7a8b9c0d...                                   | update_checker.ps1
Hash SHA256   | e4a1b2c3...                                   | ntevt.dll
Hash SHA256   | f1e2d3c4...                                   | svc.exe
Hash SHA256   | a9b8c7d6...                                   | updater.exe
Account       | ftpuser                                       | Compte compromis SSH
Account       | svc-backup                                    | Compte service compromis AD
Account       | admin.rsi                                     | Compte DA compromis
Account       | support_it                                    | Compte backdoor créé
Account       | backdoor                                      | Compte backdoor SSH (UID 0)
Account       | j.martin                                      | Victime initiale (phishing)
"""

CHALLENGE = {
    "id": "c10_full_attack_chain",
    "title": "⚔️ L'Autopsie Complète",
    "category": "incident_response",
    "level": 4,
    "points_total": 500,
    "estimated_time": "45-60 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 20h00  
**Priorité :** POST-INCIDENT  
**Source :** Direction — Demande de rapport exécutif

---

L'incident est sous contrôle. Le COMEX (Comité Exécutif) demande un rapport complet de l'attaque. Vous devez mapper l'ensemble de la chaîne d'attaque sur la matrice MITRE ATT&CK et valider la liste des IoC.

> *"Le DG veut un rapport pour le conseil d'administration demain matin. J'ai besoin que tu mappes toute la kill chain sur MITRE ATT&CK, que tu valides les IoC, et que tu identifies ce qu'on aurait pu détecter plus tôt. C'est notre retour d'expérience."*

**Objectif :** Démontrer votre compréhension globale de la chaîne d'attaque en répondant aux questions stratégiques.
    """,
    "artifacts": [
        {
            "name": "attack_chain_mapping.txt",
            "type": "report",
            "content": ARTIFACT_ATTACK_CHAIN,
            "description": "Matrice ATT&CK à compléter et liste des IoC"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quelle technique MITRE ATT&CK correspond au phishing avec pièce jointe ? (format: T1566.XXX)",
            "answer": "T1566.001",
            "flag": "FLAG{T1566.001}",
            "points": 50,
            "hints": [
                "T1566 = Phishing, le sous-numéro .001 = Spearphishing Attachment",
                "C'est du phishing avec une pièce jointe (pas un lien)"
            ],
            "hint_cost": 17
        },
        {
            "id": "q2",
            "text": "Quelle technique correspond au dump de credentials via Mimikatz/LSASS ? (format: T1003.XXX)",
            "answer": "T1003.001",
            "flag": "FLAG{T1003.001}",
            "points": 50,
            "hints": [
                "T1003 = OS Credential Dumping",
                ".001 = LSASS Memory"
            ],
            "hint_cost": 17
        },
        {
            "id": "q3",
            "text": "Combien d'IoC de type 'IP' distincts ont été identifiés au total ?",
            "answer": "4",
            "flag": "FLAG{4}",
            "points": 40,
            "hints": [
                "Comptez les lignes de type IP dans la table des IoC",
                "185.234.72.19, 91.234.56.78, 45.33.21.99, 185.220.101.34"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Combien de comptes au total ont été compromis ou créés par l'attaquant ?",
            "answer": "6",
            "flag": "FLAG{6}",
            "points": 40,
            "hints": [
                "Comptez tous les comptes dans la section Account des IoC",
                "ftpuser, svc-backup, admin.rsi, support_it, backdoor, j.martin"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Quelle technique MITRE correspond à l'exfiltration via DNS ? (format: T1048.XXX — le sous-numéro pour protocole alternatif)",
            "answer": "T1048",
            "flag": "FLAG{T1048}",
            "points": 50,
            "hints": [
                "T1048 = Exfiltration Over Alternative Protocol",
                "Le DNS n'est pas un protocole standard pour le transfert de données"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "À quel moment de la kill chain l'attaque aurait-elle pu être détectée le plus tôt ? (événement T-? jours)",
            "answer": "T-7",
            "flag": "FLAG{T-7}",
            "points": 50,
            "hints": [
                "Le premier événement malveillant est le phishing du 11/02",
                "EXCEL.EXE lançant cmd.exe/powershell.exe aurait dû déclencher une alerte EDR"
            ],
            "hint_cost": 17
        },
        {
            "id": "q7",
            "text": "Quel est le nombre total de fichiers malveillants (File IoC) identifiés ?",
            "answer": "9",
            "flag": "FLAG{9}",
            "points": 40,
            "hints": [
                "Comptez les lignes de type File dans la table des IoC"
            ],
            "hint_cost": 13
        },
        {
            "id": "q8",
            "text": "Quelle technique ATT&CK correspond au Golden Ticket ? (format: T1558.XXX)",
            "answer": "T1558.001",
            "flag": "FLAG{T1558.001}",
            "points": 60,
            "hints": [
                "T1558 = Steal or Forge Kerberos Tickets",
                ".001 = Golden Ticket"
            ],
            "hint_cost": 20
        },
        {
            "id": "q9",
            "text": "Combien de domaines malveillants distincts ont été utilisés dans l'attaque ?",
            "answer": "4",
            "flag": "FLAG{4}",
            "points": 40,
            "hints": [
                "Comptez les IoC de type Domain",
                "micros0ft-security.com, c2-update-service.xyz, update-service-cdn.xyz, redpawn-c0rp.com"
            ],
            "hint_cost": 13
        },
        {
            "id": "q10",
            "text": "Quelle technique correspond à l'utilisation de PsExec pour le mouvement latéral ? (format: T1570 ou T1021.XXX)",
            "answer": "T1021.002",
            "flag": "FLAG{T1021.002}",
            "points": 60,
            "hints": [
                "T1021 = Remote Services",
                ".002 = SMB/Windows Admin Shares (PsExec utilise les partages admin)"
            ],
            "hint_cost": 20
        }
    ]
}
