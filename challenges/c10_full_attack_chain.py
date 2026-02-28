"""
Challenge 10 — Reconstruction de la Chaine d'Attaque Complete
Niveau : 4 (Expert SOC)
Categorie : Incident Response
"""

ARTIFACT_ATTACK_CHAIN = r"""
=== MATRICE ATT&CK — MAPPING DE L'INCIDENT REDPAWN-2026-0218 ===
=== Classification: TLP:AMBER ===

Completez cette matrice en identifiant les techniques utilisees a chaque etape.

PHASE              | DESCRIPTION                                            | TECHNIQUE   | SUB-TECHNIQUE
-------------------+--------------------------------------------------------+-------------+--------------
Initial Access     | Email phishing avec macro Excel (.xlsm)                | T????       |  .???
Execution #1       | Macro VBA Auto_Open -> cmd.exe -> powershell.exe       | T????       |  .???
Execution #2       | PowerShell -EncodedCommand (IEX download cradle)       | T????       |  .???
Persistence #1     | Registre Run — GoogleChromeAutoUpdate                  | T????       |  .???
Persistence #2     | Tache planifiee — Faux GatherNetworkInfo (DLL)         | T????       |  .???
Persistence #3     | Service Windows — WinDefenderUpdate                    | T????       |  .???
Persistence #4     | WMI Event Subscription (CommandLineEventConsumer)      | T????       |  .???
Persistence #5     | Golden Ticket Kerberos (RC4, 10 ans)                   | T????       |  .???
Defense Evasion #1 | Obfuscation PowerShell ([char[]] + Base64)             | T????       |  .???
Defense Evasion #2 | Masquerading — faux certificat Microsoft               | T????       |  .???
Defense Evasion #3 | Anti-VM/Anti-Debug (Get-Process check)                 | T????       |  .???
Defense Evasion #4 | DLL Side-Loading (ntevt.dll via rundll32)              | T????       |  .???
Credential Access  | Mimikatz (sekurlsa::logonpasswords + NTDS dump)        | T????       |  .???
Discovery #1       | net group, net user, whoami, ipconfig, nltest          | T????       |
Discovery #2       | DNS reverse lookups internes                           | T????       |
Lateral Movement #1| PsExec + Pass-the-Hash (NTLM)                         | T????       |  .???
Lateral Movement #2| SSH brute force (SRV-WEB-01) + webshell                | T????       |  .???
Collection         | ntdsutil IFM dump (NTDS.dit + SYSTEM hive)            | T????       |
Exfiltration #1    | DNS Tunneling (TXT records via c2-update-service.xyz)  | T????       |  .???
Exfiltration #2    | Tor upload depuis WKS-RH-PC01                          | T????       |  .???
Impact #1          | Ransomware (chiffrement AES-256 + RSA-4096)            | T????       |
Impact #2          | Suppression shadow copies (vssadmin)                   | T????       |
"""

ARTIFACT_IOC_LIST = r"""
=== INDICATEURS DE COMPROMISSION (IoC) — LISTE A VALIDER ===
=== Source: CTI Team + CERT + Forensics ===
=== NOTE: Cette liste combine les IoC confirmes ET des IoC "candidats" ===
=== provenant de sources de threat intelligence ouvertes.             ===
=== Votre travail: VALIDER lesquels sont lies a cet incident.        ===

NO | TYPE          | VALEUR                                        | SOURCE          | STATUT
---+---------------+-----------------------------------------------+-----------------+---------
01 | IP            | 185.234.72.19                                 | Forensic        | ???
02 | IP            | 91.234.56.78                                  | Email Gateway   | ???
03 | IP            | 45.33.21.99                                   | DNS Logs        | ???
04 | IP            | 185.220.101.34                                | Firewall        | ???
05 | IP            | 71.6.167.142                                  | WAF Logs        | ???
06 | IP            | 167.248.133.56                                | WAF Logs        | ???
07 | IP            | 10.0.1.30                                     | Win Events      | ???
08 | IP            | 10.0.3.45                                     | Multiple        | ???
09 | Domain        | micros0ft-security.com                        | CTI Feed        | ???
10 | Domain        | c2-update-service.xyz                         | DNS Logs        | ???
11 | Domain        | update-service-cdn.xyz                        | CTI Report      | ???
12 | Domain        | redpawn-c0rp.com                              | Email Gateway   | ???
13 | Domain        | malware-traffic-analysis.net                  | CTI Feed        | ???
14 | Domain        | checkip.amazonaws.com                         | Proxy Logs      | ???
15 | Email         | facturation@redpawn-c0rp.com                  | Email Gateway   | ???
16 | Email         | ph0n-support@protonmail.com                   | Ransom Note     | ???
17 | BTC           | bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh   | Ransom Note     | ???
18 | File          | Facture_Fevrier2026.xlsm                      | Email Gateway   | ???
19 | File          | update_checker.ps1                            | EDR             | ???
20 | File          | logo-update.php                               | Web Logs        | ???
21 | File          | stager.ps1                                    | Proxy Logs      | ???
22 | File          | svc.exe                                       | Forensic        | ???
23 | File          | updater.exe                                   | Forensic        | ???
24 | File          | ntevt.dll                                     | Forensic        | ???
25 | File          | shell.elf                                     | EDR             | ???
26 | File          | d3d11.dll                                     | Sysmon          | ???
27 | File          | ransomware.exe                                | Forensic        | ???
28 | File          | crypt0r.exe                                   | AmCache         | ???
29 | File          | PsExec.exe                                    | Forensic        | ???
30 | Hash SHA256   | 8f14e45fceea167a5a36dedd4bea254304b8e5b...    | AmCache         | ???
31 | Hash SHA256   | e4a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a...    | Forensic        | ???
32 | Hash SHA256   | f1e2d3c4b5a6978869504132a1b2c3d4e5f6a7b...    | Forensic        | ???
33 | Hash SHA256   | a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b...    | Forensic        | ???
34 | Account       | ftpuser                                       | Auth Logs       | ???
35 | Account       | svc-backup                                    | Win Events      | ???
36 | Account       | admin.rsi                                     | Win Events      | ???
37 | Account       | support_it                                    | Win Events      | ???
38 | Account       | backdoor                                      | Auth Logs       | ???
39 | Account       | j.martin                                      | Email/EDR       | ???
40 | Account       | svc-sql                                       | SQL Logs        | ???
41 | Registry      | HKCU\..\Run\GoogleChromeAutoUpdate             | Autoruns        | ???
42 | Registry      | HKLM\..\Run\WindowsOptimizer                  | Autoruns        | ???

NOTES DE VALIDATION:
- IoC #05 (71.6.167.142): IP Shodan scanner — confirme par abuse DB
- IoC #06 (167.248.133.56): IP Censys scanner — confirme par abuse DB
- IoC #07 (10.0.1.30): IP interne SRV-BACKUP-01 (connexion legitime a 06:00)
- IoC #13 (malware-traffic-analysis.net): Site de recherche en securite (faux positif CTI)
- IoC #14 (checkip.amazonaws.com): Service AWS legitime, mais UTILISE par l'attaquant pour recon
- IoC #28/29 (crypt0r.exe/PsExec.exe): ransomware.exe = crypt0r.exe (renomme), PsExec = outil legitime Sysinternals utilise malicieusement
- IoC #40 (svc-sql): Compte de service SQL — NON compromis dans cet incident
"""

ARTIFACT_DETECTION_GAPS = r"""
=== ANALYSE DES LACUNES DE DETECTION ===
=== Objectif: Identifier ce qui a ete detecte, manque, et pourrait etre ameliore ===

NO | EVENEMENT                        | DETECTE? | PAR QUOI?        | ACTION N1      | RESULTAT
---+----------------------------------+----------+------------------+----------------+----------
01 | Email phishing (T-7)             | OUI      | ProofPoint       | Score 42/100   | NON BLOQUE (seuil 65)
02 | Macro -> PS execution (T-7)       | OUI      | CrowdStrike EDR  | Alerte HIGH    | NON BLOQUE (detect-only)
03 | Persistence registre (T-7)       | NON      | —                | —              | MANQUE
04 | DNS tunneling (T-5)              | NON      | —                | —              | MANQUE (pas de detection DNS)
05 | Exfil credentials DNS (T-3)       | NON      | —                | —              | MANQUE
06 | Scan Nessus legitime (T-4)        | OUI      | SIEM             | Planifie       | OK (faux positif evite)
07 | SSH brute force (T-0 08:15)       | OUI      | Suricata IDS     | Alerte         | DETECTE mais trop tard
08 | Webshell access (T-0 08:22)       | OUI      | Suricata IDS     | Alerte         | DETECTE mais trop tard
09 | Lateral movement DC (T-0 08:33)   | PARTIEL  | SIEM             | Alerte basse   | SOUS-EVALUE
10 | Mimikatz/credential dump (T-0)    | OUI      | Sysmon Event 10  | —              | PAS DE CORRELATON SIEM
11 | NTDS.dit dump (T-0 08:42)         | NON      | —                | —              | MANQUE (pas de regle)
12 | Backdoor account (T-0 08:45)      | OUI      | SIEM (4720+4732) | Alerte Medium  | DETECTE — 25min retard
13 | Unusual RDP (T-0 09:00)           | OUI      | SIEM             | Analyst N1     | CLASSE FAUX POSITIF !!!
14 | Tor exfiltration (T-0 10:00)      | OUI      | Suricata + FW    | Alerte         | DETECTE mais trop tard
15 | PsExec deployment (T-0 11:22)     | OUI      | Suricata         | Alerte         | DETECTE mais trop tard
16 | Ransomware execution (T-0 11:25)  | OUI      | CrowdStrike      | CRITICAL       | NON BLOQUE (detect-only)
17 | VSS deletion (T-0 11:28)          | OUI      | Suricata         | Alerte         | DETECTE mais trop tard

RESUME DES LACUNES CRITIQUES:
  A) CrowdStrike EDR en mode DETECT-ONLY sur les serveurs (pas de prevention)
  B) Aucune detection DNS (pas de DNS security / pas de regles sur DNS tunneling)
  C) Pas de regle SIEM pour ntdsutil / IFM dump
  D) Alerte RDP anomale classee faux positif par l'analyste N1 (erreur humaine)
  E) ProofPoint seuil de blocage trop eleve (65 au lieu de 50)
  F) Pas de segmentation reseau (workstation -> DC autorise en SMB)
  G) Pas de backup air-gapped (hors-site)
  H) Sysmon Event 10 (credential dump) pas integre dans les regles SIEM
"""

CHALLENGE = {
    "id": "c10_full_attack_chain",
    "title": "L'Autopsie Complete",
    "category": "incident_response",
    "level": 4,
    "points_total": 640,
    "estimated_time": "55-75 min",
    "story": """
## Briefing de Mission

**Date :** 18 fevrier 2026, 20h00
**Priorite :** POST-INCIDENT
**Source :** Direction -- Demande de rapport executif

---

L'incident est sous controle. Le COMEX (Comite Executif) demande un rapport complet de l'attaque. Vous devez mapper l'ensemble de la chaine d'attaque sur la matrice MITRE ATT&CK, valider la liste des IoC, et analyser les lacunes de detection.

> *"Le DG veut un rapport pour le conseil d'administration demain matin. J'ai besoin que tu mappes toute la kill chain sur MITRE ATT&CK, que tu valides les IoC (attention, il y a du bruit dans la liste — des faux positifs CTI et des IoC internes), et que tu identifies les lacunes de detection. Pourquoi on n'a pas pu stopper ca plus tot ? C'est notre retour d'experience."*

**Objectif :** Demonstrer votre comprehension globale de la chaine d'attaque, valider les IoC, et proposer des ameliorations de detection.

<details>
<summary>Indice methodologique (cliquez pour afficher)</summary>

La matrice ATT&CK utilise le format TXXxx.YYY. Cherchez les techniques sur attack.mitre.org. Pour les IoC, croisez les sources et les notes de validation pour distinguer les vrais IoC des faux positifs.

</details>
    """,
    "artifacts": [
        {
            "name": "attack_chain_mapping.txt",
            "type": "report",
            "content": ARTIFACT_ATTACK_CHAIN,
            "description": "Matrice ATT&CK a completer (22 techniques)"
        },
        {
            "name": "ioc_validation_list.txt",
            "type": "ioc_list",
            "content": ARTIFACT_IOC_LIST,
            "description": "Liste des 42 IoC a valider (confirmes + candidats + faux positifs)"
        },
        {
            "name": "detection_gap_analysis.txt",
            "type": "analysis",
            "content": ARTIFACT_DETECTION_GAPS,
            "description": "Analyse des lacunes de detection — 17 evenements evalues"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quelle technique MITRE ATT&CK correspond au phishing avec piece jointe ?",
            "answer": "T1566.001",
            "flag": "REDPAWN{T1566.001}",
            "points": 40,
            "hints": [
                "T1566 = Phishing, le sous-numero .001 = Spearphishing Attachment",
                "C'est du phishing avec une piece jointe (pas un lien)"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Quelle technique correspond au dump de credentials via Mimikatz/LSASS ?",
            "answer": "T1003.001",
            "flag": "REDPAWN{T1003.001}",
            "points": 40,
            "hints": [
                "T1003 = OS Credential Dumping",
                ".001 = LSASS Memory"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Dans la liste des IoC, combien sont des FAUX POSITIFS (non lies a l'incident) ? (IoC #05, #06, #07, #13, #40)",
            "answer": "5",
            "flag": "REDPAWN{5}",
            "points": 50,
            "hints": [
                "Lisez attentivement les NOTES DE VALIDATION en bas de la liste IoC",
                "#05=Shodan, #06=Censys, #07=IP interne legitime, #13=site recherche, #40=non compromis"
            ],
            "hint_cost": 17
        },
        {
            "id": "q4",
            "text": "L'IoC #14 (checkip.amazonaws.com) est un service AWS legitime. Pourquoi est-il quand meme pertinent ?",
            "answer": "utilise par l'attaquant pour la reconnaissance",
            "flag": "REDPAWN{reconnaissance}",
            "points": 50,
            "hints": [
                "Un service legitime peut etre utilise malicieusement",
                "L'attaquant l'a utilise pour verifier l'IP publique de l'organisation"
            ],
            "hint_cost": 17
        },
        {
            "id": "q5",
            "text": "Quel evenement critique (#13 dans l'analyse des lacunes) a ete classe comme faux positif par l'analyste N1 ?",
            "answer": "Unusual RDP connections",
            "flag": "REDPAWN{unusual_rdp}",
            "points": 50,
            "hints": [
                "Regardez l'evenement #13 dans la table des lacunes de detection",
                "C'est une alerte SIEM sur des connexions RDP anormales"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "Combien de lacunes critiques (A-H) sont listees dans le resume ? Quelle est la plus impactante selon vous ? (nombre)",
            "answer": "8",
            "flag": "REDPAWN{8}",
            "points": 30,
            "hints": [
                "Comptez les lettres dans le RESUME DES LACUNES CRITIQUES",
                "De A a H"
            ],
            "hint_cost": 10
        },
        {
            "id": "q7",
            "text": "Quelle technique ATT&CK correspond au Golden Ticket ?",
            "answer": "T1558.001",
            "flag": "REDPAWN{T1558.001}",
            "points": 50,
            "hints": [
                "T1558 = Steal or Forge Kerberos Tickets",
                ".001 = Golden Ticket"
            ],
            "hint_cost": 17
        },
        {
            "id": "q8",
            "text": "Quelle est la lacune de detection la plus critique qui a permis a l'attaquant d'operer 5 jours sans detection ? (lettre)",
            "answer": "B",
            "flag": "REDPAWN{B}",
            "points": 50,
            "hints": [
                "L'attaquant a utilise le DNS tunneling pendant 5 jours (T-5 a T-0)",
                "Quelle lacune concerne specifiquement la detection DNS ?"
            ],
            "hint_cost": 17
        },
        {
            "id": "q9",
            "text": "Combien de phases ATT&CK distinctes la chaine d'attaque couvre-t-elle dans la matrice ?",
            "answer": "10",
            "flag": "REDPAWN{10}",
            "points": 40,
            "hints": [
                "Comptez les phases uniques (Initial Access, Execution, Persistence, etc.)",
                "Attention: certaines phases ont plusieurs sous-entrees (#1, #2)"
            ],
            "hint_cost": 13
        },
        {
            "id": "q10",
            "text": "Le ransomware.exe est en realite quel fichier renomme ? (nom original)",
            "answer": "crypt0r.exe",
            "flag": "REDPAWN{crypt0r.exe}",
            "points": 40,
            "hints": [
                "Regardez la note de validation pour l'IoC #28",
                "L'AmCache revele le OriginalFilename"
            ],
            "hint_cost": 13
        },
        {
            "id": "q11",
            "text": "Quelle technique correspond a l'utilisation de PsExec pour le mouvement lateral ?",
            "answer": "T1021.002",
            "flag": "REDPAWN{T1021.002}",
            "points": 50,
            "hints": [
                "T1021 = Remote Services",
                ".002 = SMB/Windows Admin Shares (PsExec utilise les partages admin$)"
            ],
            "hint_cost": 17
        },
        {
            "id": "q12",
            "text": "Combien d'evenements ont ete DETECTES mais n'ont PAS pu etre bloques a temps ? (statut 'DETECTE mais trop tard' + 'NON BLOQUE')",
            "answer": "8",
            "flag": "REDPAWN{8}",
            "points": 50,
            "hints": [
                "Comptez les evenements avec resultat 'NON BLOQUE' ou 'DETECTE mais trop tard'",
                "Incluez les detect-only et les detections tardives"
            ],
            "hint_cost": 17
        },
        {
            "id": "q13",
            "text": "Si le seuil ProofPoint avait ete a 40 au lieu de 65, l'email aurait-il ete bloque ? (oui/non)",
            "answer": "non",
            "flag": "REDPAWN{non}",
            "points": 40,
            "hints": [
                "Le score de l'email etait 42/100",
                "42 > 40, donc il aurait TOUJOURS passe meme avec un seuil a 40"
            ],
            "hint_cost": 13
        },
        {
            "id": "q14",
            "text": "Quelle technique ATT&CK correspond a la suppression des shadow copies ?",
            "answer": "T1490",
            "flag": "REDPAWN{T1490}",
            "points": 50,
            "hints": [
                "T1490 = Inhibit System Recovery",
                "vssadmin delete shadows empeche la restauration"
            ],
            "hint_cost": 17
        }
    ]
}
