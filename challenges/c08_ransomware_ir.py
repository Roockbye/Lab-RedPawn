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

[T-7 jours] 11/02/2026 14:23 UTC
  Source: Email Gateway
  Event: Email de phishing reçu par j.martin@redpawn-corp.com
  Detail: Pièce jointe "Facture_Fevrier2026.xlsm" (macro malveillante)
  Sender: facturation@redpawn-c0rp.com (typosquatting)

[T-7 jours] 11/02/2026 14:31 UTC
  Source: EDR — WKS-COMPTA-PC03
  Event: EXCEL.EXE lance cmd.exe → powershell.exe
  Detail: Macro exécutée — téléchargement du stage 1
  IOC: hxxp://185.234.72[.]19:8080/stager.ps1

[T-7 jours] 11/02/2026 14:35 UTC
  Source: EDR — WKS-COMPTA-PC03
  Event: Persistence établie via registre Run
  Detail: GoogleChromeAutoUpdate → update_checker.ps1

[T-5 jours] 13/02/2026 02:15 UTC
  Source: DNS Logs
  Event: Première exfiltration DNS
  Detail: Reconnaissance système via DNS tunneling
  IOC: *.data.c2-update-service[.]xyz

[T-3 jours] 15/02/2026 22:00 UTC
  Source: DNS Logs
  Event: Exfiltration de credentials
  Detail: Mots de passe DB, VPN, API exfiltrés via DNS
  Impact: Credentials compromis (HR DB, MySQL root, VPN)

[T-0] 18/02/2026 08:15 UTC
  Source: SIEM
  Event: Début de l'attaque finale
  Detail: Brute force SSH sur srv-web-01 + exploitation webshell

[T-0] 18/02/2026 08:33 UTC
  Source: Windows Events — SRV-AD-01
  Event: Mouvement latéral vers le Domain Controller
  Detail: svc-backup compromis → Mimikatz → admin.rsi compromis

[T-0] 18/02/2026 08:42 UTC
  Source: Windows Events — SRV-AD-01
  Event: Extraction NTDS.dit
  Detail: ntdsutil IFM dump → backup.zip
  Impact: Tous les hashes du domaine compromis

[T-0] 18/02/2026 08:45 UTC
  Source: Windows Events — SRV-AD-01
  Event: Compte backdoor créé : support_it (Domain Admin)

[T-0] 18/02/2026 10:00 UTC
  Source: Firewall
  Event: Exfiltration massive via Tor depuis WKS-RH-PC01
  Detail: 2.3 MB uploadés, probablement le dump NTDS

[T-0] 18/02/2026 11:30 UTC
  Source: EDR — Multiple servers
  Event: Ransomware déployé via PsExec + compte support_it
  Detail: Chiffrement de SRV-FILE-02, SRV-DB-01, SRV-BACKUP-01
  IOC: Extension .ph0n, ransom note "README_RESTORE.txt"

[T-0] 18/02/2026 11:45 UTC
  Source: Helpdesk
  Event: Premiers tickets utilisateurs — fichiers inaccessibles
  Detail: "Mes fichiers ont une extension bizarre .ph0n"

[T-0] 18/02/2026 12:00 UTC
  Source: SOC
  Event: Incident déclaré — Sévérité P1
  Detail: Activation du plan IR, CERT notifié
"""

CHALLENGE = {
    "id": "c08_ransomware_ir",
    "title": "🚨 Code Rouge : Ransomware",
    "category": "incident_response",
    "level": 3,
    "points_total": 450,
    "estimated_time": "40-60 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 16h30  
**Priorité :** CRITIQUE — P1  
**Source :** Incident Response — Ransomware en cours

---

**SITUATION :** L'entreprise RedPawn Corp est sous attaque ransomware active. Trois serveurs ont été chiffrés. Le CERT a été activé et vous participez à la cellule de crise.

Vous avez accès à la note de rançon et à la timeline reconstituée de l'incident. Votre mission est d'analyser l'ensemble de la chaîne d'attaque.

> *"Situation de crise. On a du ransomware sur 3 serveurs. Le COMEX veut des réponses : comment on s'est fait avoir, quel est l'impact, et quelles sont les actions immédiates. Tu as la timeline et la ransom note — je veux une analyse complète."*

**Contexte d'équipe :** La timeline a été reconstituée grâce aux investigations des challenges précédents. Vous devez maintenant avoir une vision globale de bout en bout.
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
            "description": "Timeline de l'incident reconstituée par l'équipe forensic"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quel a été le vecteur d'attaque initial ?",
            "answer": "xlsm",
            "flag": "REDPAWN{xlsm}",
            "points": 40,
            "hints": [
                "Regardez l'événement T-7 jours dans la timeline",
                "C'est un fichier Excel avec macros"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Combien de jours se sont écoulés entre la compromission initiale et le déploiement du ransomware ?",
            "answer": "7",
            "flag": "REDPAWN{7}",
            "points": 40,
            "hints": [
                "La compromission initiale est le 11/02, le ransomware le 18/02",
                "Comptez les jours entre ces deux dates"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Quelle est l'extension ajoutée aux fichiers chiffrés par le ransomware ?",
            "answer": ".ph0n",
            "flag": "REDPAWN{.ph0n}",
            "points": 30,
            "hints": [
                "Regardez la note de rançon",
                "C'est mentionné dans la section 'WHAT HAPPENED'"
            ],
            "hint_cost": 10
        },
        {
            "id": "q4",
            "text": "Combien de BTC la rançon demandée s'élève-t-elle ?",
            "answer": "5",
            "flag": "REDPAWN{5}",
            "points": 30,
            "hints": [
                "Regardez la section 'HOW TO RECOVER' de la note"
            ],
            "hint_cost": 10
        },
        {
            "id": "q5",
            "text": "Quelle adresse email est utilisée par les attaquants pour le contact ?",
            "answer": "ph0n-support@protonmail.com",
            "flag": "REDPAWN{ph0n-support@protonmail.com}",
            "points": 30,
            "hints": [
                "Cherchez l'adresse email dans la note de rançon"
            ],
            "hint_cost": 10
        },
        {
            "id": "q6",
            "text": "Quel outil de déploiement distant a été utilisé pour propager le ransomware sur les serveurs ?",
            "answer": "PsExec",
            "flag": "REDPAWN{PsExec}",
            "points": 50,
            "hints": [
                "Regardez l'événement T-0 11:30 dans la timeline",
                "C'est un outil Sysinternals utilisé pour l'exécution à distance"
            ],
            "hint_cost": 17
        },
        {
            "id": "q7",
            "text": "Combien de serveurs ont été chiffrés au total ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 30,
            "hints": [
                "Comptez les serveurs listés dans la note de rançon",
                "SRV-FILE-02, SRV-DB-01, SRV-BACKUP-01"
            ],
            "hint_cost": 10
        },
        {
            "id": "q8",
            "text": "Quel est l'identifiant unique de la victime dans la note de rançon ?",
            "answer": "RPWN-2026-0218-A7F3B2C1",
            "flag": "REDPAWN{RPWN-2026-0218-A7F3B2C1}",
            "points": 30,
            "hints": [
                "Cherchez 'Unique ID' dans la note de rançon"
            ],
            "hint_cost": 10
        },
        {
            "id": "q9",
            "text": "Le domaine de typosquatting utilisé pour le phishing initial remplaçait quel caractère par quel autre ? (format: lettre_vers_chiffre)",
            "answer": "o_vers_0",
            "flag": "REDPAWN{o_vers_0}",
            "points": 40,
            "hints": [
                "Comparez redpawn-corp.com avec redpawn-c0rp.com",
                "Répondez au format lettre_vers_chiffre, ex: a_vers_1"
            ],
            "hint_cost": 13
        },
        {
            "id": "q10",
            "text": "Quel compte compromis a été utilisé pour déployer le ransomware ?",
            "answer": "support_it",
            "flag": "REDPAWN{support_it}",
            "points": 50,
            "hints": [
                "C'est le compte backdoor créé par l'attaquant",
                "Regardez l'événement T-0 11:30 dans la timeline"
            ],
            "hint_cost": 17
        },
        {
            "id": "q11",
            "text": "Pourquoi les backups ne peuvent-ils pas être utilisés pour la restauration ?",
            "answer": "SRV-BACKUP-01 a été chiffré",
            "flag": "REDPAWN{backup_chiffre}",
            "points": 40,
            "hints": [
                "Regardez la liste des serveurs chiffrés",
                "Le serveur de backup fait partie des cibles"
            ],
            "hint_cost": 13
        },
        {
            "id": "q12",
            "text": "Combien de temps s'est écoulé entre le début de l'attaque finale (08:15) et la déclaration d'incident (12:00) ? (format: XhYY)",
            "answer": "3h45",
            "flag": "REDPAWN{3h45}",
            "points": 40,
            "hints": [
                "De 08:15 à 12:00",
                "Calculez la différence en heures et minutes"
            ],
            "hint_cost": 13
        }
    ]
}
