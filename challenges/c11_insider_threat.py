"""
Challenge 11 — Menace Interne (Insider Threat)
Niveau : 3 (Analyste Senior)
Catégorie : Threat Intelligence
"""

ARTIFACT_DLP_LOGS = r"""
=== LOGS DLP (Data Loss Prevention) — Anomalies détectées ===
=== Période : 10/02/2026 — 18/02/2026 ===

[DLP-001] 2026-02-10 18:45:12
  User:     s.moreau (Service RH — Responsable Paie)
  Action:   FILE_COPY_TO_USB
  File:     \\SRV-FILE-02\RH\Salaires_2025_Complet.xlsx (4.2 MB)
  Device:   USB Kingston DataTraveler (Serial: KT-9F8E7D6C)
  Policy:   Violation — Données confidentielles RH sur support amovible
  Status:   BLOCKED (Policy enforcement)
  
[DLP-002] 2026-02-11 12:30:45
  User:     s.moreau
  Action:   FILE_UPLOAD_CLOUD
  File:     \\SRV-FILE-02\RH\Salaires_2025_Complet.xlsx
  Dest:     https://drive.google.com (Personal account: sophie.moreau92@gmail.com)
  Policy:   Violation — Upload de données confidentielles vers cloud personnel
  Status:   BLOCKED
  
[DLP-003] 2026-02-12 08:15:00
  User:     s.moreau
  Action:   PRINT_JOB
  File:     \\SRV-FILE-02\RH\Salaires_2025_Complet.xlsx
  Printer:  PRT-RH-01 (Couleur, 47 pages)
  Policy:   Alert — Impression massive de données RH
  Status:   ALLOWED (impression autorisée mais loggée)

[DLP-004] 2026-02-13 19:22:33
  User:     s.moreau
  Action:   EMAIL_ATTACHMENT
  To:       recrutement@competitor-corp.com
  Subject:  "CV + Informations salariales pour entretien"
  File:     Grille_Salaires_RedPawn_2025.pdf (892 KB)
  Policy:   Violation — Envoi de données confidentielles par email externe
  Status:   BLOCKED + QUARANTINED

[DLP-005] 2026-02-14 20:10:00
  User:     s.moreau
  Action:   FILE_COPY_TO_USB
  File:     \\SRV-FILE-02\RH\Contrats\*.pdf (23 fichiers, 156 MB)
  Device:   USB Kingston DataTraveler (Serial: KT-9F8E7D6C)
  Policy:   Violation — Copie massive de contrats
  Status:   BLOCKED
  
[DLP-006] 2026-02-15 13:45:00
  User:     s.moreau
  Action:   SCREENSHOT_DETECTED
  App:      SnippingTool.exe → données RH affichées à l'écran
  Saved:    C:\Users\s.moreau\Pictures\Screenshots\capture*.png (12 fichiers)
  Policy:   Alert — Captures d'écran de données sensibles
  Status:   LOGGED (screenshots non bloqués)

[DLP-007] 2026-02-17 22:00:15
  User:     s.moreau
  Action:   FILE_ARCHIVE_CREATED  
  File:     C:\Users\s.moreau\Documents\personnel\backup_rh.7z (PASSWORD PROTECTED)
  Contents: Salaires, contrats, évaluations (estimé ~200 MB avant compression)
  Policy:   Alert — Création d'archive chiffrée avec données RH
  Status:   LOGGED

[DLP-008] 2026-02-18 09:55:00
  User:     s.moreau
  Action:   TOR_BROWSER_LAUNCH
  Process:  C:\Users\s.moreau\Desktop\Tor\tor.exe
  Dest:     185.220.101.34:443 (Tor Exit Node)
  Transfer: 2.3 MB uploaded
  Policy:   CRITICAL — Utilisation de Tor + upload de données
  Status:   DETECTED (corrélé avec alerte SIEM-2026-4404)
"""

ARTIFACT_HR_CONTEXT = r"""
=== CONTEXTE RH — CONFIDENTIEL ===
=== Fourni par: Direction RH avec autorisation légale ===

Employé: Sophie MOREAU (s.moreau)
Poste:   Responsable Paie — Service RH
Ancienneté: 5 ans
Évaluation 2025: "Performance insuffisante" — plan d'amélioration en cours

Événements récents:
- 05/02/2026: Entretien disciplinaire suite à des retards répétés
- 07/02/2026: Refus de promotion (poste de DRH adjoint attribué à un autre candidat)
- 08/02/2026: s.moreau a posé 2 semaines de congés à partir du 19/02/2026
- 10/02/2026: Début des alertes DLP (voir logs)

Note du manager:
"Sophie semble démotivée depuis le refus de promotion. Elle a mentionné avoir des 
entretiens chez un concurrent (Competitor Corp). Je m'inquiète qu'elle parte avec 
des données sensibles RH."
"""

CHALLENGE = {
    "id": "c11_insider_threat",
    "title": "🐍 Le Serpent dans le Nid",
    "category": "threat_intel",
    "level": 3,
    "points_total": 380,
    "estimated_time": "30-45 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 17h00  
**Priorité :** HAUTE  
**Source :** DLP + Direction RH — Suspicion de menace interne

---

En parallèle de l'incident ransomware, la Direction RH a contacté le SOC concernant un comportement suspect d'une employée du service Paie.

Les logs DLP montrent des tentatives répétées d'exfiltration de données sensibles. Attention : cette investigation est **distincte** de l'attaque externe.

> *"On a un problème interne en parallèle du ransomware. Sophie Moreau des RH essaie de sortir des données salariales depuis une semaine. La DRH a autorisé l'investigation. Analyse les logs DLP et le contexte RH, et donne-moi une évaluation de la menace."*

**Rappel juridique :** Cette investigation est encadrée par une autorisation de la Direction et du DPO. Tous les logs sont collectés conformément à la politique de sécurité signée par l'employée.
    """,
    "artifacts": [
        {
            "name": "dlp_alerts.log",
            "type": "dlp_log",
            "content": ARTIFACT_DLP_LOGS,
            "description": "Alertes DLP de la dernière semaine pour l'utilisatrice s.moreau"
        },
        {
            "name": "hr_context.txt",
            "type": "confidential",
            "content": ARTIFACT_HR_CONTEXT,
            "description": "Contexte RH — CONFIDENTIEL (communication autorisée)"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Combien de violations DLP (BLOCKED) l'utilisatrice a-t-elle déclenchées ?",
            "answer": "4",
            "flag": "FLAG{4}",
            "points": 30,
            "hints": [
                "Comptez les événements avec Status: BLOCKED",
                "DLP-001, DLP-002, DLP-004, DLP-005"
            ],
            "hint_cost": 10
        },
        {
            "id": "q2",
            "text": "Quel est le numéro de série du périphérique USB utilisé pour les tentatives de copie ?",
            "answer": "KT-9F8E7D6C",
            "flag": "FLAG{KT-9F8E7D6C}",
            "points": 40,
            "hints": [
                "Cherchez le serial du device USB dans les logs DLP",
                "C'est une clé Kingston DataTraveler"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "À quelle entreprise concurrente l'employée a-t-elle tenté d'envoyer des données salariales ?",
            "answer": "Competitor Corp",
            "flag": "FLAG{Competitor_Corp}",
            "points": 40,
            "hints": [
                "Regardez l'événement DLP-004 (email bloqué)",
                "Le domaine destinataire donne le nom"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Quel compte personnel cloud l'employée a-t-elle utilisé pour tenter l'upload ?",
            "answer": "sophie.moreau92@gmail.com",
            "flag": "FLAG{sophie.moreau92@gmail.com}",
            "points": 30,
            "hints": [
                "Regardez l'événement DLP-002",
                "C'est un compte Google Drive personnel"
            ],
            "hint_cost": 10
        },
        {
            "id": "q5",
            "text": "Combien de pages ont été imprimées lors de l'impression massive qui n'a PAS été bloquée ?",
            "answer": "47",
            "flag": "FLAG{47}",
            "points": 30,
            "hints": [
                "DLP-003 a le statut ALLOWED",
                "L'impression n'est que loggée, pas bloquée"
            ],
            "hint_cost": 10
        },
        {
            "id": "q6",
            "text": "Quel outil de capture d'écran a été utilisé pour contourner le DLP ?",
            "answer": "SnippingTool.exe",
            "flag": "FLAG{SnippingTool}",
            "points": 40,
            "hints": [
                "L'employée a changé de méthode quand les copies étaient bloquées",
                "C'est un outil Windows natif de capture d'écran"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Quel format d'archive protégée par mot de passe a été créé pour préparer l'exfiltration ?",
            "answer": "7z",
            "flag": "FLAG{7z}",
            "points": 40,
            "hints": [
                "Regardez l'événement DLP-007",
                "C'est un format de compression avec chiffrement intégré"
            ],
            "hint_cost": 13
        },
        {
            "id": "q8",
            "text": "Quel est l'événement déclencheur probable de la menace interne ? (date format JJ/MM/AAAA)",
            "answer": "07/02/2026",
            "flag": "FLAG{07/02/2026}",
            "points": 50,
            "hints": [
                "Regardez les événements RH récents",
                "Le refus de promotion est souvent un déclencheur classique"
            ],
            "hint_cost": 17
        },
        {
            "id": "q9",
            "text": "L'utilisation de Tor (DLP-008) est-elle liée à l'attaque ransomware externe ou à la menace interne ?",
            "answer": "menace interne",
            "flag": "FLAG{menace_interne}",
            "points": 50,
            "hints": [
                "Analysez qui a installé Tor et depuis quel poste",
                "s.moreau a installé Tor sur son bureau (Desktop), c'est une action volontaire de l'employée"
            ],
            "hint_cost": 17
        },
        {
            "id": "q10",
            "text": "Combien de MB de données ont été effectivement exfiltrées via Tor ?",
            "answer": "2.3",
            "flag": "FLAG{2.3}",
            "points": 30,
            "hints": [
                "Regardez le volume d'upload dans DLP-008",
                "2.3 MB uploaded"
            ],
            "hint_cost": 10
        }
    ]
}
