"""
Challenge 11 -- Menace Interne (Insider Threat)
Niveau : 3 (Analyste Senior)
Categorie : Threat Intelligence
"""

ARTIFACT_DLP_LOGS = r"""
=== LOGS DLP (Data Loss Prevention) -- Toutes les anomalies ===
=== Periode : 10/02/2026 -- 18/02/2026 ===
=== Filtre: Tous les utilisateurs ayant declenche des alertes ===

[DLP-001] 2026-02-10 09:12:33
  User:     m.petit (Service Comptabilite -- Comptable Senior)
  Action:   FILE_COPY_TO_USB
  File:     \\SRV-FILE-02\Compta\Bilan_Q4_2025.xlsx (1.8 MB)
  Device:   USB SanDisk Cruzer (Serial: SD-4A5B6C7D)
  Policy:   Violation -- Donnees financieres sur support amovible
  Status:   BLOCKED (Policy enforcement)
  Context:  m.petit a demande une exception IT pour travail a domicile
            (exception REFUSEE par le RSSI le 11/02)

[DLP-002] 2026-02-10 18:45:12
  User:     s.moreau (Service RH -- Responsable Paie)
  Action:   FILE_COPY_TO_USB
  File:     \\SRV-FILE-02\RH\Salaires_2025_Complet.xlsx (4.2 MB)
  Device:   USB Kingston DataTraveler (Serial: KT-9F8E7D6C)
  Policy:   Violation -- Donnees confidentielles RH sur support amovible
  Status:   BLOCKED (Policy enforcement)

[DLP-003] 2026-02-11 08:22:00
  User:     a.bernard (Service Dev -- Lead Developer)
  Action:   FILE_UPLOAD_CLOUD
  File:     \\SRV-FILE-02\IT\Scripts\deploy_prod.sh (12 KB)
  Dest:     https://github.com (Entreprise account: redpawn-corp/infra)
  Policy:   Alert -- Upload de script vers repo Git
  Status:   ALLOWED (repo entreprise autorise)
  Context:  Workflow de deploiement normal

[DLP-004] 2026-02-11 12:30:45
  User:     s.moreau
  Action:   FILE_UPLOAD_CLOUD
  File:     \\SRV-FILE-02\RH\Salaires_2025_Complet.xlsx
  Dest:     https://drive.google.com (Personal account: sophie.moreau92@gmail.com)
  Policy:   Violation -- Upload de donnees confidentielles vers cloud personnel
  Status:   BLOCKED

[DLP-005] 2026-02-11 14:15:00
  User:     t.girard (Service IT -- Admin Systeme)
  Action:   FILE_COPY_TO_USB
  File:     C:\Tools\PuTTY.exe + C:\Tools\WinSCP.exe (8.5 MB)
  Device:   USB Kingston DataTraveler (Serial: KT-1A2B3C4D)
  Policy:   Alert -- Copie d'outils sur USB
  Status:   ALLOWED (outils IT autorises)
  Context:  Maintenance planifiee sur serveur salle serveur (hors reseau)

[DLP-006] 2026-02-12 08:15:00
  User:     s.moreau
  Action:   PRINT_JOB
  File:     \\SRV-FILE-02\RH\Salaires_2025_Complet.xlsx
  Printer:  PRT-RH-01 (Couleur, 47 pages)
  Policy:   Alert -- Impression massive de donnees RH
  Status:   ALLOWED (impression autorisee mais loggee)

[DLP-007] 2026-02-12 09:30:00
  User:     l.mercier (Service Commercial -- Directeur Commercial)
  Action:   EMAIL_ATTACHMENT
  To:       partenaire@logistics-partner.com
  Subject:  "Contrat de distribution 2026"
  File:     Contrat_Distribution_2026_Draft.pdf (2.1 MB)
  Policy:   Alert -- Envoi de contrat par email externe
  Status:   ALLOWED (destinataire dans whitelist partenaires)
  Context:  Negociation commerciale en cours (validee par Direction)

[DLP-008] 2026-02-13 07:55:00
  User:     m.petit
  Action:   PRINT_JOB
  File:     \\SRV-FILE-02\Compta\Factures_Fournisseurs_Q4.xlsx
  Printer:  PRT-COMPTA-01 (N&B, 8 pages)
  Policy:   No violation
  Status:   ALLOWED
  Context:  Impression normale pour archivage papier (procedure compta)

[DLP-009] 2026-02-13 19:22:33
  User:     s.moreau
  Action:   EMAIL_ATTACHMENT
  To:       recrutement@competitor-corp.com
  Subject:  "CV + Informations salariales pour entretien"
  File:     Grille_Salaires_RedPawn_2025.pdf (892 KB)
  Policy:   Violation -- Envoi de donnees confidentielles par email externe
  Status:   BLOCKED + QUARANTINED

[DLP-010] 2026-02-14 10:00:00
  User:     a.bernard
  Action:   FILE_UPLOAD_CLOUD
  File:     C:\Users\a.bernard\Documents\presentation_archi.pptx (15 MB)
  Dest:     https://drive.google.com (Personal: a.bernard.dev@gmail.com)
  Policy:   Alert -- Upload vers cloud personnel
  Status:   BLOCKED (donnees internes vers cloud perso)
  Context:  a.bernard prepare une presentation pour une conference tech
            (demande d'exception en cours aupres de la DSI)

[DLP-011] 2026-02-14 20:10:00
  User:     s.moreau
  Action:   FILE_COPY_TO_USB
  File:     \\SRV-FILE-02\RH\Contrats\*.pdf (23 fichiers, 156 MB)
  Device:   USB Kingston DataTraveler (Serial: KT-9F8E7D6C)
  Policy:   Violation -- Copie massive de contrats
  Status:   BLOCKED

[DLP-012] 2026-02-15 11:20:00
  User:     l.mercier
  Action:   FILE_COPY_TO_USB
  File:     \\SRV-FILE-02\Commercial\Pricing_2026.xlsx (3.4 MB)
  Device:   USB SanDisk Ultra (Serial: SD-8E9F0A1B)
  Policy:   Violation -- Donnees commerciales sur support amovible
  Status:   BLOCKED
  Context:  l.mercier voulait emporter les tarifs pour un RDV client
            Dirigee vers le portail securise de partage

[DLP-013] 2026-02-15 13:45:00
  User:     s.moreau
  Action:   SCREENSHOT_DETECTED
  App:      SnippingTool.exe -> donnees RH affichees a l'ecran
  Saved:    C:\Users\s.moreau\Pictures\Screenshots\capture*.png (12 fichiers)
  Policy:   Alert -- Captures d'ecran de donnees sensibles
  Status:   LOGGED (screenshots non bloques)
  Analysis: Les 12 captures contiennent des grilles salariales et des
            evaluations de performance

[DLP-014] 2026-02-16 16:30:00
  User:     t.girard
  Action:   FILE_COPY_TO_USB
  File:     C:\Backups\firewall_config_backup.xml (245 KB)
  Device:   USB Kingston DataTraveler (Serial: KT-1A2B3C4D)
  Policy:   Violation -- Config firewall sur support amovible
  Status:   BLOCKED
  Context:  t.girard tentait de sauvegarder la config FW avant mise a jour
            Procédure non conforme (doit passer par le coffre-fort numerique)

[DLP-015] 2026-02-17 22:00:15
  User:     s.moreau
  Action:   FILE_ARCHIVE_CREATED
  File:     C:\Users\s.moreau\Documents\personnel\backup_rh.7z (PASSWORD PROTECTED)
  Contents: Salaires, contrats, evaluations (estime ~200 MB avant compression)
  Policy:   Alert -- Creation d'archive chiffree avec donnees RH
  Status:   LOGGED
  Analysis: Archive 7z avec chiffrement AES-256 -- mot de passe inconnu
            Creee a 22:00 (hors heures de bureau)

[DLP-016] 2026-02-18 08:30:00
  User:     m.petit
  Action:   EMAIL_ATTACHMENT
  To:       cabinet-audit@deloitte.fr
  Subject:  "Documents pour audit annuel 2025"
  File:     Export_Comptable_2025.xlsx + Annexes_Fiscales.pdf (12 MB total)
  Policy:   Alert -- Envoi de donnees financieres par email
  Status:   ALLOWED (Deloitte dans whitelist auditeurs)
  Context:  Audit annuel planifie -- autorise par le DAF

[DLP-017] 2026-02-18 09:55:00
  User:     s.moreau
  Action:   TOR_BROWSER_LAUNCH
  Process:  C:\Users\s.moreau\Desktop\Tor\tor.exe
  Dest:     185.220.101.34:443 (Tor Exit Node)
  Transfer: 2.3 MB uploaded via Tor circuit
  Policy:   CRITICAL -- Utilisation de Tor + upload de donnees
  Status:   DETECTED (correle avec alerte SIEM-2026-4404)
  Analysis: L'upload de 2.3 MB correspond approximativement a la taille
            des 12 captures d'ecran + grille salariale PDF

[DLP-018] 2026-02-18 10:30:00
  User:     s.moreau
  Action:   BROWSER_HISTORY_ANOMALY
  URLs visited (derniere heure):
    - https://www.competitor-corp.com/carrieres
    - https://www.indeed.fr/emploi-responsable-paie
    - https://anonymousemail.me (service d'email anonyme)
    - https://www.protonmail.com (creation de compte?)
    - https://transfert.free.fr (service de transfert de fichiers)
  Policy:   Alert -- Navigation suspecte
  Status:   LOGGED
"""

ARTIFACT_HR_CONTEXT = r"""
=== CONTEXTE RH -- CONFIDENTIEL ===
=== Fourni par: Direction RH avec autorisation legale ===

Employe: Sophie MOREAU (s.moreau)
Poste:   Responsable Paie -- Service RH
Anciennete: 5 ans
Evaluation 2025: "Performance insuffisante" -- plan d'amelioration en cours
Acces IT: Lecteur \\SRV-FILE-02\RH (lecture + ecriture), pas d'acces admin

Evenements recents:
- 05/02/2026: Entretien disciplinaire suite a des retards repetes
- 07/02/2026: Refus de promotion (poste de DRH adjoint attribue a un autre candidat)
- 08/02/2026: s.moreau a pose 2 semaines de conges a partir du 19/02/2026
- 09/02/2026: Notation du plan d'amelioration: 2/5 ("insuffisant")
- 10/02/2026: Debut des alertes DLP (voir logs)

Note du manager (M. Durand, DRH):
"Sophie semble demotivee depuis le refus de promotion. Elle a mentionne avoir des
entretiens chez un concurrent (Competitor Corp). Je m'inquiete qu'elle parte avec
des donnees sensibles RH. Elle a acces a toutes les grilles salariales et aux
contrats de travail."

Note complementaire (RSSI):
"L'investigation DLP revele un pattern classique d'escalade: USB bloque -> cloud bloque ->
email bloque -> impression -> screenshots -> archive chiffree -> Tor. L'employeee adapte
ses methodes a chaque blocage, montrant une determination croissante."
"""

ARTIFACT_UEBA_REPORT = r"""
=== RAPPORT UEBA (User Entity & Behavior Analytics) ===
=== Utilisateur: s.moreau ===
=== Periode d'analyse: 01/01/2026 -- 18/02/2026 ===
=== Outil: Microsoft Sentinel UEBA ===

--- SCORE DE RISQUE ---
  Score actuel: 87/100 (CRITIQUE)
  Baseline (janvier): 12/100 (normal)
  Premiere elevation: 10/02/2026 (score 45)
  Escalade rapide: 13/02/2026 (score 72)
  Score max: 18/02/2026 (score 87)

--- ANOMALIES COMPORTEMENTALES DETECTEES ---

1. HORAIRES DE CONNEXION ANORMAUX
   Baseline janvier: Connexion 08:30-17:30 (5j/7)
   Fevrier:
   - 10/02: Connexion 07:00-20:15 (+3h45 au-dessus baseline)
   - 11/02: Connexion 07:30-19:00
   - 13/02: Connexion 08:00-21:30 (+4h)
   - 14/02: Connexion 08:30-22:10 (+4h40)
   - 15/02: Connexion SAMEDI 10:00-16:00 (jamais travaille le week-end avant)
   - 17/02: Connexion DIMANCHE 20:00-23:30 (creation archive)

2. ACCES AUX FICHIERS — VOLUME ANORMAL
   Baseline janvier: ~45 fichiers/jour (acces normaux RH)
   Fevrier:
   - 10/02: 234 fichiers accedes (+420%)
   - 11/02: 189 fichiers
   - 12/02: 312 fichiers (+593%)
   - 13/02: 156 fichiers
   - 14/02: 87 fichiers (tentative USB massive)
   - 15/02-17/02: 456 fichiers (screenshots systematiques)
   Total: 1,434 fichiers accedes en 8 jours vs 360 en janvier (tout le mois)

3. CHANGEMENT DE COMPORTEMENT RESEAU
   Baseline: Navigation SharePoint + application RH interne uniquement
   Nouveau:
   - Premiere visite sur Google Drive personnel (11/02)
   - Recherches Indeed/LinkedIn (depuis le 08/02)
   - Site competitor-corp.com/carrieres (depuis le 09/02)
   - Premiere visite transfert.free.fr (18/02)
   - Installation Tor Browser (17/02) — JAMAIS vu sur le parc
   - Visite anonymousemail.me (18/02)

4. COMPARAISON AVEC LES PAIRS (Service RH)
   Utilisateur    | Fichiers/jour | Alertes DLP | Heures sup | USB attempts
   ---------------+---------------+-------------+------------+------------
   s.moreau       | 179 (moy fev) | 7 BLOCKED   | +28h       | 3 (meme USB)
   c.lambert (RH) | 52            | 0           | 0          | 0
   n.faure (RH)   | 48            | 1 (ALLOWED) | +2h        | 0
   v.rousseau(RH) | 41            | 0           | 0          | 0

   -> s.moreau est un outlier significatif (> 3 ecarts-types de la moyenne)

5. INDICATEURS "FLIGHT RISK" (risque de depart)
   [X] Visite sites emploi (Indeed, LinkedIn Jobs) — depuis 08/02
   [X] Contact avec un concurrent connu (email bloque) — 13/02
   [X] Pose de conges prolonges — 08/02
   [X] Horaires hors norme (evenings/weekends) — depuis 10/02
   [X] Tentatives d'exfiltration de donnees multiples — 8 incidents
   [X] Escalade des methodes apres chaque blocage — pattern confirme
   [ ] Demission officielle — PAS ENCORE
   Score Flight Risk: 6/7 criteres remplis -- TRES ELEVE
"""

CHALLENGE = {
    "id": "c11_insider_threat",
    "title": "Le Serpent dans le Nid",
    "category": "threat_intel",
    "level": 3,
    "points_total": 530,
    "estimated_time": "40-60 min",
    "story": """
## Briefing de Mission

**Date :** 18 fevrier 2026, 17h00
**Priorite :** HAUTE
**Source :** DLP + Direction RH -- Suspicion de menace interne

---

En parallele de l'incident ransomware, la Direction RH a contacte le SOC concernant un comportement suspect d'une employee du service Paie.

Les logs DLP montrent des anomalies multiples provenant de PLUSIEURS utilisateurs. Vous devez distinguer les comportements normaux des veritables tentatives d'exfiltration.

> *"On a un probleme interne en parallele du ransomware. Le DLP a declenche des alertes sur plusieurs utilisateurs cette semaine. La DRH suspecte Sophie Moreau des RH d'essayer de sortir des donnees salariales. Mais attention, il y a aussi des alertes sur d'autres employes -- il faut faire le tri. L'investigation est autorisee. Analyse les logs DLP, le contexte RH et le rapport UEBA, et donne-moi une evaluation de la menace."*

**Rappel juridique :** Cette investigation est encadree par une autorisation de la Direction et du DPO. Tous les logs sont collectes conformement a la politique de securite signee par l'employee.

<details>
<summary>Indice methodologique (cliquez pour afficher)</summary>

Les logs DLP contiennent des evenements de PLUSIEURS utilisateurs. Tous ne sont pas malveillants. Comparez les comportements avec le rapport UEBA et le contexte RH pour distinguer les vrais incidents des faux positifs operationnels.

</details>
    """,
    "artifacts": [
        {
            "name": "dlp_alerts.log",
            "type": "dlp_log",
            "content": ARTIFACT_DLP_LOGS,
            "description": "Alertes DLP de tous les utilisateurs -- derniere semaine"
        },
        {
            "name": "hr_context.txt",
            "type": "confidential",
            "content": ARTIFACT_HR_CONTEXT,
            "description": "Contexte RH -- CONFIDENTIEL (communication autorisee)"
        },
        {
            "name": "ueba_report_s.moreau.txt",
            "type": "analytics",
            "content": ARTIFACT_UEBA_REPORT,
            "description": "Rapport UEBA Microsoft Sentinel -- Analyse comportementale"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Combien d'utilisateurs DISTINCTS ont declenche des alertes DLP sur la periode ?",
            "answer": "5",
            "flag": "REDPAWN{5}",
            "points": 30,
            "hints": [
                "Parcourez tous les events DLP et listez les noms d'utilisateurs uniques",
                "s.moreau, m.petit, a.bernard, t.girard, l.mercier"
            ],
            "hint_cost": 10
        },
        {
            "id": "q2",
            "text": "Combien d'alertes DLP de s.moreau ont ete BLOQUEES (pas juste loggees) ?",
            "answer": "4",
            "flag": "REDPAWN{4}",
            "points": 30,
            "hints": [
                "Comptez les events DLP de s.moreau avec Status: BLOCKED",
                "DLP-002, DLP-004, DLP-009, DLP-011"
            ],
            "hint_cost": 10
        },
        {
            "id": "q3",
            "text": "L'alerte DLP-010 (a.bernard upload cloud perso) est-elle un vrai insider threat ? (oui/non)",
            "answer": "non",
            "flag": "REDPAWN{non}",
            "points": 40,
            "hints": [
                "Lisez le contexte de DLP-010: c'est pour une conference tech",
                "Une demande d'exception est en cours -- c'est une violation de procedure, pas un vol de donnees"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Quel est le pattern d'escalade des methodes de s.moreau ? Citez les 6 methodes dans l'ordre chronologique (separes par des virgules).",
            "answer": "USB,cloud,impression,email,screenshot,Tor",
            "flag": "REDPAWN{USB,cloud,impression,email,screenshot,Tor}",
            "points": 60,
            "hints": [
                "Suivez la chronologie des DLP pour s.moreau du 10/02 au 18/02",
                "Chaque fois qu'une methode est bloquee, elle en essaie une autre"
            ],
            "hint_cost": 20
        },
        {
            "id": "q5",
            "text": "Quel est le score de risque UEBA actuel de s.moreau ? (sur 100)",
            "answer": "87",
            "flag": "REDPAWN{87}",
            "points": 30,
            "hints": [
                "Regardez le rapport UEBA en haut",
                "C'est dans la section SCORE DE RISQUE"
            ],
            "hint_cost": 10
        },
        {
            "id": "q6",
            "text": "Combien de fichiers s.moreau a-t-elle accede le 12/02 (jour de pic) ?",
            "answer": "312",
            "flag": "REDPAWN{312}",
            "points": 30,
            "hints": [
                "Regardez la section ACCES AUX FICHIERS du rapport UEBA",
                "Le pourcentage d'augmentation est aussi mentionne"
            ],
            "hint_cost": 10
        },
        {
            "id": "q7",
            "text": "L'alerte DLP-016 (m.petit envoi a Deloitte) est-elle suspecte ? Pourquoi ? (oui/non)",
            "answer": "non",
            "flag": "REDPAWN{non}",
            "points": 40,
            "hints": [
                "Deloitte est dans la whitelist des auditeurs",
                "C'est un audit annuel planifie, autorise par le DAF"
            ],
            "hint_cost": 13
        },
        {
            "id": "q8",
            "text": "Quel est l'evenement declencheur probable de la menace interne ? (date format JJ/MM/AAAA)",
            "answer": "07/02/2026",
            "flag": "REDPAWN{07/02/2026}",
            "points": 50,
            "hints": [
                "Regardez les evenements RH recents dans le contexte",
                "Le refus de promotion est souvent un declencheur classique d'insider threat"
            ],
            "hint_cost": 17
        },
        {
            "id": "q9",
            "text": "Combien de criteres 'Flight Risk' sur 7 sont remplis dans le rapport UEBA ?",
            "answer": "6",
            "flag": "REDPAWN{6}",
            "points": 30,
            "hints": [
                "Comptez les criteres coches [X] dans la section Flight Risk",
                "Un seul critere n'est pas coche"
            ],
            "hint_cost": 10
        },
        {
            "id": "q10",
            "text": "Le meme numero de serie USB (KT-9F8E7D6C) apparait combien de fois dans les logs DLP ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 40,
            "hints": [
                "Cherchez KT-9F8E7D6C dans tous les evenements DLP",
                "DLP-002, DLP-011, et comparaison UEBA"
            ],
            "hint_cost": 13
        },
        {
            "id": "q11",
            "text": "Quelle est la taille estimee de l'upload Tor (DLP-017) et a quoi correspond-elle probablement ?",
            "answer": "2.3 MB",
            "flag": "REDPAWN{2.3}",
            "points": 40,
            "hints": [
                "Regardez l'analyse dans DLP-017",
                "Ca correspond aux 12 captures d'ecran + grille salariale PDF"
            ],
            "hint_cost": 13
        },
        {
            "id": "q12",
            "text": "Selon la comparaison UEBA avec les pairs RH, de combien d'ecarts-types s.moreau depasse-t-elle la moyenne ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 40,
            "hints": [
                "Regardez la section comparaison avec les pairs dans le rapport UEBA",
                "Elle est qualifiee d'outlier significatif"
            ],
            "hint_cost": 13
        },
        {
            "id": "q13",
            "text": "Le DLP-014 (t.girard copie config FW) est-il un insider threat ? (oui/non) Justification ?",
            "answer": "non",
            "flag": "REDPAWN{non}",
            "points": 50,
            "hints": [
                "t.girard est admin systeme -- c'est son role de gerer les configs FW",
                "C'est une violation de procedure (il devrait utiliser le coffre-fort numerique) mais pas un vol de donnees"
            ],
            "hint_cost": 17
        }
    ]
}
