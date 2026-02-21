"""
Challenge 7 — Exfiltration DNS
Niveau : 3 (Analyste Senior)
Catégorie : Forensics Réseau
"""

ARTIFACT_DNS_LOGS = r"""
=== DNS Query Logs — Firewall/DNS Resolver (10.0.0.1) ===
=== Date: 2026-02-18 — Filtre: requêtes sortantes non-standard ===

2026-02-18 09:00:01.123 | QUERY  | 10.0.3.45  | A     | www.google.com                                    | NOERROR | 142.250.74.100
2026-02-18 09:00:15.456 | QUERY  | 10.0.3.45  | A     | outlook.office365.com                             | NOERROR | 52.96.87.14
2026-02-18 09:01:00.789 | QUERY  | 10.0.3.45  | TXT   | aG9zdG5hbWU6V0tTLUNPTVBUQS1QQzAz.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:01:01.234 | QUERY  | 10.0.3.45  | TXT   | dXNlcm5hbWU6ai5tYXJ0aW4=.data.c2-update-service.xyz         | NXDOMAIN | -
2026-02-18 09:01:02.567 | QUERY  | 10.0.3.45  | TXT   | ZG9tYWluOlJFRFBBV04=.data.c2-update-service.xyz             | NXDOMAIN | -
2026-02-18 09:01:03.890 | QUERY  | 10.0.3.45  | TXT   | b3M6V2luZG93cyAxMCBFbnRlcnByaXNl.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:01:05.123 | QUERY  | 10.0.3.45  | TXT   | aXA6MTAuMC4zLjQ1.data.c2-update-service.xyz                  | NXDOMAIN | -
2026-02-18 09:01:06.456 | QUERY  | 10.0.3.45  | TXT   | YXY6V2luZG93cyBEZWZlbmRlcg==.data.c2-update-service.xyz     | NXDOMAIN | -
2026-02-18 09:01:08.789 | QUERY  | 10.0.3.45  | TXT   | YWRtaW5zOkFkbWluaXN0cmF0b3Isai5tYXJ0aW4=.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:02:00.012 | QUERY  | 10.0.3.45  | A     | www.google.com                                    | NOERROR | 142.250.74.100
2026-02-18 09:10:00.345 | QUERY  | 10.0.5.12  | A     | update-service-cdn.xyz                            | NOERROR | 45.33.21.99
2026-02-18 09:15:00.678 | QUERY  | 10.0.3.45  | A     | www.microsoft.com                                 | NOERROR | 20.70.246.20
2026-02-18 09:30:01.012 | QUERY  | 10.0.3.45  | TXT   | Q09ORklERU5USUFMX0RBVEE6.data.c2-update-service.xyz          | NXDOMAIN | -
2026-02-18 09:30:02.345 | QUERY  | 10.0.3.45  | TXT   | c2FsYXJ5X2RiX3Bhc3N3b3JkPUhSQDFz.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:30:03.678 | QUERY  | 10.0.3.45  | TXT   | TXlTUUxfcm9vdD1zcWxAZG1pbjIwMjY=.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:30:04.012 | QUERY  | 10.0.3.45  | TXT   | QVBJX2tleT1hazRmN2IyOXgzcTh6bTVu.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:30:05.345 | QUERY  | 10.0.3.45  | TXT   | VlBOX3NlY3JldD1SZVBAV24yMDI2IQ==.data.c2-update-service.xyz  | NXDOMAIN | -
2026-02-18 09:30:06.678 | QUERY  | 10.0.3.45  | TXT   | RU5EX0NPTkZJREVOVElBTA==.data.c2-update-service.xyz          | NXDOMAIN | -
2026-02-18 09:35:00.012 | QUERY  | 10.0.3.45  | A     | time.windows.com                                  | NOERROR | 168.61.215.74
2026-02-18 10:00:01.345 | QUERY  | 10.0.4.22  | A     | check.torproject.org                              | NOERROR | 116.202.120.184
2026-02-18 10:00:02.678 | QUERY  | 10.0.4.22  | A     | 185.220.101.34                                    | NOERROR | 185.220.101.34
"""

CHALLENGE = {
    "id": "c07_dns_exfil",
    "title": "🌐 Les Murmures du DNS",
    "category": "network",
    "level": 3,
    "points_total": 420,
    "estimated_time": "40-55 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 16h00  
**Priorité :** CRITIQUE  
**Source :** Investigation proactive — Analyse des logs DNS

---

En poursuivant l'investigation sur WKS-COMPTA-PC03, vous décidez d'analyser les logs DNS pour détecter d'éventuelles communications C2 ou exfiltration de données.

Le script malveillant analysé précédemment utilisait l'exfiltration DNS. Il est temps de voir ce qui a réellement été exfiltré.

> *"On sait que le malware utilise du DNS tunneling pour exfiltrer. J'ai besoin que tu analyses les logs DNS, que tu déocdes les données Base64 dans les sous-domaines, et que tu me dises exactement quelles données ont été volées. On doit savoir si des credentials ont fuité."*

**Technique :** Les données sont encodées en Base64 dans les sous-domaines des requêtes TXT vers `c2-update-service.xyz`.  
Format : `<données_base64>.data.c2-update-service.xyz`
    """,
    "artifacts": [
        {
            "name": "dns_query_logs.txt",
            "type": "log",
            "content": ARTIFACT_DNS_LOGS,
            "description": "Logs DNS du résolveur interne — requêtes sortantes suspectes"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Combien de requêtes DNS d'exfiltration (vers c2-update-service.xyz) ont été effectuées au total ?",
            "answer": "13",
            "flag": "FLAG{13}",
            "points": 40,
            "hints": [
                "Comptez toutes les requêtes TXT vers *.data.c2-update-service.xyz",
                "Il y a deux vagues : une vers 09:01 et une vers 09:30"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Décodez le premier chunk Base64 (aG9zdG5hbWU6V0tTLUNPTVBUQS1QQzAz). Quel est le hostname de la machine infectée ?",
            "answer": "WKS-COMPTA-PC03",
            "flag": "FLAG{WKS-COMPTA-PC03}",
            "points": 40,
            "hints": [
                "Décodez : echo 'aG9zdG5hbWU6V0tTLUNPTVBUQS1QQzAz' | base64 -d",
                "Le résultat est au format 'hostname:VALEUR'"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Quel utilisateur est connecté sur la machine infectée ? (décodez le 2ème chunk)",
            "answer": "j.martin",
            "flag": "FLAG{j.martin}",
            "points": 40,
            "hints": [
                "Décodez : dXNlcm5hbWU6ai5tYXJ0aW4=",
                "Format: username:VALEUR"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Quel antivirus est installé sur la machine ? (décodez le chunk 'YXY6...')",
            "answer": "Windows Defender",
            "flag": "FLAG{Windows_Defender}",
            "points": 40,
            "hints": [
                "Décodez : YXY6V2luZG93cyBEZWZlbmRlcg==",
                "av = antivirus"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Dans la 2ème vague d'exfiltration (09:30), quel mot de passe de base de données RH a été volé ?",
            "answer": "HR@1s",
            "flag": "FLAG{HR@1s}",
            "points": 60,
            "hints": [
                "Décodez : c2FsYXJ5X2RiX3Bhc3N3b3JkPUhSQDFz",
                "Le format est salary_db_password=VALEUR"
            ],
            "hint_cost": 20
        },
        {
            "id": "q6",
            "text": "Quel est le mot de passe root MySQL exfiltré ?",
            "answer": "sql@dmin2026",
            "flag": "FLAG{sql@dmin2026}",
            "points": 60,
            "hints": [
                "Décodez : TXlTUUxfcm9vdD1zcWxAZG1pbjIwMjY=",
                "Format: MySQL_root=VALEUR"
            ],
            "hint_cost": 20
        },
        {
            "id": "q7",
            "text": "Quel secret VPN a été exfiltré ?",
            "answer": "ReP@wn2026!",
            "flag": "FLAG{ReP@wn2026!}",
            "points": 60,
            "hints": [
                "Décodez : VlBOX3NlY3JldD1SZVBAV24yMDI2IQ==",
                "Format: VPN_secret=VALEUR"
            ],
            "hint_cost": 20
        },
        {
            "id": "q8",
            "text": "Quels comptes sont membres du groupe Administrators local ? (décodez le chunk admins, séparez par une virgule)",
            "answer": "Administrator,j.martin",
            "flag": "FLAG{Administrator,j.martin}",
            "points": 40,
            "hints": [
                "Décodez : YWRtaW5zOkFkbWluaXN0cmF0b3Isai5tYXJ0aW4=",
                "Format: admins:user1,user2"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Quel type de réponse DNS le serveur C2 renvoie-t-il pour les requêtes d'exfiltration ?",
            "answer": "NXDOMAIN",
            "flag": "FLAG{NXDOMAIN}",
            "points": 40,
            "hints": [
                "Regardez la colonne Response des requêtes TXT",
                "Le domaine n'existe pas réellement, mais les données sont captées par le serveur DNS autoritaire"
            ],
            "hint_cost": 13
        }
    ]
}
