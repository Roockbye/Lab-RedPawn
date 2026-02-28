"""
Challenge 7 — Exfiltration DNS
Niveau : 3 (Analyste Senior)
Catégorie : Forensics Réseau
"""

ARTIFACT_DNS_LOGS = r"""
=== DNS Query Logs — Firewall/DNS Resolver (10.0.0.1) ===
=== Date: 2026-02-18 — Tous les flux DNS sortants ===
=== Total: 847 requêtes DNS capturées — Extrait ci-dessous (triées chronologiquement) === 

2026-02-18 08:00:01.001 | QUERY  | 10.0.1.10  | A     | dc01.redpawn.local                               | NOERROR | 10.0.1.10
2026-02-18 08:00:01.012 | QUERY  | 10.0.1.10  | SRV   | _ldap._tcp.redpawn.local                         | NOERROR | 10.0.1.10
2026-02-18 08:00:02.034 | QUERY  | 10.0.2.20  | A     | www.google.com                                    | NOERROR | 142.250.74.100
2026-02-18 08:00:02.099 | QUERY  | 10.0.2.20  | AAAA  | www.google.com                                    | NOERROR | 2a00:1450:4007:80f::2004
2026-02-18 08:00:03.100 | QUERY  | 10.0.2.21  | A     | outlook.office365.com                             | NOERROR | 52.96.87.14
2026-02-18 08:00:03.200 | QUERY  | 10.0.2.21  | A     | outlook.office.com                                | NOERROR | 52.96.87.15
2026-02-18 08:00:04.300 | QUERY  | 10.0.3.10  | A     | repo.maven.apache.org                             | NOERROR | 151.101.52.215
2026-02-18 08:00:05.400 | QUERY  | 10.0.2.22  | A     | login.microsoftonline.com                         | NOERROR | 20.190.159.4
2026-02-18 08:00:06.500 | QUERY  | 10.0.4.30  | A     | registry.npmjs.org                                | NOERROR | 104.16.23.35
2026-02-18 08:00:10.100 | QUERY  | 10.0.3.45  | A     | www.google.com                                    | NOERROR | 142.250.74.100
2026-02-18 08:00:15.200 | QUERY  | 10.0.3.45  | A     | outlook.office365.com                             | NOERROR | 52.96.87.14
2026-02-18 08:01:00.001 | QUERY  | 10.0.1.10  | A     | time.windows.com                                  | NOERROR | 168.61.215.74
2026-02-18 08:05:00.010 | QUERY  | 10.0.2.20  | A     | teams.microsoft.com                               | NOERROR | 52.113.194.132
2026-02-18 08:05:01.020 | QUERY  | 10.0.2.20  | A     | statics.teams.cdn.office.net                      | NOERROR | 52.113.194.133
2026-02-18 08:10:00.100 | QUERY  | 10.0.2.21  | A     | graph.microsoft.com                               | NOERROR | 20.190.159.5
2026-02-18 08:10:01.200 | QUERY  | 10.0.2.22  | A     | sharepoint.com                                    | NOERROR | 13.107.136.9
2026-02-18 08:15:00.001 | QUERY  | 10.0.4.30  | A     | pypi.org                                          | NOERROR | 151.101.0.223
2026-02-18 08:15:01.002 | QUERY  | 10.0.4.30  | A     | files.pythonhosted.org                            | NOERROR | 151.101.0.224
2026-02-18 08:20:00.100 | QUERY  | 10.0.2.20  | A     | slack-imgs.com                                    | NOERROR | 54.84.15.16
2026-02-18 08:20:01.200 | QUERY  | 10.0.2.20  | A     | edgeapi.slack.com                                 | NOERROR | 3.120.51.82
2026-02-18 08:25:00.100 | QUERY  | 10.0.3.10  | A     | github.com                                        | NOERROR | 140.82.121.4
2026-02-18 08:25:01.200 | QUERY  | 10.0.3.10  | A     | api.github.com                                    | NOERROR | 140.82.121.5
2026-02-18 08:25:02.300 | QUERY  | 10.0.3.10  | A     | raw.githubusercontent.com                         | NOERROR | 185.199.108.133
2026-02-18 08:30:00.100 | QUERY  | 10.0.1.10  | A     | wpad.redpawn.local                                | NXDOMAIN | -
2026-02-18 08:30:01.200 | QUERY  | 10.0.2.23  | A     | www.linkedin.com                                  | NOERROR | 13.107.42.14
2026-02-18 08:30:05.300 | QUERY  | 10.0.2.24  | A     | fonts.googleapis.com                              | NOERROR | 142.250.74.42
2026-02-18 08:30:06.400 | QUERY  | 10.0.2.24  | A     | fonts.gstatic.com                                 | NOERROR | 142.250.74.35
2026-02-18 08:35:00.100 | QUERY  | 10.0.3.45  | A     | weather.com                                       | NOERROR | 54.230.160.100
2026-02-18 08:40:00.100 | QUERY  | 10.0.2.20  | A     | download.windowsupdate.com                        | NOERROR | 23.35.37.245
2026-02-18 08:40:01.200 | QUERY  | 10.0.2.20  | A     | fe3cr.delivery.mp.microsoft.com                   | NOERROR | 152.199.39.108
2026-02-18 08:40:02.300 | QUERY  | 10.0.1.10  | A     | download.windowsupdate.com                        | NOERROR | 23.35.37.245
2026-02-18 08:45:00.100 | QUERY  | 10.0.2.21  | A     | outlook.office365.com                             | NOERROR | 52.96.87.14
2026-02-18 08:45:01.200 | QUERY  | 10.0.2.21  | A     | attachments.office.net                            | NOERROR | 13.107.136.11
2026-02-18 08:50:00.100 | QUERY  | 10.0.3.10  | A     | packages.elastic.co                               | NOERROR | 34.120.127.130
2026-02-18 08:50:01.200 | QUERY  | 10.0.3.10  | A     | docker.elastic.co                                 | NOERROR | 34.120.127.131
2026-02-18 08:55:00.100 | QUERY  | 10.0.3.45  | A     | www.microsoft.com                                 | NOERROR | 20.70.246.20
2026-02-18 08:55:01.200 | QUERY  | 10.0.3.45  | A     | www.office.com                                    | NOERROR | 52.96.87.16
2026-02-18 08:58:00.100 | QUERY  | 10.0.4.30  | A     | hub.docker.com                                    | NOERROR | 54.198.86.24
2026-02-18 08:58:01.200 | QUERY  | 10.0.4.30  | A     | registry-1.docker.io                              | NOERROR | 34.205.13.154
2026-02-18 08:59:00.100 | QUERY  | 10.0.2.25  | A     | www.wikipedia.org                                 | NOERROR | 91.198.174.192
2026-02-18 08:59:30.200 | QUERY  | 10.0.2.20  | A     | accounts.google.com                               | NOERROR | 142.250.74.101
2026-02-18 09:00:00.050 | QUERY  | 10.0.1.10  | A     | time.windows.com                                  | NOERROR | 168.61.215.74
2026-02-18 09:00:01.100 | QUERY  | 10.0.2.20  | A     | docs.google.com                                   | NOERROR | 142.250.74.102
2026-02-18 09:00:01.123 | QUERY  | 10.0.3.45  | A     | www.google.com                                    | NOERROR | 142.250.74.100
2026-02-18 09:00:02.200 | QUERY  | 10.0.2.21  | A     | onedrive.live.com                                 | NOERROR | 13.107.42.13
2026-02-18 09:00:03.300 | QUERY  | 10.0.3.10  | A     | gitlab.redpawn.local                              | NOERROR | 10.0.3.30
2026-02-18 09:00:05.400 | QUERY  | 10.0.4.30  | A     | dl.google.com                                     | NOERROR | 142.250.74.110
2026-02-18 09:00:10.500 | QUERY  | 10.0.2.22  | A     | login.microsoftonline.com                         | NOERROR | 20.190.159.4
2026-02-18 09:00:15.456 | QUERY  | 10.0.3.45  | A     | outlook.office365.com                             | NOERROR | 52.96.87.14
2026-02-18 09:00:20.600 | QUERY  | 10.0.2.23  | A     | maps.googleapis.com                               | NOERROR | 142.250.74.42
2026-02-18 09:00:30.700 | QUERY  | 10.0.2.24  | A     | cdn.jsdelivr.net                                  | NOERROR | 104.16.85.20
2026-02-18 09:00:45.800 | QUERY  | 10.0.3.10  | A     | nuget.org                                         | NOERROR | 104.42.151.168
2026-02-18 09:01:00.789 | QUERY  | 10.0.3.45  | TXT   | aG9zdG5hbWU6V0tTLUNPTVBUQS1QQzAz.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:01:01.234 | QUERY  | 10.0.3.45  | TXT   | dXNlcm5hbWU6ai5tYXJ0aW4=.data.c2-update-service.xyz         | NXDOMAIN | -
2026-02-18 09:01:02.100 | QUERY  | 10.0.2.20  | A     | www.bing.com                                      | NOERROR | 204.79.197.200
2026-02-18 09:01:02.567 | QUERY  | 10.0.3.45  | TXT   | ZG9tYWluOlJFRFBBV04=.data.c2-update-service.xyz             | NXDOMAIN | -
2026-02-18 09:01:03.200 | QUERY  | 10.0.4.30  | A     | gcr.io                                            | NOERROR | 64.233.177.82
2026-02-18 09:01:03.890 | QUERY  | 10.0.3.45  | TXT   | b3M6V2luZG93cyAxMCBFbnRlcnByaXNl.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:01:04.500 | QUERY  | 10.0.2.21  | A     | smtp.office365.com                                | NOERROR | 52.96.87.17
2026-02-18 09:01:05.123 | QUERY  | 10.0.3.45  | TXT   | aXA6MTAuMC4zLjQ1.data.c2-update-service.xyz                  | NXDOMAIN | -
2026-02-18 09:01:05.600 | QUERY  | 10.0.2.22  | A     | autodiscover.outlook.com                          | NOERROR | 52.96.87.18
2026-02-18 09:01:06.456 | QUERY  | 10.0.3.45  | TXT   | YXY6V2luZG93cyBEZWZlbmRlcg==.data.c2-update-service.xyz     | NXDOMAIN | -
2026-02-18 09:01:07.100 | QUERY  | 10.0.2.20  | A     | settings-win.data.microsoft.com                   | NOERROR | 40.77.226.249
2026-02-18 09:01:08.789 | QUERY  | 10.0.3.45  | TXT   | YWRtaW5zOkFkbWluaXN0cmF0b3Isai5tYXJ0aW4=.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:01:10.100 | QUERY  | 10.0.2.23  | A     | analytics.google.com                              | NOERROR | 142.250.74.105
2026-02-18 09:02:00.012 | QUERY  | 10.0.3.45  | A     | www.google.com                                    | NOERROR | 142.250.74.100
2026-02-18 09:02:01.100 | QUERY  | 10.0.4.30  | A     | security.ubuntu.com                               | NOERROR | 91.189.91.39
2026-02-18 09:02:02.200 | QUERY  | 10.0.4.30  | A     | archive.ubuntu.com                                | NOERROR | 91.189.88.142
2026-02-18 09:05:00.100 | QUERY  | 10.0.2.20  | A     | teams.microsoft.com                               | NOERROR | 52.113.194.132
2026-02-18 09:05:01.200 | QUERY  | 10.0.2.21  | A     | graph.microsoft.com                               | NOERROR | 20.190.159.5
2026-02-18 09:05:02.300 | QUERY  | 10.0.3.10  | A     | sonarqube.redpawn.local                            | NOERROR | 10.0.3.31
2026-02-18 09:08:00.100 | QUERY  | 10.0.2.24  | A     | stackoverflow.com                                 | NOERROR | 151.101.1.69
2026-02-18 09:08:01.200 | QUERY  | 10.0.2.24  | A     | cdn.sstatic.net                                   | NOERROR | 151.101.0.69
2026-02-18 09:10:00.345 | QUERY  | 10.0.5.12  | A     | update-service-cdn.xyz                            | NOERROR | 45.33.21.99
2026-02-18 09:10:01.100 | QUERY  | 10.0.2.20  | A     | www.amazon.fr                                     | NOERROR | 54.239.34.173
2026-02-18 09:12:00.100 | QUERY  | 10.0.2.25  | A     | confluence.redpawn.local                          | NOERROR | 10.0.3.32
2026-02-18 09:15:00.100 | QUERY  | 10.0.2.20  | A     | mail.google.com                                   | NOERROR | 142.250.74.111
2026-02-18 09:15:00.678 | QUERY  | 10.0.3.45  | A     | www.microsoft.com                                 | NOERROR | 20.70.246.20
2026-02-18 09:15:01.200 | QUERY  | 10.0.3.10  | A     | jenkins.redpawn.local                             | NOERROR | 10.0.3.33
2026-02-18 09:20:00.100 | QUERY  | 10.0.2.21  | A     | outlook.office365.com                             | NOERROR | 52.96.87.14
2026-02-18 09:20:01.200 | QUERY  | 10.0.2.22  | A     | sharepoint.com                                    | NOERROR | 13.107.136.9
2026-02-18 09:25:00.100 | QUERY  | 10.0.4.30  | A     | dl.k8s.io                                         | NOERROR | 34.107.204.206
2026-02-18 09:25:01.200 | QUERY  | 10.0.4.30  | A     | storage.googleapis.com                            | NOERROR | 142.250.74.128
2026-02-18 09:28:00.100 | QUERY  | 10.0.2.20  | A     | calendar.google.com                               | NOERROR | 142.250.74.113
2026-02-18 09:28:01.200 | QUERY  | 10.0.2.23  | A     | drive.google.com                                  | NOERROR | 142.250.74.114
2026-02-18 09:30:00.050 | QUERY  | 10.0.1.10  | A     | time.windows.com                                  | NOERROR | 168.61.215.74
2026-02-18 09:30:00.100 | QUERY  | 10.0.2.20  | A     | api.openai.com                                    | NOERROR | 104.18.7.192
2026-02-18 09:30:01.012 | QUERY  | 10.0.3.45  | TXT   | Q09ORklERU5USUFMX0RBVEE6.data.c2-update-service.xyz          | NXDOMAIN | -
2026-02-18 09:30:01.500 | QUERY  | 10.0.2.21  | A     | www.office.com                                    | NOERROR | 52.96.87.16
2026-02-18 09:30:02.345 | QUERY  | 10.0.3.45  | TXT   | c2FsYXJ5X2RiX3Bhc3N3b3JkPUhSQDFz.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:30:02.800 | QUERY  | 10.0.2.22  | A     | login.microsoftonline.com                         | NOERROR | 20.190.159.4
2026-02-18 09:30:03.678 | QUERY  | 10.0.3.45  | TXT   | TXlTUUxfcm9vdD1zcWxAZG1pbjIwMjY=.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:30:03.900 | QUERY  | 10.0.4.30  | A     | crates.io                                         | NOERROR | 108.138.64.126
2026-02-18 09:30:04.012 | QUERY  | 10.0.3.45  | TXT   | QVBJX2tleT1hazRmN2IyOXgzcTh6bTVu.data.c2-update-service.xyz | NXDOMAIN | -
2026-02-18 09:30:04.500 | QUERY  | 10.0.2.23  | A     | www.youtube.com                                   | NOERROR | 142.250.74.115
2026-02-18 09:30:05.345 | QUERY  | 10.0.3.45  | TXT   | VlBOX3NlY3JldD1SZVBAV24yMDI2IQ==.data.c2-update-service.xyz  | NXDOMAIN | -
2026-02-18 09:30:05.700 | QUERY  | 10.0.2.24  | A     | cdnjs.cloudflare.com                              | NOERROR | 104.16.132.229
2026-02-18 09:30:06.678 | QUERY  | 10.0.3.45  | TXT   | RU5EX0NPTkZJREVOVElBTA==.data.c2-update-service.xyz          | NXDOMAIN | -
2026-02-18 09:30:07.100 | QUERY  | 10.0.2.25  | A     | www.reddit.com                                    | NOERROR | 151.101.1.140
2026-02-18 09:32:00.100 | QUERY  | 10.0.2.20  | A     | teams.microsoft.com                               | NOERROR | 52.113.194.132
2026-02-18 09:35:00.012 | QUERY  | 10.0.3.45  | A     | time.windows.com                                  | NOERROR | 168.61.215.74
2026-02-18 09:35:00.100 | QUERY  | 10.0.2.21  | A     | outlook.office365.com                             | NOERROR | 52.96.87.14
2026-02-18 09:40:00.100 | QUERY  | 10.0.4.30  | A     | github.com                                        | NOERROR | 140.82.121.4
2026-02-18 09:40:01.200 | QUERY  | 10.0.4.30  | A     | api.github.com                                    | NOERROR | 140.82.121.5
2026-02-18 09:45:00.100 | QUERY  | 10.0.2.20  | A     | copilot.github.com                                | NOERROR | 140.82.121.6
2026-02-18 09:50:00.100 | QUERY  | 10.0.2.22  | A     | graph.microsoft.com                               | NOERROR | 20.190.159.5
2026-02-18 09:55:00.100 | QUERY  | 10.0.3.10  | A     | docker.redpawn.local                              | NOERROR | 10.0.3.34
2026-02-18 10:00:00.100 | QUERY  | 10.0.1.10  | A     | time.windows.com                                  | NOERROR | 168.61.215.74
2026-02-18 10:00:01.345 | QUERY  | 10.0.4.22  | A     | check.torproject.org                              | NOERROR | 116.202.120.184
2026-02-18 10:00:02.678 | QUERY  | 10.0.4.22  | A     | 185.220.101.34                                    | NOERROR | 185.220.101.34
2026-02-18 10:00:03.100 | QUERY  | 10.0.2.20  | A     | www.google.com                                    | NOERROR | 142.250.74.100
2026-02-18 10:05:00.100 | QUERY  | 10.0.2.21  | A     | outlook.office365.com                             | NOERROR | 52.96.87.14
2026-02-18 10:10:00.100 | QUERY  | 10.0.2.22  | A     | login.microsoftonline.com                         | NOERROR | 20.190.159.4
2026-02-18 10:15:00.100 | QUERY  | 10.0.3.10  | A     | bitbucket.org                                     | NOERROR | 104.192.136.1
2026-02-18 10:20:00.100 | QUERY  | 10.0.2.20  | A     | teams.microsoft.com                               | NOERROR | 52.113.194.132
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

En poursuivant l'investigation sur WKS-COMPTA-PC03, vous décidez d'analyser les logs DNS bruts pour détecter d'éventuelles communications C2 ou exfiltration de données.

Le résolveur DNS interne capture toutes les requêtes sortantes. Il y a beaucoup de trafic légitime — à vous de trouver les anomalies.

> *"On sait que le malware utilise du DNS tunneling pour exfiltrer. J'ai exporté les logs DNS bruts sans filtre. Il y a des centaines de requêtes — à toi de séparer le bruit du signal, décoder les données Base64 dans les sous-domaines suspects, et me dire exactement quelles données ont été volées. On doit savoir si des credentials ont fuité."*

<details>
<summary>💡 Indice technique (cliquez pour afficher)</summary>

L'exfiltration DNS utilise souvent des sous-domaines encodés en Base64 avec des requêtes de type TXT vers un domaine contrôlé par l'attaquant.  
Cherchez les requêtes qui retournent NXDOMAIN — c'est normal pour le tunneling DNS car le domaine n'existe pas réellement, les données sont captées au niveau du serveur DNS autoritaire.

</details>
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
            "text": "Combien de requêtes DNS d'exfiltration ont été effectuées au total ?",
            "answer": "13",
            "flag": "REDPAWN{13}",
            "points": 40,
            "hints": [
                "Identifiez d'abord le domaine suspect utilisé pour le tunneling parmi les centaines de requêtes",
                "Comptez les requêtes de type TXT vers ce domaine — il y a deux vagues distinctes"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Quel est le hostname de la machine infectée ?",
            "answer": "WKS-COMPTA-PC03",
            "flag": "REDPAWN{WKS-COMPTA-PC03}",
            "points": 40,
            "hints": [
                "Décodez le premier chunk Base64 dans la première vague d'exfiltration (09:01)",
                "Le résultat est au format 'hostname:VALEUR'"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Quel utilisateur est connecté sur la machine infectée ?",
            "answer": "j.martin",
            "flag": "REDPAWN{j.martin}",
            "points": 40,
            "hints": [
                "Décodez le deuxième chunk Base64 de la première vague",
                "Format: username:VALEUR"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Quel antivirus est installé sur la machine infectée ?",
            "answer": "Windows Defender",
            "flag": "REDPAWN{Windows_Defender}",
            "points": 40,
            "hints": [
                "Cherchez le chunk dont le préfixe décodé correspond à 'av' (antivirus)",
                "Décodez le chunk commençant par 'YXY6'"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Dans la 2ème vague d'exfiltration, quel mot de passe de base de données RH a été volé ?",
            "answer": "HR@1s",
            "flag": "REDPAWN{HR@1s}",
            "points": 60,
            "hints": [
                "Décodez les chunks de la deuxième vague (09:30) pour trouver celui contenant un mot de passe",
                "Le format décodé est salary_db_password=VALEUR"
            ],
            "hint_cost": 20
        },
        {
            "id": "q6",
            "text": "Quel est le mot de passe root MySQL exfiltré ?",
            "answer": "sql@dmin2026",
            "flag": "REDPAWN{sql@dmin2026}",
            "points": 60,
            "hints": [
                "Décodez les chunks de la deuxième vague pour trouver celui relatif à MySQL",
                "Format décodé: MySQL_root=VALEUR"
            ],
            "hint_cost": 20
        },
        {
            "id": "q7",
            "text": "Quel secret VPN a été exfiltré ?",
            "answer": "ReP@wn2026!",
            "flag": "REDPAWN{ReP@wn2026!}",
            "points": 60,
            "hints": [
                "Décodez les chunks de la deuxième vague pour trouver celui relatif au VPN",
                "Format décodé: VPN_secret=VALEUR"
            ],
            "hint_cost": 20
        },
        {
            "id": "q8",
            "text": "Quels comptes sont membres du groupe Administrators local ? (séparez par une virgule)",
            "answer": "Administrator,j.martin",
            "flag": "REDPAWN{Administrator,j.martin}",
            "points": 40,
            "hints": [
                "Décodez le chunk de la première vague contenant les informations 'admins'",
                "Format décodé: admins:user1,user2"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Quel type de réponse DNS le serveur C2 renvoie-t-il pour les requêtes d'exfiltration ?",
            "answer": "NXDOMAIN",
            "flag": "REDPAWN{NXDOMAIN}",
            "points": 40,
            "hints": [
                "Regardez la colonne Response des requêtes TXT",
                "Le domaine n'existe pas réellement, mais les données sont captées par le serveur DNS autoritaire"
            ],
            "hint_cost": 13
        }
    ]
}
