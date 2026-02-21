"""
Challenge 14 — Analyse PCAP Avancée
Niveau : 4 (Expert SOC)
Catégorie : Forensics Réseau
"""

ARTIFACT_PCAP = r"""
========== ANALYSE PCAP — Capture réseau WKS-COMPTA-PC03 ==========
Fichier : capture_20260218_0800-1400.pcap (2.4 GB)
Période : 18/02/2026 08:00 — 14:00 UTC
Interface : eth0 (10.0.3.45)
Outil : Wireshark 4.2 + tshark + NetworkMiner

===== STATISTIQUES GÉNÉRALES =====
Total paquets     : 4,847,231
Protocoles        : TCP (78%), UDP (18%), ICMP (2%), Other (2%)
Conversations TCP : 1,247
Conversations UDP : 892
Bytes transférés  : 3.8 GB

===== TOP 10 DESTINATIONS (par volume) =====
#   IP Destination      Port  Proto  Bytes      Pays        ASN          Verdict
1   10.0.1.10           445   TCP    892 MB     Interne     -            Normal (DC)
2   10.0.1.50           22    TCP    234 MB     Interne     -            Normal (deploy)
3   185.234.72.19       443   TCP    156 MB     RU          AS48693      MALVEILLANT
4   185.234.72.19       8443  TCP    89 MB      RU          AS48693      MALVEILLANT
5   91.234.56.78        80    TCP    45 MB      UA          AS15497      MALVEILLANT
6   10.0.2.20           3389  TCP    34 MB      Interne     -            Suspect
7   8.8.8.8             53    UDP    12 MB      US          Google       Normal
8   10.0.1.1            53    UDP    8.7 MB     Interne     -            Normal (DNS)
9   update.microsoft.com 443  TCP    4.2 MB     US          Microsoft    Normal
10  c2-update-service.xyz 443 TCP    2.1 MB     RU          AS48693      MALVEILLANT

===== ANALYSE DNS DÉTAILLÉE =====
Requêtes DNS totales : 34,521
Requêtes NXDOMAIN    : 1,247 (anormalement élevé)

Top domaines suspects :
  c2-update-service.xyz           — 847 requêtes (TXT records, beacon pattern)
  data-sync.c2-update-service.xyz — 312 requêtes (sous-domaines base64)
  health-check.phantomcrane.xyz   — 48 requêtes (résout vers 91.234.56.78)
  cdn-static.microsft-update.com  — 23 requêtes (typosquatting Microsoft)

===== ANALYSE TLS / CERTIFICATS =====
Connexion #1 : 10.0.3.45 → 185.234.72.19:443
  JA3 Hash      : 72a589da586844d7f0818ce684948eea
  JA3S Hash     : ae4edc6faf64d08308082ad26be60767
  Server Name   : update-service.microsft.com (SNI falsifié)
  Certificate   :
    Subject     : CN=update-service.microsft.com
    Issuer      : CN=update-service.microsft.com (SELF-SIGNED)
    Serial      : 0x4A3F2B1C
    Valid From  : 2026-02-14 00:00:00
    Valid To    : 2027-02-14 00:00:00
    Fingerprint : SHA256:9f3a2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a

Connexion #2 : 10.0.3.45 → 185.234.72.19:8443
  JA3 Hash      : 72a589da586844d7f0818ce684948eea (MÊME JA3)
  Server Name   : (vide — pas de SNI)
  Certificate   : Même certificat auto-signé

Connexion #3 : 10.0.3.45 → 91.234.56.78:80
  Pas de TLS — HTTP en clair

===== ANALYSE DES BEACONS (pattern C2) =====
Destination : 185.234.72.19:443
  Premier beacon : 08:16:45 UTC
  Dernier beacon : 13:58:12 UTC
  Interval moyen : 60.2 secondes (±2.1s jitter)
  Jitter %       : 3.5%
  Taille paquets : 92-156 bytes (check-in), 2048-65535 bytes (tasking)
  User-Agent     : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
  
Pattern temporel (extrait) :
  08:16:45 → Check-in (128 bytes envoyés, 92 bytes reçus)
  08:17:46 → Check-in (132 bytes envoyés, 92 bytes reçus)
  08:18:44 → Check-in (128 bytes envoyés, 8432 bytes reçus) ← TASKING reçu
  08:18:47 → Data upload (65535 bytes envoyés)
  08:19:48 → Check-in (156 bytes envoyés, 92 bytes reçus)
  [...]

===== HTTP EN CLAIR (91.234.56.78:80) =====
GET /update.php?id=RPWN-WKS03&ts=1708258800 HTTP/1.1
Host: 91.234.56.78
User-Agent: WinHTTP/6.1

HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Length: 458752
X-Command: EXFIL_START

[458752 bytes de payload binaire — PE executable]
SHA256: e7b4c3d2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4

POST /gate.php HTTP/1.1
Host: 91.234.56.78
Content-Type: application/octet-stream
Content-Length: 15728640
X-Session: RPWN-WKS03-20260218

[15728640 bytes — données exfiltrées, ~15 MB]

===== ANALYSE SMB (trafic interne) =====
10.0.3.45 → 10.0.1.10 (SRV-DC-01) Port 445:
  SMB2 TreeConnect : \\SRV-DC-01\ADMIN$
  SMB2 TreeConnect : \\SRV-DC-01\C$
  SMB2 Create      : \Windows\Temp\health_check.exe (WRITE)
  SMB2 Create      : \Windows\System32\config\SAM (READ)
  
10.0.3.45 → 10.0.2.20 Port 3389:
  RDP handshake détecté — session de 45 minutes
  Clipboard data transféré : 2.3 MB

===== EXTRACTION FICHIERS (NetworkMiner) =====
Fichiers extraits du trafic :
  1. health_check.exe    (SHA256: a1b2...f0e9) — PE32+ x86-64, UPX packed
  2. stager.ps1          (SHA256: c3d4...b2a1) — Script PowerShell obfusqué
  3. data_export.7z      (SHA256: e5f6...d4c3) — Archive chiffrée, 15 MB
  4. mimikatz_output.txt (SHA256: f7a8...e6d5) — Credentials dumpés

===== INDICATEURS TEMPORELS CLÉS =====
08:12:33 — Premier DNS vers c2-update-service.xyz
08:16:45 — Premier beacon HTTPS vers 185.234.72.19
09:30:12 — Début scan SMB interne (10.0.1.0/24)
10:15:44 — Accès SMB au DC (ADMIN$, C$)
10:16:02 — Upload health_check.exe vers DC
11:30:00 — Connexion RDP vers 10.0.2.20
12:45:33 — Début exfiltration via HTTP (91.234.56.78)
13:15:00 — Upload data_export.7z (15 MB) vers gate.php
13:58:12 — Dernier beacon C2 observé
"""

CHALLENGE = {
    "id": "c14_pcap_analysis",
    "title": "🔍 L'Écoute Silencieuse",
    "category": "network",
    "level": 4,
    "points_total": 530,
    "estimated_time": "45-60 min",
    "story": """
## Briefing de Mission

**Date :** 18 février 2026, 15h30
**Priorité :** CRITIQUE
**Source :** Équipe Network Forensics

---

Une capture réseau complète a été réalisée sur le poste compromis **WKS-COMPTA-PC03** pendant l'incident. L'analyse révèle du trafic C2, de l'exfiltration de données et du mouvement latéral.

> *"On a une PCAP de 6 heures sur le poste de la comptable. Il y a du C2 chiffré, de l'exfil en clair, et du mouvement latéral par SMB. Analyse tout ça et reconstitue le schéma de communication de l'attaquant."*

Forensique réseau avancée. Montrez votre maîtrise de l'analyse PCAP.
    """,
    "artifacts": [
        {
            "name": "pcap_analysis_report.txt",
            "type": "report",
            "content": ARTIFACT_PCAP,
            "description": "Rapport d'analyse PCAP — Capture réseau WKS-COMPTA-PC03"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quel est le JA3 hash du client C2 ? (empreinte TLS du malware)",
            "answer": "72a589da586844d7f0818ce684948eea",
            "flag": "FLAG{72a589da586844d7f0818ce684948eea}",
            "points": 50,
            "hints": [
                "Regardez la section Analyse TLS / Certificats",
                "Le JA3 est l'empreinte TLS côté client — identique pour les 2 connexions"
            ],
            "hint_cost": 17
        },
        {
            "id": "q2",
            "text": "Quel est l'intervalle moyen des beacons C2 en secondes (arrondi) ?",
            "answer": "60",
            "flag": "FLAG{60}",
            "points": 40,
            "hints": [
                "Regardez la section Analyse des Beacons",
                "L'interval moyen est de 60.2 secondes"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Quel domaine est utilisé pour le typosquatting de Microsoft dans les requêtes DNS ?",
            "answer": "cdn-static.microsft-update.com",
            "flag": "FLAG{cdn-static.microsft-update.com}",
            "points": 50,
            "hints": [
                "Regardez les Top domaines suspects dans l'analyse DNS",
                "Un domaine ressemble à Microsoft mais avec une faute"
            ],
            "hint_cost": 17
        },
        {
            "id": "q4",
            "text": "Quel est le volume approximatif de données exfiltrées via gate.php (en MB) ?",
            "answer": "15",
            "flag": "FLAG{15}",
            "points": 40,
            "hints": [
                "Regardez le POST vers gate.php dans la section HTTP en clair",
                "Content-Length indique la taille en bytes"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Le certificat TLS du C2 est auto-signé. Quel CN (Common Name) usurpe-t-il ?",
            "answer": "update-service.microsft.com",
            "flag": "FLAG{update-service.microsft.com}",
            "points": 50,
            "hints": [
                "Regardez le champ Subject du certificat",
                "C'est un faux domaine Microsoft (notez le 'o' manquant)"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "Combien de fichiers ont été extraits du trafic par NetworkMiner ?",
            "answer": "4",
            "flag": "FLAG{4}",
            "points": 30,
            "hints": [
                "Comptez dans la section Extraction Fichiers"
            ],
            "hint_cost": 10
        },
        {
            "id": "q7",
            "text": "Par quel outil l'exécutable health_check.exe est-il packé ?",
            "answer": "UPX",
            "flag": "FLAG{UPX}",
            "points": 50,
            "hints": [
                "Regardez la description du fichier dans les extractions NetworkMiner",
                "C'est un packer open-source très courant"
            ],
            "hint_cost": 17
        },
        {
            "id": "q8",
            "text": "Quel partage SMB administratif a été utilisé pour uploader health_check.exe sur le DC ?",
            "answer": "ADMIN$",
            "flag": "FLAG{ADMIN$}",
            "points": 40,
            "hints": [
                "Regardez les TreeConnect SMB2",
                "Le fichier a été écrit dans \\Windows\\Temp\\"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Quel paramètre HTTP identifie la machine compromise dans les requêtes vers le serveur d'exfiltration ?",
            "answer": "RPWN-WKS03",
            "flag": "FLAG{RPWN-WKS03}",
            "points": 40,
            "hints": [
                "Regardez le GET /update.php",
                "C'est le paramètre 'id' dans l'URL"
            ],
            "hint_cost": 13
        },
        {
            "id": "q10",
            "text": "Quel pourcentage de jitter est appliqué aux beacons C2 ?",
            "answer": "3.5",
            "flag": "FLAG{3.5}",
            "points": 40,
            "hints": [
                "Regardez la section Analyse des Beacons, champ Jitter %"
            ],
            "hint_cost": 13
        },
        {
            "id": "q11",
            "text": "Quel fichier sensible du DC a été lu via SMB par l'attaquant ? (chemin relatif depuis C:\\Windows\\)",
            "answer": "System32\\config\\SAM",
            "flag": "FLAG{SAM}",
            "points": 60,
            "hints": [
                "Regardez les opérations SMB2 Create avec accès READ",
                "C'est un fichier qui contient les hashes de mots de passe locaux"
            ],
            "hint_cost": 20
        }
    ]
}
