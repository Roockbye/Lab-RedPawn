# 🛡️ RedPawn SOC Lab — Blue Team Interactive Training

> Lab interactif de formation Blue Team / SOC, style CTF, avec 18 challenges progressifs couvrant l'analyse de logs, le phishing, le triage SIEM, la forensique réseau et mémoire, l'analyse malware, le reverse engineering, l'incident response, la threat intelligence, le threat hunting et la sécurité cloud.

## 🚀 Lancement rapide

```bash
# 1. Cloner et entrer dans le projet
cd Lab-RedPawn

# 2. Lancer le lab (installe automatiquement les dépendances)
./start.sh          # Linux / macOS
start.bat           # Windows
```

Ou manuellement :

```bash
python3 -m venv .venv
source .venv/bin/activate    # Linux/macOS
pip install -r requirements.txt
python app.py
```

Ouvrez **http://127.0.0.1:5050** dans votre navigateur.

## 📋 Vue d'ensemble

| Métrique | Valeur |
|----------|--------|
| **Challenges** | 18 |
| **Questions** | ~180 |
| **Niveaux** | 5 (Junior → Threat Hunter) |
| **Points totaux** | ~8000+ |
| **Durée estimée** | 10-15 heures |
| **Joueurs** | Multi-joueurs (scoreboard) |
| **Anti-triche** | ✅ HMAC-SHA256 + rate limiting |

## 🎯 Les 18 Challenges

### 🟢 Niveau 1 — Analyste Junior
| # | Challenge | Catégorie | Points | Durée |
|---|-----------|-----------|--------|-------|
| 1 | 🔐 Opération Porte Dérobée | Analyse de Logs | 250 | 20-30 min |
| 2 | 🎣 L'Hameçon de Microsoft | Phishing | 280 | 25-35 min |
| 3 | 🔔 La Queue d'Alertes du Lundi | Triage SIEM | 300 | 25-40 min |

### 🟡 Niveau 2 — Analyste Confirmé
| # | Challenge | Catégorie | Points | Durée |
|---|-----------|-----------|--------|-------|
| 4 | 🕷️ Le Faux Logo | Analyse de Logs | 350 | 30-45 min |
| 5 | 🏰 La Chute du Château Fort | Forensics Système | 400 | 35-50 min |
| 6 | 🦠 Le Faux Google Update | Analyse Malware | 380 | 35-50 min |

### 🟠 Niveau 3 — Analyste Senior
| # | Challenge | Catégorie | Points | Durée |
|---|-----------|-----------|--------|-------|
| 7 | 🌐 Les Murmures du DNS | Forensics Réseau | 420 | 40-55 min |
| 8 | 🚨 Code Rouge : Ransomware | Incident Response | 450 | 40-60 min |
| 9 | 🕵️ Les Sept Péchés de Persistance | Forensics Système | 480 | 45-60 min |
| 10 | 🐍 Le Serpent dans le Nid | Threat Intelligence | 380 | 30-45 min |

### 🔴 Niveau 4 — Expert SOC
| # | Challenge | Catégorie | Points | Durée |
|---|-----------|-----------|--------|-------|
| 11 | ⚔️ L'Autopsie Complète | Incident Response | 500 | 45-60 min |
| 12 | 🔗 La Chaîne Brisée | Threat Intelligence | 450 | 35-50 min |
| 13 | 👻 Le Fantôme dans la RAM | Memory Forensics | 520 | 45-60 min |
| 14 | 🎧 L'Écoute Silencieuse | PCAP Analysis | 530 | 50-70 min |

### 🟣 Niveau 5 — Threat Hunter
| # | Challenge | Catégorie | Points | Durée |
|---|-----------|-----------|--------|-------|
| 15 | ⛈️ Tempête dans le Cloud | Cloud Security | 580 | 50-70 min |
| 16 | 🔬 Le Cœur de la Bête | Reverse Engineering | 560 | 50-70 min |
| 17 | 🎯 La Chasse est Ouverte | Threat Hunting | 550 | 50-70 min |
| 18 | 🏆 L'Examen Final : PHANTOM CRANE | Full Reconstruction | 650 | 60-90 min |

## 🏗️ Architecture narrative

Tous les challenges racontent **une seule histoire continue** : l'investigation d'une attaque APT complète contre RedPawn Corp — **Opération PHANTOM CRANE**.

```
📧 Phishing → 💻 Compromission poste → 🔑 Vol credentials
    → 🏰 Mouvement latéral → 🗃️ Exfiltration données  
    → 💀 Ransomware → 🔍 Investigation post-incident
    → 🕵️ Attribution & Supply Chain
    → 🧠 Memory Forensics → 🌐 PCAP Analysis
    → ☁️ Cloud Incident → ⚙️ Malware Reverse Engineering
    → 🎯 Threat Hunting → 🏆 Reconstruction complète
```

En parallèle, une **menace interne** (insider threat) est également à investiguer.

## 🔒 Système Anti-triche

- **Hachage HMAC-SHA256** : les réponses ne sont jamais en clair côté client
- **Rate limiting** : max 5 tentatives / 30s par question, cooldown 3s
- **Stripping des données** : réponses et flags retirés de toutes les réponses API et templates
- **Headers de sécurité** : no-cache, no-store, X-Frame-Options, X-Content-Type-Options
- **Distribution compilée** : possibilité de distribuer les challenges en `.pyc` uniquement

## 🎮 Fonctionnalités

- **Interface web** sombre thème SOC professionnel
- **Scoring en temps réel** avec système de flags (`REDPAWN{...}`)
- **Système d'indices** avec pénalités de points
- **Scoreboard multi-joueurs** avec synchronisation réseau
- **Artefacts réalistes** : logs auth, emails, SIEM, Event Logs Windows, scripts malveillants, rapports forensics
- **Progression sauvegardée** (SQLite local)
- **Responsive** — fonctionne sur desktop, tablette, mobile

## 🛠️ Compétences couvertes

- Analyse de logs (Linux auth.log, Apache access.log)
- Analyse d'emails de phishing (headers, SPF/DKIM/DMARC)
- Triage d'alertes SIEM (TP/FP/BTP)
- Détection de webshells
- Analyse d'Event Logs Windows (4624, 4625, 4688, 4720...)
- Déobfuscation de scripts malveillants (PowerShell)
- Analyse d'exfiltration DNS
- Incident Response (timeline, kill chain)
- Mécanismes de persistance (registre, services, WMI, Golden Ticket)
- Mapping MITRE ATT&CK
- Threat Intelligence & Attribution
- Détection de menaces internes (DLP)
- Analyse supply chain
- **Memory Forensics** (Volatility 3, process injection, Cobalt Strike)
- **PCAP Analysis** (Wireshark, JA3, beacon analysis, SMB lateral)
- **Cloud Security** (AWS CloudTrail, IAM abuse, S3 exfiltration, Lambda backdoor)
- **Reverse Engineering** (malware analysis, packing, anti-analysis, C2 protocol)
- **Threat Hunting** (KQL, Sigma rules, detection gaps, LOLBins)

## 📁 Structure du projet

```
Lab-RedPawn/
├── app.py                  # Application Flask (port 5050)
├── config.py               # Configuration (5 niveaux, 12 catégories)
├── database.py             # Gestion SQLite
├── security.py             # Module anti-triche
├── requirements.txt        # Dépendances Python
├── build_dist.sh           # Script de build pour distribution
├── challenges/             # Définition des 18 challenges
│   ├── registry.py         # Registre central
│   ├── c01_brute_force.py → c12_supply_chain.py    # Niveaux 1-4
│   └── c13_memory_forensics.py → c18_final_exam.py # Niveaux 4-5
├── templates/              # Templates HTML (Jinja2)
│   ├── base.html
│   ├── index.html
│   ├── dashboard.html
│   ├── challenge.html
│   └── scoreboard.html
└── static/
    ├── css/style.css       # Thème SOC sombre
    └── js/app.js           # Interactivité client
```

## 📦 Distribution à l'équipe

### Option 1 — Partage du ZIP compilé (recommandé)

Lance le build depuis le poste admin :

```bash
./build_dist.sh
```

Cela crée `dist/Lab-RedPawn.zip` avec :
- Code Python compilé (.pyc) — réponses non lisibles
- Scripts de lancement (start.sh + start.bat)
- Templates, CSS, JS

Envoie le ZIP à chaque participant (clé USB, partage réseau, Google Drive...).

Chaque participant :
1. Dézippe dans un dossier
2. Lance `./start.sh` (Linux/Mac) ou `start.bat` (Windows)
3. Ouvre http://127.0.0.1:5050

### Option 2 — Dépôt Git privé

```bash
# Sur un dépôt Git privé (GitHub/GitLab)
git init && git add . && git commit -m "RedPawn SOC Lab"
git remote add origin <url-du-depot>
git push -u origin main
```

Chaque participant :
```bash
git clone <url-du-depot>
cd Lab-RedPawn
./start.sh
```

⚠️ Avec cette méthode les fichiers `.py` sont en clair. Utilise le build compilé si tu veux cacher les réponses.

### Option 3 — Serveur centralisé

Lance le lab sur un serveur accessible par tous :
```bash
python app.py    # Écoute sur 0.0.0.0:5050
```

Les participants ouvrent `http://<ip-du-serveur>:5050` — rien à installer.

### Option 4 — Local + Scoreboard réseau (recommandé pour les compétitions)

Chaque membre joue en local sur sa machine, mais tous les scores sont synchronisés sur un **scoreboard commun**.

#### Étape 1 : Le Hub (1 seule machine)

Une machine du réseau fait office de serveur central. Lance le lab normalement :

```bash
cd Lab-RedPawn
source .venv/bin/activate
python3 app.py
```

Note l'IP de cette machine sur le réseau local :
```bash
ip -4 addr show | grep "inet " | grep -v 127.0.0.1    # Linux
ipconfig                                                # Windows
```

Exemple : `192.168.1.42`

#### Étape 2 : Les joueurs (toutes les autres machines)

Chaque participant clone le repo, installe les dépendances, puis lance avec la variable d'environnement `SCOREBOARD_SERVER` :

```bash
cd Lab-RedPawn
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
SCOREBOARD_SERVER="http://192.168.1.42:5050" python3 app.py
```

Sur Windows :
```cmd
set SCOREBOARD_SERVER=http://192.168.1.42:5050
python app.py
```

Chaque joueur accède à **son propre** `http://127.0.0.1:5050`. La synchronisation est automatique :
- À chaque **connexion** (login), le score existant est envoyé au hub
- À chaque **bonne réponse**, le score est mis à jour sur le hub
- Le **scoreboard** affiche tous les joueurs du réseau (badge 🌐)

#### Pré-requis réseau

- Toutes les machines doivent être sur le **même réseau local** (même WiFi / LAN)
- Le port **5050** du hub doit être accessible (pas de firewall bloquant)
- Si le hub n'est pas joignable, le lab continue de fonctionner en local sans erreur

## 🔧 Prérequis

- Python 3.8+
- Flask (installé automatiquement par start.sh ou via `pip install -r requirements.txt`)

Aucune autre dépendance. Le lab est entièrement self-contained.

## 📝 Pour les formateurs

### Réinitialiser les scores
Supprimez le fichier `instance/soc_lab.db` et relancez l'application.

### Ajouter un challenge
1. Créez un nouveau fichier `challenges/c19_xxx.py` en suivant le format existant
2. Importez-le dans `challenges/registry.py`
3. Relancez l'application

### Modifier les réponses
Les réponses sont dans chaque fichier de challenge (`answer` et `flag`). Le système anti-triche hache automatiquement les réponses au démarrage.

---

**Bonne chasse, analystes !** 🎯
