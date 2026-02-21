"""
Challenge 1 — Attaque par Brute Force SSH
Niveau : 1 (Analyste Junior)
Catégorie : Analyse de Logs
"""

ARTIFACT_AUTH_LOG = r"""Feb 18 08:12:01 srv-web-01 sshd[12340]: Accepted publickey for deploy from 10.0.1.50 port 52341 ssh2
Feb 18 08:15:22 srv-web-01 sshd[12455]: Failed password for admin from 185.234.72.19 port 44312 ssh2
Feb 18 08:15:23 srv-web-01 sshd[12455]: Failed password for admin from 185.234.72.19 port 44312 ssh2
Feb 18 08:15:24 srv-web-01 sshd[12455]: Failed password for admin from 185.234.72.19 port 44312 ssh2
Feb 18 08:15:25 srv-web-01 sshd[12455]: Failed password for admin from 185.234.72.19 port 44312 ssh2
Feb 18 08:15:26 srv-web-01 sshd[12455]: Failed password for admin from 185.234.72.19 port 44313 ssh2
Feb 18 08:15:27 srv-web-01 sshd[12455]: Failed password for admin from 185.234.72.19 port 44313 ssh2
Feb 18 08:15:28 srv-web-01 sshd[12455]: Failed password for admin from 185.234.72.19 port 44314 ssh2
Feb 18 08:15:29 srv-web-01 sshd[12455]: Failed password for admin from 185.234.72.19 port 44314 ssh2
Feb 18 08:15:30 srv-web-01 sshd[12455]: Failed password for admin from 185.234.72.19 port 44315 ssh2
Feb 18 08:15:31 srv-web-01 sshd[12455]: Failed password for admin from 185.234.72.19 port 44315 ssh2
Feb 18 08:15:32 srv-web-01 sshd[12455]: Failed password for root from 185.234.72.19 port 44316 ssh2
Feb 18 08:15:33 srv-web-01 sshd[12455]: Failed password for root from 185.234.72.19 port 44316 ssh2
Feb 18 08:15:34 srv-web-01 sshd[12455]: Failed password for root from 185.234.72.19 port 44317 ssh2
Feb 18 08:15:35 srv-web-01 sshd[12455]: Failed password for root from 185.234.72.19 port 44317 ssh2
Feb 18 08:15:36 srv-web-01 sshd[12455]: Failed password for root from 185.234.72.19 port 44318 ssh2
Feb 18 08:15:37 srv-web-01 sshd[12455]: Failed password for root from 185.234.72.19 port 44318 ssh2
Feb 18 08:15:38 srv-web-01 sshd[12455]: Failed password for root from 185.234.72.19 port 44319 ssh2
Feb 18 08:15:39 srv-web-01 sshd[12455]: Failed password for root from 185.234.72.19 port 44319 ssh2
Feb 18 08:15:40 srv-web-01 sshd[12455]: Failed password for root from 185.234.72.19 port 44320 ssh2
Feb 18 08:15:41 srv-web-01 sshd[12455]: Failed password for root from 185.234.72.19 port 44320 ssh2
Feb 18 08:15:42 srv-web-01 sshd[12455]: Failed password for ubuntu from 185.234.72.19 port 44321 ssh2
Feb 18 08:15:43 srv-web-01 sshd[12455]: Failed password for ubuntu from 185.234.72.19 port 44321 ssh2
Feb 18 08:15:44 srv-web-01 sshd[12455]: Failed password for ubuntu from 185.234.72.19 port 44322 ssh2
Feb 18 08:15:45 srv-web-01 sshd[12455]: Failed password for test from 185.234.72.19 port 44323 ssh2
Feb 18 08:15:46 srv-web-01 sshd[12455]: Failed password for test from 185.234.72.19 port 44323 ssh2
Feb 18 08:15:47 srv-web-01 sshd[12455]: Failed password for user from 185.234.72.19 port 44324 ssh2
Feb 18 08:15:48 srv-web-01 sshd[12455]: Failed password for user from 185.234.72.19 port 44324 ssh2
Feb 18 08:15:49 srv-web-01 sshd[12455]: Failed password for ftpuser from 185.234.72.19 port 44325 ssh2
Feb 18 08:16:02 srv-web-01 sshd[12455]: Accepted password for ftpuser from 185.234.72.19 port 44326 ssh2
Feb 18 08:16:05 srv-web-01 sshd[12460]: pam_unix(sshd:session): session opened for user ftpuser by (uid=0)
Feb 18 08:16:10 srv-web-01 sudo: ftpuser : TTY=pts/1 ; PWD=/home/ftpuser ; USER=root ; COMMAND=/bin/bash
Feb 18 08:16:15 srv-web-01 sshd[12470]: pam_unix(sshd:session): session opened for user root by ftpuser(uid=1003)
Feb 18 08:17:30 srv-web-01 useradd[12501]: new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash
Feb 18 08:18:00 srv-web-01 sshd[12510]: Accepted publickey for deploy from 10.0.1.50 port 52400 ssh2
Feb 18 08:22:14 srv-web-01 CRON[12600]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 08:30:00 srv-web-01 sshd[12700]: Accepted password for backdoor from 185.234.72.19 port 44500 ssh2
Feb 18 09:00:01 srv-web-01 CRON[12800]: pam_unix(cron:session): session opened for user root by (uid=0)
"""

CHALLENGE = {
    "id": "c01_brute_force",
    "title": "🔐 Opération Porte Dérobée",
    "category": "log_analysis",
    "level": 1,
    "points_total": 250,
    "estimated_time": "20-30 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 09h30  
**Priorité :** HAUTE  
**Source :** Alerte automatique SIEM — Règle `SSH_BRUTE_FORCE_DETECTED`

---

Le SIEM a déclenché une alerte sur le serveur **srv-web-01** (serveur web de production).  
Un nombre anormalement élevé de tentatives de connexion SSH échouées a été détecté en provenance d'une IP externe.

Votre responsable SOC vous confie l'investigation :

> *"On a une alerte brute force sur le serveur web de prod. Vérifie les logs auth, détermine si l'attaquant a réussi à rentrer, et si oui, ce qu'il a fait. Je veux un rapport complet."*

Analysez le fichier `auth.log` ci-dessous et répondez aux questions pour compléter votre investigation.
    """,
    "artifacts": [
        {
            "name": "auth.log",
            "type": "log",
            "content": ARTIFACT_AUTH_LOG,
            "description": "Extrait du fichier /var/log/auth.log de srv-web-01"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quelle est l'adresse IP de l'attaquant ?",
            "answer": "185.234.72.19",
            "flag": "FLAG{185.234.72.19}",
            "points": 30,
            "hints": [
                "Cherchez l'IP qui génère le plus de 'Failed password'",
                "C'est une IP externe (pas en 10.x.x.x)",
                "L'IP commence par 185"
            ],
            "hint_cost": 10
        },
        {
            "id": "q2",
            "text": "Combien de tentatives de connexion échouées l'attaquant a-t-il effectuées au total ?",
            "answer": "27",
            "flag": "FLAG{27}",
            "points": 40,
            "hints": [
                "Comptez toutes les lignes 'Failed password' provenant de l'IP attaquante",
                "Il y a des tentatives sur plusieurs comptes (admin, root, ubuntu, test, user, ftpuser)",
                "admin: 8, root: 10, ubuntu: 3, test: 2, user: 2, ftpuser: 1 = ?"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Sur quel compte utilisateur l'attaquant a-t-il finalement réussi à se connecter ?",
            "answer": "ftpuser",
            "flag": "FLAG{ftpuser}",
            "points": 40,
            "hints": [
                "Cherchez la première ligne 'Accepted password' venant de l'IP attaquante",
                "Le compte compromis est un compte de service",
                "Le nom commence par 'ftp'"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "À quelle heure exacte (format HH:MM:SS) l'attaquant a-t-il obtenu l'accès initial ?",
            "answer": "08:16:02",
            "flag": "FLAG{08:16:02}",
            "points": 30,
            "hints": [
                "Regardez le timestamp de la ligne 'Accepted password' pour ftpuser",
                "C'est entre 08:15 et 08:17"
            ],
            "hint_cost": 10
        },
        {
            "id": "q5",
            "text": "Quelle commande de privilege escalation l'attaquant a-t-il utilisée après la connexion ?",
            "answer": "sudo",
            "flag": "FLAG{sudo}",
            "points": 40,
            "hints": [
                "Cherchez une action de l'utilisateur ftpuser après sa connexion",
                "L'attaquant a exécuté une commande pour devenir root"
            ],
            "hint_cost": 13
        },
        {
            "id": "q6",
            "text": "Quel est le nom du compte de backdoor créé par l'attaquant ?",
            "answer": "backdoor",
            "flag": "FLAG{backdoor}",
            "points": 40,
            "hints": [
                "Cherchez une ligne 'useradd' dans les logs",
                "Le compte créé a un UID=0, ce qui est très suspect"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Pourquoi le compte créé est-il particulièrement dangereux ? (Quel UID lui a été attribué ?)",
            "answer": "0",
            "flag": "FLAG{0}",
            "points": 30,
            "hints": [
                "Regardez les détails du useradd : UID=?",
                "UID 0 est réservé au compte root"
            ],
            "hint_cost": 10
        }
    ]
}
