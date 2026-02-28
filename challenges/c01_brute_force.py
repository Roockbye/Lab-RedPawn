"""
Challenge 1 — Attaque par Brute Force SSH
Niveau : 1 (Analyste Junior)
Catégorie : Analyse de Logs
"""

ARTIFACT_AUTH_LOG = r"""Feb 18 00:00:01 srv-web-01 CRON[9001]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 00:00:01 srv-web-01 CRON[9001]: pam_unix(cron:session): session closed for user root
Feb 18 00:05:00 srv-web-01 CRON[9012]: pam_unix(cron:session): session opened for user www-data by (uid=0)
Feb 18 00:05:01 srv-web-01 CRON[9012]: pam_unix(cron:session): session closed for user www-data
Feb 18 00:15:33 srv-web-01 sshd[9101]: Failed password for invalid user postgres from 103.45.67.12 port 39201 ssh2
Feb 18 00:15:35 srv-web-01 sshd[9101]: Failed password for invalid user oracle from 103.45.67.12 port 39202 ssh2
Feb 18 00:15:37 srv-web-01 sshd[9101]: Connection closed by 103.45.67.12 port 39202 [preauth]
Feb 18 00:30:01 srv-web-01 CRON[9150]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 00:30:01 srv-web-01 CRON[9150]: pam_unix(cron:session): session closed for user root
Feb 18 01:00:01 srv-web-01 CRON[9200]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 01:00:01 srv-web-01 CRON[9200]: pam_unix(cron:session): session closed for user root
Feb 18 01:05:00 srv-web-01 CRON[9212]: pam_unix(cron:session): session opened for user www-data by (uid=0)
Feb 18 01:05:01 srv-web-01 CRON[9212]: pam_unix(cron:session): session closed for user www-data
Feb 18 01:12:44 srv-web-01 sshd[9250]: Accepted publickey for deploy from 10.0.1.50 port 48201 ssh2
Feb 18 01:12:44 srv-web-01 sshd[9250]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Feb 18 01:14:02 srv-web-01 sudo: deploy : TTY=pts/0 ; PWD=/opt/webapp ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx
Feb 18 01:14:10 srv-web-01 sshd[9250]: pam_unix(sshd:session): session closed for user deploy
Feb 18 01:30:01 srv-web-01 CRON[9300]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 01:30:01 srv-web-01 CRON[9300]: pam_unix(cron:session): session closed for user root
Feb 18 01:45:22 srv-web-01 sshd[9350]: Failed password for invalid user admin from 91.240.118.54 port 52100 ssh2
Feb 18 01:45:24 srv-web-01 sshd[9350]: Failed password for invalid user admin from 91.240.118.54 port 52101 ssh2
Feb 18 01:45:26 srv-web-01 sshd[9350]: Failed password for root from 91.240.118.54 port 52102 ssh2
Feb 18 01:45:28 srv-web-01 sshd[9350]: Failed password for root from 91.240.118.54 port 52103 ssh2
Feb 18 01:45:30 srv-web-01 sshd[9350]: Connection closed by 91.240.118.54 port 52103 [preauth]
Feb 18 02:00:01 srv-web-01 CRON[9400]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 02:00:01 srv-web-01 CRON[9400]: pam_unix(cron:session): session closed for user root
Feb 18 02:05:00 srv-web-01 CRON[9412]: pam_unix(cron:session): session opened for user www-data by (uid=0)
Feb 18 02:05:01 srv-web-01 CRON[9412]: pam_unix(cron:session): session closed for user www-data
Feb 18 02:30:01 srv-web-01 CRON[9450]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 02:30:01 srv-web-01 CRON[9450]: pam_unix(cron:session): session closed for user root
Feb 18 02:33:10 srv-web-01 sshd[9470]: Failed password for invalid user test from 178.62.34.89 port 41230 ssh2
Feb 18 02:33:12 srv-web-01 sshd[9470]: Connection closed by 178.62.34.89 port 41230 [preauth]
Feb 18 03:00:01 srv-web-01 CRON[9500]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 03:00:02 srv-web-01 CRON[9500]: pam_unix(cron:session): session closed for user root
Feb 18 03:05:00 srv-web-01 CRON[9512]: pam_unix(cron:session): session opened for user www-data by (uid=0)
Feb 18 03:05:01 srv-web-01 CRON[9512]: pam_unix(cron:session): session closed for user www-data
Feb 18 03:15:44 srv-web-01 sshd[9540]: Failed password for invalid user nagios from 45.33.21.102 port 38900 ssh2
Feb 18 03:15:46 srv-web-01 sshd[9540]: Failed password for invalid user zabbix from 45.33.21.102 port 38901 ssh2
Feb 18 03:15:48 srv-web-01 sshd[9540]: Failed password for invalid user monitor from 45.33.21.102 port 38902 ssh2
Feb 18 03:15:50 srv-web-01 sshd[9540]: Connection closed by 45.33.21.102 port 38902 [preauth]
Feb 18 03:30:01 srv-web-01 CRON[9600]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 03:30:01 srv-web-01 CRON[9600]: pam_unix(cron:session): session closed for user root
Feb 18 04:00:01 srv-web-01 CRON[9700]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 04:00:01 srv-web-01 CRON[9700]: pam_unix(cron:session): session closed for user root
Feb 18 04:05:00 srv-web-01 CRON[9712]: pam_unix(cron:session): session opened for user www-data by (uid=0)
Feb 18 04:05:01 srv-web-01 CRON[9712]: pam_unix(cron:session): session closed for user www-data
Feb 18 04:22:11 srv-web-01 sshd[9740]: Accepted publickey for deploy from 10.0.1.50 port 49100 ssh2
Feb 18 04:22:12 srv-web-01 sshd[9740]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Feb 18 04:23:33 srv-web-01 sudo: deploy : TTY=pts/0 ; PWD=/opt/webapp ; USER=root ; COMMAND=/usr/bin/apt update
Feb 18 04:25:01 srv-web-01 sudo: deploy : TTY=pts/0 ; PWD=/opt/webapp ; USER=root ; COMMAND=/usr/bin/apt upgrade -y
Feb 18 04:30:01 srv-web-01 CRON[9800]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 04:30:01 srv-web-01 CRON[9800]: pam_unix(cron:session): session closed for user root
Feb 18 04:35:44 srv-web-01 sshd[9740]: pam_unix(sshd:session): session closed for user deploy
Feb 18 05:00:01 srv-web-01 CRON[9900]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 05:00:01 srv-web-01 CRON[9900]: pam_unix(cron:session): session closed for user root
Feb 18 05:05:00 srv-web-01 CRON[9912]: pam_unix(cron:session): session opened for user www-data by (uid=0)
Feb 18 05:05:01 srv-web-01 CRON[9912]: pam_unix(cron:session): session closed for user www-data
Feb 18 05:12:33 srv-web-01 sshd[9930]: Failed password for invalid user pi from 198.51.100.45 port 55100 ssh2
Feb 18 05:12:35 srv-web-01 sshd[9930]: Failed password for invalid user pi from 198.51.100.45 port 55101 ssh2
Feb 18 05:12:37 srv-web-01 sshd[9930]: Failed password for root from 198.51.100.45 port 55102 ssh2
Feb 18 05:12:39 srv-web-01 sshd[9930]: Connection closed by 198.51.100.45 port 55102 [preauth]
Feb 18 05:30:01 srv-web-01 CRON[10000]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 05:30:01 srv-web-01 CRON[10000]: pam_unix(cron:session): session closed for user root
Feb 18 06:00:01 srv-web-01 CRON[10100]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 06:00:01 srv-web-01 CRON[10100]: pam_unix(cron:session): session closed for user root
Feb 18 06:05:00 srv-web-01 CRON[10112]: pam_unix(cron:session): session opened for user www-data by (uid=0)
Feb 18 06:05:01 srv-web-01 CRON[10112]: pam_unix(cron:session): session closed for user www-data
Feb 18 06:15:22 srv-web-01 sshd[10130]: Accepted publickey for monitoring from 10.0.1.55 port 47200 ssh2
Feb 18 06:15:23 srv-web-01 sshd[10130]: pam_unix(sshd:session): session opened for user monitoring by (uid=0)
Feb 18 06:15:45 srv-web-01 sshd[10130]: pam_unix(sshd:session): session closed for user monitoring
Feb 18 06:30:01 srv-web-01 CRON[10200]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 06:30:01 srv-web-01 CRON[10200]: pam_unix(cron:session): session closed for user root
Feb 18 06:45:10 srv-web-01 sshd[10240]: Failed password for invalid user support from 62.210.180.33 port 60100 ssh2
Feb 18 06:45:12 srv-web-01 sshd[10240]: Failed password for invalid user webmaster from 62.210.180.33 port 60101 ssh2
Feb 18 06:45:14 srv-web-01 sshd[10240]: Failed password for root from 62.210.180.33 port 60102 ssh2
Feb 18 06:45:16 srv-web-01 sshd[10240]: Failed password for invalid user guest from 62.210.180.33 port 60103 ssh2
Feb 18 06:45:18 srv-web-01 sshd[10240]: Connection closed by 62.210.180.33 port 60103 [preauth]
Feb 18 07:00:01 srv-web-01 CRON[10300]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 07:00:01 srv-web-01 CRON[10300]: pam_unix(cron:session): session closed for user root
Feb 18 07:05:00 srv-web-01 CRON[10312]: pam_unix(cron:session): session opened for user www-data by (uid=0)
Feb 18 07:05:01 srv-web-01 CRON[10312]: pam_unix(cron:session): session closed for user www-data
Feb 18 07:15:44 srv-web-01 sshd[10340]: Accepted publickey for monitoring from 10.0.1.55 port 47300 ssh2
Feb 18 07:15:45 srv-web-01 sshd[10340]: pam_unix(sshd:session): session opened for user monitoring by (uid=0)
Feb 18 07:16:02 srv-web-01 sshd[10340]: pam_unix(sshd:session): session closed for user monitoring
Feb 18 07:22:31 srv-web-01 sshd[10360]: Failed password for invalid user admin from 209.141.55.78 port 33400 ssh2
Feb 18 07:22:33 srv-web-01 sshd[10360]: Failed password for invalid user admin from 209.141.55.78 port 33401 ssh2
Feb 18 07:22:35 srv-web-01 sshd[10360]: Failed password for root from 209.141.55.78 port 33402 ssh2
Feb 18 07:22:37 srv-web-01 sshd[10360]: Connection closed by 209.141.55.78 port 33402 [preauth]
Feb 18 07:30:01 srv-web-01 CRON[10400]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 07:30:01 srv-web-01 CRON[10400]: pam_unix(cron:session): session closed for user root
Feb 18 07:45:19 srv-web-01 sshd[10450]: Accepted publickey for deploy from 10.0.1.50 port 49500 ssh2
Feb 18 07:45:20 srv-web-01 sshd[10450]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Feb 18 07:46:33 srv-web-01 sudo: deploy : TTY=pts/0 ; PWD=/opt/webapp ; USER=root ; COMMAND=/usr/bin/systemctl status nginx
Feb 18 07:47:01 srv-web-01 sshd[10450]: pam_unix(sshd:session): session closed for user deploy
Feb 18 08:00:01 srv-web-01 CRON[10500]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 08:00:01 srv-web-01 CRON[10500]: pam_unix(cron:session): session closed for user root
Feb 18 08:05:00 srv-web-01 CRON[10512]: pam_unix(cron:session): session opened for user www-data by (uid=0)
Feb 18 08:05:01 srv-web-01 CRON[10512]: pam_unix(cron:session): session closed for user www-data
Feb 18 08:10:15 srv-web-01 sshd[10530]: Failed password for invalid user teamcity from 23.94.12.67 port 42100 ssh2
Feb 18 08:10:17 srv-web-01 sshd[10530]: Failed password for invalid user jenkins from 23.94.12.67 port 42101 ssh2
Feb 18 08:10:19 srv-web-01 sshd[10530]: Connection closed by 23.94.12.67 port 42101 [preauth]
Feb 18 08:12:01 srv-web-01 sshd[12340]: Accepted publickey for deploy from 10.0.1.50 port 52341 ssh2
Feb 18 08:12:02 srv-web-01 sshd[12340]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Feb 18 08:13:44 srv-web-01 sshd[12340]: pam_unix(sshd:session): session closed for user deploy
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
Feb 18 08:18:01 srv-web-01 sshd[12510]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Feb 18 08:19:33 srv-web-01 sshd[12510]: pam_unix(sshd:session): session closed for user deploy
Feb 18 08:22:14 srv-web-01 CRON[12600]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 08:22:14 srv-web-01 CRON[12600]: pam_unix(cron:session): session closed for user root
Feb 18 08:30:00 srv-web-01 sshd[12700]: Accepted password for backdoor from 185.234.72.19 port 44500 ssh2
Feb 18 08:30:01 srv-web-01 sshd[12700]: pam_unix(sshd:session): session opened for user backdoor by (uid=0)
Feb 18 08:30:01 srv-web-01 CRON[12710]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 08:30:01 srv-web-01 CRON[12710]: pam_unix(cron:session): session closed for user root
Feb 18 08:35:22 srv-web-01 sshd[12750]: Failed password for invalid user mysql from 45.155.205.93 port 37800 ssh2
Feb 18 08:35:24 srv-web-01 sshd[12750]: Failed password for invalid user backup from 45.155.205.93 port 37801 ssh2
Feb 18 08:35:26 srv-web-01 sshd[12750]: Connection closed by 45.155.205.93 port 37801 [preauth]
Feb 18 09:00:01 srv-web-01 CRON[12800]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 09:00:01 srv-web-01 CRON[12800]: pam_unix(cron:session): session closed for user root
Feb 18 09:05:00 srv-web-01 CRON[12812]: pam_unix(cron:session): session opened for user www-data by (uid=0)
Feb 18 09:05:01 srv-web-01 CRON[12812]: pam_unix(cron:session): session closed for user www-data
Feb 18 09:15:44 srv-web-01 sshd[12830]: Accepted publickey for monitoring from 10.0.1.55 port 47500 ssh2
Feb 18 09:15:45 srv-web-01 sshd[12830]: pam_unix(sshd:session): session opened for user monitoring by (uid=0)
Feb 18 09:16:01 srv-web-01 sshd[12830]: pam_unix(sshd:session): session closed for user monitoring
Feb 18 09:30:01 srv-web-01 CRON[12900]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 09:30:01 srv-web-01 CRON[12900]: pam_unix(cron:session): session closed for user root
Feb 18 09:45:12 srv-web-01 sshd[12950]: Failed password for invalid user tomcat from 141.98.10.22 port 48700 ssh2
Feb 18 09:45:14 srv-web-01 sshd[12950]: Failed password for root from 141.98.10.22 port 48701 ssh2
Feb 18 09:45:16 srv-web-01 sshd[12950]: Connection closed by 141.98.10.22 port 48701 [preauth]
Feb 18 10:00:01 srv-web-01 CRON[13000]: pam_unix(cron:session): session opened for user root by (uid=0)
Feb 18 10:00:01 srv-web-01 CRON[13000]: pam_unix(cron:session): session closed for user root
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
            "text": "Plusieurs IPs sources effectuent des tentatives de connexion échouées. Laquelle représente une véritable menace (brute force ciblé suivi d'un accès réussi) ?",
            "answer": "185.234.72.19",
            "flag": "REDPAWN{185.234.72.19}",
            "points": 30,
            "hints": [
                "Cherchez l'IP qui a non seulement échoué, mais aussi RÉUSSI à se connecter",
                "Les scanners opportunistes échouent sur 2-4 tentatives puis abandonnent",
                "L'attaquant réel persiste plus longtemps et obtient un 'Accepted password'"
            ],
            "hint_cost": 10
        },
        {
            "id": "q2",
            "text": "Combien de tentatives de connexion échouées l'attaquant principal a-t-il effectuées ? (uniquement cette IP)",
            "answer": "28",
            "flag": "REDPAWN{28}",
            "points": 40,
            "hints": [
                "Comptez toutes les lignes 'Failed password' provenant uniquement de l'IP de l'attaquant réel",
                "Attention à ne pas mélanger avec les scans d'autres IPs",
                "admin: 10, root: 10, ubuntu: 3, test: 2, user: 2, ftpuser: 1 = ?"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Sur quel compte utilisateur l'attaquant a-t-il finalement réussi à se connecter ?",
            "answer": "ftpuser",
            "flag": "REDPAWN{ftpuser}",
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
            "flag": "REDPAWN{08:16:02}",
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
            "flag": "REDPAWN{sudo}",
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
            "flag": "REDPAWN{backdoor}",
            "points": 40,
            "hints": [
                "Cherchez une ligne 'useradd' dans les logs",
                "Le compte créé a un UID=0, ce qui est très suspect"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Pourquoi le compte créé est-il particulièrement dangereux ?",
            "answer": "0",
            "flag": "REDPAWN{0}",
            "points": 30,
            "hints": [
                "Regardez les détails du useradd : UID=?",
                "UID 0 est réservé au compte root"
            ],
            "hint_cost": 10
        }
    ]
}
