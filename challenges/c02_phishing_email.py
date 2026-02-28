"""
Challenge 2 — Analyse d'Email de Phishing
Niveau : 1 (Analyste Junior)
Catégorie : Phishing
"""

ARTIFACT_EMAIL_QUEUE = r"""
================================================================================
 _____ __  __    _    ___ _       ___  _   _ _____ _   _ _____
| ____|  \/  |  / \  |_ _| |     / _ \| | | | ____| | | | ____|
|  _| | |\/| | / _ \  | || |    | | | | | | |  _| | | | |  _|
| |___| |  | |/ ___ \ | || |___ | |_| | |_| | |___| |_| | |___
|_____|_|  |_/_/   \_\___|_____| \__\_\\___/|_____|\\___/|_____|
================================================================================
 QUEUE DE SIGNALEMENT PHISHING — RAPPORT DE SHIFT
 Instance    : MAIL-GW-01.redpawn-corp.local
 Date        : 18/02/2026
 Shift       : 06h00 — 14h00
 Signalements: 5 emails en attente d'analyse
================================================================================

═══════════════════════════════════════════════════════════════
 EMAIL #1 — Signalé par p.leroy@redpawn-corp.com à 07h12
═══════════════════════════════════════════════════════════════

Return-Path: <noreply@linkedin.com>
Received: from mail-sor-f41.google.com (209.85.220.41)
    by mail.redpawn-corp.local (10.0.2.10) with ESMTPS id abc123
    for <p.leroy@redpawn-corp.com>;
    Tue, 18 Feb 2026 07:02:11 +0100
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
    by mx.google.com with SMTPS id d2sor654321abc
    for <p.leroy@redpawn-corp.com>;
    Tue, 18 Feb 2026 06:02:10 +0000
Received: by 2002:a17:906:c14a:0:0:0:0 with SMTP id dp10csp456789
    for <p.leroy@redpawn-corp.com>;
    Tue, 18 Feb 2026 06:02:09 +0000
From: "LinkedIn" <noreply@linkedin.com>
To: p.leroy@redpawn-corp.com
Subject: Pierre, vous avez 3 nouvelles notifications
Date: Tue, 18 Feb 2026 06:02:08 +0000
Message-ID: <CABx+XJ3kR=nH8vy+kFP5Q@mail.linkedin.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
List-Unsubscribe: <https://www.linkedin.com/e/v2?e=2f5k0x-lv>
X-LinkedIn-Class: INMAIL-NOTIFICATION
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=linkedin.com;
    s=proddkim1024; h=from:to:subject:date;
    bh=abc123def456==; b=WxYzAbCdEf...
Authentication-Results: mail.redpawn-corp.local;
    spf=pass smtp.mailfrom=linkedin.com;
    dkim=pass header.d=linkedin.com;
    dmarc=pass

<html>
<body>
<div style="max-width:600px;margin:auto;font-family:Helvetica,Arial;">
<img src="https://static.licdn.com/aero-v1/sc/h/2if24wp7oqlodqdlgei1n1520" width="84">
<h3>Pierre, voici ce que vous avez manqué</h3>
<p>Vous avez 3 nouvelles vues de profil et 1 invitation de connexion.</p>
<a href="https://www.linkedin.com/feed/?trk=eml-email_pymk_01-hero-02" style="background:#0a66c2;color:white;padding:10px 24px;text-decoration:none;border-radius:24px;">Voir les notifications</a>
<p style="font-size:11px;color:#86888a;">Si vous ne souhaitez plus recevoir ces emails : <a href="https://www.linkedin.com/e/v2?e=2f5k0x-lv&lipi=urn%3Ali">Se désinscrire</a></p>
<p style="font-size:10px;color:#86888a;">LinkedIn Corporation, 1000 W Maude Ave, Sunnyvale, CA 94085</p>
</div>
</body>
</html>

═══════════════════════════════════════════════════════════════
 EMAIL #2 — Signalé par a.bernard@redpawn-corp.com à 08h34
═══════════════════════════════════════════════════════════════

Return-Path: <bounce+srs=abc123=FR=redpawn-corp.com=a.bernard@amazonses.com>
Received: from a48-93.smtp-out.amazonses.com (54.240.48.93)
    by mail.redpawn-corp.local (10.0.2.10) with ESMTPS id def456
    for <a.bernard@redpawn-corp.com>;
    Tue, 18 Feb 2026 08:30:02 +0100
Received: from email-smtp.eu-west-1.amazonaws.com (email-smtp.eu-west-1.amazonaws.com [54.240.48.93])
    by a48-93.smtp-out.amazonses.com (Postfix) with ESMTPS
    Tue, 18 Feb 2026 07:30:01 +0000
From: "Slack" <notification@slack.com>
To: a.bernard@redpawn-corp.com
Subject: [Slack] New message from #dev-ops: "Deploiement prod v2.4.1 confirmé"
Date: Tue, 18 Feb 2026 07:30:00 +0000
Message-ID: <01020186abc123-def456-7890@eu-west-1.amazonses.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
X-SES-Outgoing: 2026.02.18-54.240.48.93
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=slack.com;
    s=s1; h=from:to:subject:date;
    bh=xyz789abc==; b=AbCdEfGh...
Authentication-Results: mail.redpawn-corp.local;
    spf=pass smtp.mailfrom=amazonses.com;
    dkim=pass header.d=slack.com;
    dmarc=pass

<html><body>
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto;max-width:600px;margin:auto;">
<img src="https://a.slack-edge.com/80588/marketing/img/meta/slack_hash_256.png" width="36">
<p><strong>Thomas Girard</strong> posted in <strong>#dev-ops</strong>:</p>
<blockquote style="border-left:4px solid #36c5f0;padding:8px 12px;background:#f8f8f8;">"Deploiement production v2.4.1 validé. RAS après 30min de monitoring. @a.bernard pour info."</blockquote>
<a href="https://redpawn-corp.slack.com/archives/C03ABCD1234/p170824900001" style="color:#1264a3;">Voir le message dans Slack</a>
<p style="font-size:10px;color:#696969;">Pour ne plus recevoir ces notifications : <a href="https://redpawn-corp.slack.com/account/notifications">Paramètres</a></p>
</div>
</body></html>

═══════════════════════════════════════════════════════════════
 EMAIL #3 — Signalé par marie.dupont@redpawn-corp.com à 10h45
 ⚠️  UTILISATEUR INDIQUE : "Je ne sais pas si c'est légitime"
═══════════════════════════════════════════════════════════════

Return-Path: <notifications-noreply@micros0ft-security.com>
Received: from mail-gateway.micros0ft-security.com (91.234.56.78)
    by mail.redpawn-corp.local (10.0.2.10) with SMTP;
    Wed, 18 Feb 2026 10:23:45 +0100
Received: from localhost (unknown [91.234.56.78])
    by mail-gateway.micros0ft-security.com (Postfix) with ESMTP id A1B2C3D4
    Wed, 18 Feb 2026 10:23:40 +0100
From: "Microsoft 365 Security" <notifications-noreply@micros0ft-security.com>
To: marie.dupont@redpawn-corp.com
Cc:
Subject: [URGENT] Activite suspecte detectee sur votre compte Microsoft 365
Date: Wed, 18 Feb 2026 10:23:39 +0100
Message-ID: <5f8a3b2c-1234-5678-9abc-def012345678@micros0ft-security.com>
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="----=_Part_12345"
X-Mailer: PHPMailer 6.5.0
X-Priority: 1
X-Spam-Score: 7.8
X-SPF-Result: FAIL (domain micros0ft-security.com does not designate 91.234.56.78 as permitted sender)
DKIM-Signature: NONE
Authentication-Results: mail.redpawn-corp.local;
    spf=fail smtp.mailfrom=micros0ft-security.com;
    dkim=none;
    dmarc=fail

------=_Part_12345
Content-Type: text/html; charset="UTF-8"

<html>
<body style="font-family: Segoe UI, Arial; background: #f5f5f5; padding: 20px;">
<div style="max-width: 600px; margin: auto; background: white; border-radius: 8px; padding: 30px;">
<img src="https://micros0ft-security.com/images/ms-logo.png" width="120">
<h2 style="color: #0078d4;">⚠️ Alerte de Sécurité Microsoft 365</h2>
<p>Bonjour Marie,</p>
<p>Nous avons détecté une <strong>activité de connexion suspecte</strong> sur votre compte Microsoft 365 :</p>
<table style="width: 100%; border-collapse: collapse; margin: 15px 0;">
<tr><td style="padding: 8px; border: 1px solid #ddd;">📍 Localisation</td><td style="padding: 8px; border: 1px solid #ddd;">Moscou, Russie</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;">🖥️ Appareil</td><td style="padding: 8px; border: 1px solid #ddd;">Linux Desktop</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;">⏰ Heure</td><td style="padding: 8px; border: 1px solid #ddd;">18/02/2026 09:15:00 UTC</td></tr>
<tr><td style="padding: 8px; border: 1px solid #ddd;">🌐 Adresse IP</td><td style="padding: 8px; border: 1px solid #ddd;">185.156.73.44</td></tr>
</table>
<p><strong>Si ce n'était pas vous</strong>, veuillez sécuriser votre compte immédiatement :</p>
<p style="text-align: center;">
<a href="https://micros0ft-security.com/auth/login?redirect=https://login.microsoftonline.com&session=ae5f8b2c&user=marie.dupont" 
   style="background: #0078d4; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; display: inline-block;">
   🔒 Sécuriser mon compte
</a>
</p>
<p style="font-size: 12px; color: #666;">Si vous ne sécurisez pas votre compte dans les <strong>24 heures</strong>, 
il sera temporairement suspendu pour votre protection.</p>
<hr style="border: 1px solid #eee;">
<p style="font-size: 11px; color: #999;">Microsoft Corporation, One Microsoft Way, Redmond, WA 98052<br>
Cet email a été envoyé automatiquement. Ne pas répondre.</p>
</div>
</body>
</html>

------=_Part_12345--

═══════════════════════════════════════════════════════════════
 EMAIL #4 — Signalé par c.martin@redpawn-corp.com à 11h05
═══════════════════════════════════════════════════════════════

Return-Path: <noreply@github.com>
Received: from out-25.smtp.github.com (192.30.252.208)
    by mail.redpawn-corp.local (10.0.2.10) with ESMTPS id ghi789
    for <c.martin@redpawn-corp.com>;
    Tue, 18 Feb 2026 10:55:33 +0100
Received: from github-smtp2-ext-cp1-prd.iad.github.net (github-smtp2-ext-cp1-prd.iad.github.net [10.0.6.23])
    by smtp.github.com (Postfix) with ESMTP id AB12CD34
    for <c.martin@redpawn-corp.com>;
    Tue, 18 Feb 2026 09:55:32 +0000
From: "GitHub" <noreply@github.com>
To: c.martin@redpawn-corp.com
Subject: [redpawn-corp/monitoring-agent] Pull request #142: Fix memory leak in collector module
Date: Tue, 18 Feb 2026 09:55:31 +0000
Message-ID: <redpawn-corp/monitoring-agent/pull/142@github.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
X-GitHub-Recipient-Address: c.martin@redpawn-corp.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=github.com;
    s=pf2023; h=from:to:subject:date;
    bh=LmN0oPqR==; b=StUvWxYz...
Authentication-Results: mail.redpawn-corp.local;
    spf=pass smtp.mailfrom=github.com;
    dkim=pass header.d=github.com;
    dmarc=pass

<html><body>
<div style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial;max-width:600px;margin:auto;">
<img src="https://github.githubassets.com/images/email/global/octocat-logo.png" width="32">
<h3><a href="https://github.com/redpawn-corp/monitoring-agent/pull/142" style="color:#0366d6;">Fix memory leak in collector module #142</a></h3>
<p><strong>deploy-bot</strong> requested your review on this pull request.</p>
<blockquote style="border-left:4px solid #dfe2e5;padding:8px 12px;color:#586069;">Fixed memory leak in telemetry collector. Also added periodic update check for module freshness.</blockquote>
<p>Files changed: <code>src/telemetry/collector.py</code> (+12, -2)</p>
<a href="https://github.com/redpawn-corp/monitoring-agent/pull/142" style="background:#2ea44f;color:white;padding:8px 16px;text-decoration:none;border-radius:6px;">View pull request</a>
<p style="font-size:11px;color:#586069;">You are receiving this because you were requested for review.</p>
</div>
</body></html>

═══════════════════════════════════════════════════════════════
 EMAIL #5 — Signalé par j.martin@redpawn-corp.com à 11h20
 ⚠️  UTILISATEUR INDIQUE : "J'ai reçu la même chose que Marie"
═══════════════════════════════════════════════════════════════

Return-Path: <no-reply@accounts.microsoft.com>
Received: from mail-dm6nam11on20601.outbound.protection.outlook.com (40.107.223.601)
    by mail.redpawn-corp.local (10.0.2.10) with ESMTPS id jkl012
    for <j.martin@redpawn-corp.com>;
    Tue, 18 Feb 2026 11:15:22 +0100
Received: from BN8PR04MB5765.namprd04.prod.outlook.com (2603:10b6:408:120::10)
    by BN9PR04MB8211.namprd04.prod.outlook.com (2603:10b6:408:130::22)
    with HTTPS; Tue, 18 Feb 2026 10:15:21 +0000
From: "Microsoft account team" <no-reply@accounts.microsoft.com>
To: j.martin@redpawn-corp.com
Subject: Microsoft account security info was changed
Date: Tue, 18 Feb 2026 10:15:20 +0000
Message-ID: <SA1PR04MB9876.88234567.namprd04.prod.outlook.com>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"
X-MS-Exchange-Organization-SCL: -1
X-MS-Exchange-Organization-AuthSource: BN8PR04MB5765.namprd04.prod.outlook.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=accountprotection.microsoft.com;
    s=selector2-accountprotection-microsoft-com;
    h=From:Date:Subject:Message-ID:Content-Type;
    bh=QrStUvWx==; b=YzAbCdEf...
Authentication-Results: mail.redpawn-corp.local;
    spf=pass smtp.mailfrom=accounts.microsoft.com;
    dkim=pass header.d=accountprotection.microsoft.com;
    dmarc=pass

<html>
<body style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana; background: #f2f2f2;">
<div style="max-width: 600px; margin: 20px auto; background: white; padding: 40px;">
<img src="https://img-prod-cms-rt-microsoft-com.akamaized.net/cms/api/am/imageFileData/RE1Mu3b" width="108">
<h2 style="color: #1a1a1a; font-weight: 400;">Recent activity on your account</h2>
<p style="color:#1a1a1a;">We noticed a successful sign-in to your Microsoft account. If this was you, you can safely ignore this email.</p>
<table style="width:100%;border-collapse:collapse;margin:15px 0;background:#f5f5f5;border-radius:4px;">
<tr><td style="padding:12px 16px;color:#505050;">Country/Region</td><td style="padding:12px 16px;">France</td></tr>
<tr><td style="padding:12px 16px;color:#505050;">IP address</td><td style="padding:12px 16px;">86.238.45.112</td></tr>
<tr><td style="padding:12px 16px;color:#505050;">Platform</td><td style="padding:12px 16px;">Windows 10</td></tr>
<tr><td style="padding:12px 16px;color:#505050;">Browser</td><td style="padding:12px 16px;">Edge 122.0</td></tr>
<tr><td style="padding:12px 16px;color:#505050;">Date</td><td style="padding:12px 16px;">02/18/2026 09:12 (UTC)</td></tr>
</table>
<p style="color:#505050;">If this wasn't you, your account may be compromised. Please visit <a href="https://account.microsoft.com/security" style="color:#0067b8;">your Microsoft account security page</a> to secure it.</p>
<p style="font-size:12px;color:#505050;margin-top:20px;">Thanks,<br>The Microsoft account team</p>
<hr style="border:1px solid #e5e5e5;">
<p style="font-size:10px;color:#696969;">Microsoft Corporation, One Microsoft Way, Redmond, WA 98052</p>
</div>
</body>
</html>
"""

ARTIFACT_HEADERS_ANALYSIS = """
=== ANALYSE AUTOMATIQUE DES 5 EMAILS SIGNALÉS ===
=== Mail Gateway : MAIL-GW-01.redpawn-corp.local ===
=== Date d'analyse : 18/02/2026 11:30 ===

──────── EMAIL #1 (p.leroy — LinkedIn) ────────
SPF Check    : PASS — 209.85.220.41 autorisé par linkedin.com
DKIM Check   : PASS — Signature valide (d=linkedin.com)
DMARC Check  : PASS — Politique respectée
X-Spam-Score : 0.2 / 10
Note         : Transit via infrastructure Google (normal pour LinkedIn)

──────── EMAIL #2 (a.bernard — Slack) ────────
SPF Check    : PASS — 54.240.48.93 autorisé par amazonses.com
DKIM Check   : PASS — Signature valide (d=slack.com)
DMARC Check  : PASS — Politique respectée
X-Spam-Score : 0.1 / 10
Note         : Transit via AWS SES (normal pour Slack)

──────── EMAIL #3 (marie.dupont — "Microsoft 365 Security") ────────
SPF Check    : FAIL — Le domaine micros0ft-security.com n'autorise PAS 91.234.56.78
DKIM Check   : NONE — Aucune signature DKIM présente
DMARC Check  : FAIL — Politique DMARC non respectée
X-Spam-Score : 7.8 / 10
X-Mailer     : PHPMailer 6.5.0 (inhabituel pour Microsoft)
Note         : ⚠️ Indicateurs multiples de phishing

──────── EMAIL #4 (c.martin — GitHub) ────────
SPF Check    : PASS — 192.30.252.208 autorisé par github.com
DKIM Check   : PASS — Signature valide (d=github.com)
DMARC Check  : PASS — Politique respectée
X-Spam-Score : 0.3 / 10
Note         : Notification légitime de PR review

──────── EMAIL #5 (j.martin — Microsoft) ────────
SPF Check    : PASS — Serveur Outlook Protection autorisé
DKIM Check   : PASS — Signature valide (d=accountprotection.microsoft.com)
DMARC Check  : PASS — Politique respectée
X-Spam-Score : 0.0 / 10
X-MS-Exchange-Organization-SCL : -1 (sûr)
Note         : Email légitime Microsoft — notification de connexion

═══════════════════════════════════════════
 WHOIS & OSINT — Domaines suspects
═══════════════════════════════════════════

WHOIS — micros0ft-security.com :
  Registrar      : NameCheap Inc.
  Created        : 2026-02-15T02:34:11Z (il y a 3 jours)
  Updated        : 2026-02-15T02:34:11Z
  Expires        : 2027-02-15T02:34:11Z
  Registrant     : REDACTED FOR PRIVACY (WhoisGuard)
  Registrant Org : REDACTED FOR PRIVACY
  Name Servers   : ns1.shady-hosting.ru, ns2.shady-hosting.ru
  Status         : clientTransferProhibited

WHOIS — 91.234.56.78 :
  Organization : FlyHosting LLC
  Country      : RU (Russia)
  City         : Moscow
  ASN          : AS48693
  Abuse Email  : abuse@flyhosting.ru
  Allocated    : 2024-06-12

WHOIS — 185.156.73.44 (IP mentionnée dans l'email #3 comme "IP suspecte") :
  Organization : DataLine LLC
  Country      : RU (Russia)
  ASN          : AS57629
  Note         : Pas d'abus connu — probablement inventée par l'attaquant pour effrayer la victime

═══════════════════════════════════════════
 ANALYSE URL — Liens extraits de l'email #3
═══════════════════════════════════════════

URL analysée : https://micros0ft-security.com/auth/login?redirect=https://login.microsoftonline.com&session=ae5f8b2c&user=marie.dupont

VirusTotal   : 8/92 détections
  - Google Safe Browsing : Phishing
  - Kaspersky            : Phishing
  - ESET                 : Phishing
  - Forcepoint           : Suspicious
  - Sophos               : Malware
  - Avira                : Phishing
  - BitDefender          : Phishing  
  - Fortinet             : Phishing

URLScan.io   : Redirect vers page de login Microsoft contrefaite
  - Page titre    : "Sign in to your account"
  - Certificat SSL: Let's Encrypt (valide mais gratuit — pas un certificat Microsoft)
  - Hébergement   : FlyHosting LLC (même que le serveur SMTP)
  - Screenshot    : Clone quasi-identique de login.microsoftonline.com
  - Formulaire    : Envoie les credentials OTP vers /api/harvest.php

Analyse Sandbox ANY.RUN (URL) :
  - La page demande email → mot de passe → code MFA
  - Après saisie du MFA, redirige vers login.microsoftonline.com réel
  - Les credentials sont envoyés en POST vers micros0ft-security.com/api/harvest.php
  - Cookie de session capturé et envoyé vers 185.234.72.19:443 via WebSocket
  - Technique : Adversary-in-the-Middle (AiTM) phishing — contourne le MFA
"""

ARTIFACT_EMAIL_LEGIT_MICROSOFT = r"""
=== EMAIL LÉGITIME MICROSOFT — Référence pour comparaison ===
=== Récupéré depuis la mailbox de j.martin pour comparaison ===

(Email #5 de la queue — headers complets ci-dessus)

Points de comparaison avec l'email suspect (#3) :

┌─────────────────────┬────────────────────────────────────┬────────────────────────────────────┐
│ CRITÈRE             │ EMAIL #3 (suspect)                 │ EMAIL #5 (Microsoft légitime)      │
├─────────────────────┼────────────────────────────────────┼────────────────────────────────────┤
│ From domain         │ micros0ft-security.com             │ accounts.microsoft.com             │
│ Return-Path         │ micros0ft-security.com             │ accounts.microsoft.com             │
│ SMTP server         │ 91.234.56.78 (Russie)             │ Outlook Protection (Microsoft)     │
│ SPF                 │ FAIL                               │ PASS                               │
│ DKIM                │ NONE                               │ PASS (accountprotection.ms.com)    │
│ DMARC               │ FAIL                               │ PASS                               │
│ X-Mailer            │ PHPMailer 6.5.0                    │ (pas de X-Mailer, Exchange natif)  │
│ Spam Score          │ 7.8                                │ 0.0                                │
│ Ton                 │ URGENT, menace de suspension       │ Informatif, pas de menace          │
│ Lien CTA            │ micros0ft-security.com/auth/...    │ account.microsoft.com/security     │
│ SSL Certificate     │ Let's Encrypt                      │ DigiCert (Microsoft)               │
│ Received hops       │ 2 (serveur unique)                 │ 3+ (infra Microsoft multi-hop)     │
│ Encoding            │ Pas de text/plain alternative      │ Pas nécessaire (Exchange)          │
└─────────────────────┴────────────────────────────────────┴────────────────────────────────────┘
"""

CHALLENGE = {
    "id": "c02_phishing_email",
    "title": "🎣 L'Hameçon de Microsoft",
    "category": "phishing",
    "level": 1,
    "points_total": 420,
    "estimated_time": "35-50 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 11h30  
**Priorité :** HAUTE  
**Source :** Queue de signalement phishing — Shift du matin

---

En arrivant à votre shift, vous trouvez **5 emails signalés** par les utilisateurs dans la queue de triage phishing. Certains utilisateurs paniquent, d'autres signalent par précaution.

Votre responsable SOC vous dit :

> *"On a 5 signalements dans la queue ce matin. La plupart seront probablement des faux positifs — des gens qui signalent des newsletters ou des notifs légitimes. Mais il y a peut-être du vrai phishing dans le lot. Trie tout ça, identifie la menace réelle, et donne-moi les IoC à bloquer."*

Analysez les 5 emails, comparez les headers, les résultats SPF/DKIM/DMARC, et identifiez le(s) email(s) malveillant(s).
    """,
    "artifacts": [
        {
            "name": "phishing_queue_report.eml",
            "type": "email",
            "content": ARTIFACT_EMAIL_QUEUE,
            "description": "Queue de signalement phishing — 5 emails signalés par les utilisateurs"
        },
        {
            "name": "automated_analysis.txt",
            "type": "text",
            "content": ARTIFACT_HEADERS_ANALYSIS,
            "description": "Analyse automatique SPF/DKIM/DMARC, WHOIS, URL scan et sandbox"
        },
        {
            "name": "microsoft_email_comparison.txt",
            "type": "reference",
            "content": ARTIFACT_EMAIL_LEGIT_MICROSOFT,
            "description": "Comparaison Email #3 (suspect) vs Email #5 (Microsoft légitime)"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Parmi les 5 emails signalés, lequel est malveillant ? (donnez le numéro #)",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 40,
            "hints": [
                "Comparez les résultats SPF/DKIM/DMARC de chaque email",
                "Un seul email a FAIL sur les 3 vérifications"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Quel est le domaine d'envoi utilisé par l'attaquant dans l'email malveillant ?",
            "answer": "micros0ft-security.com",
            "flag": "REDPAWN{micros0ft-security.com}",
            "points": 30,
            "hints": [
                "Regardez l'en-tête 'From:' de l'email identifié comme malveillant",
                "Le domaine utilise du typosquatting — un caractère est remplacé"
            ],
            "hint_cost": 10
        },
        {
            "id": "q3",
            "text": "L'email #5 (j.martin) ressemble à l'email #3 (Marie). Pourquoi l'email #5 est-il légitime ? Donnez la preuve technique principale (3 lettres).",
            "answer": "SPF",
            "flag": "REDPAWN{SPF}",
            "points": 50,
            "hints": [
                "Comparez les résultats d'authentification des deux emails",
                "L'email #5 PASS sur les 3 vérifications, l'email #3 FAIL"
            ],
            "hint_cost": 17
        },
        {
            "id": "q4",
            "text": "Quel outil inhabituel a été utilisé pour envoyer l'email malveillant ? (nom et version exacte)",
            "answer": "PHPMailer 6.5.0",
            "flag": "REDPAWN{PHPMailer_6.5.0}",
            "points": 40,
            "hints": [
                "Cherchez l'en-tête X-Mailer dans l'email suspect",
                "Microsoft n'utilise pas cet outil pour ses emails"
            ],
            "hint_cost": 13
        },
        {
            "id": "q5",
            "text": "Quelle technique de phishing avancée le site malveillant utilise-t-il pour contourner le MFA ? (nom anglais, acronyme de 4 lettres)",
            "answer": "AiTM",
            "flag": "REDPAWN{AiTM}",
            "points": 60,
            "hints": [
                "Regardez l'analyse sandbox ANY.RUN de l'URL",
                "Adversary-in-the-Middle — le site se place entre la victime et Microsoft"
            ],
            "hint_cost": 20
        },
        {
            "id": "q6",
            "text": "Vers quel endpoint PHP les credentials volés sont-ils envoyés ? (chemin complet commençant par /)",
            "answer": "/api/harvest.php",
            "flag": "REDPAWN{/api/harvest.php}",
            "points": 40,
            "hints": [
                "Regardez l'analyse sandbox de l'URL malveillante",
                "Les credentials sont envoyés en POST vers un fichier PHP"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Quel domaine Microsoft légitime est utilisé dans le paramètre 'redirect' du lien de phishing ?",
            "answer": "login.microsoftonline.com",
            "flag": "REDPAWN{login.microsoftonline.com}",
            "points": 30,
            "hints": [
                "Regardez l'URL complète du lien 'Sécuriser mon compte'",
                "Cherchez le paramètre redirect= dans l'URL"
            ],
            "hint_cost": 10
        },
        {
            "id": "q8",
            "text": "Depuis combien de jours le domaine malveillant a-t-il été enregistré au moment de l'email ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 30,
            "hints": [
                "Regardez le WHOIS du domaine suspect",
                "Comparez la date de création avec la date de l'email"
            ],
            "hint_cost": 10
        },
        {
            "id": "q9",
            "text": "L'email #4 (GitHub) mentionne un utilisateur suspect lié à un autre challenge. Quel est son nom ?",
            "answer": "deploy-bot",
            "flag": "REDPAWN{deploy-bot}",
            "points": 50,
            "hints": [
                "Regardez qui demande une review dans le PR GitHub",
                "Ce nom apparaît aussi dans un incident supply chain"
            ],
            "hint_cost": 17
        },
        {
            "id": "q10",
            "text": "Combien de détections VirusTotal l'URL malveillante a-t-elle obtenues ? (format: X/Y)",
            "answer": "8/92",
            "flag": "REDPAWN{8/92}",
            "points": 30,
            "hints": [
                "Regardez la section Analyse URL dans le rapport automatique"
            ],
            "hint_cost": 10
        },
        {
            "id": "q11",
            "text": "Quel fournisseur de certificat SSL le site de phishing utilise-t-il ?",
            "answer": "Let's Encrypt",
            "flag": "REDPAWN{Lets_Encrypt}",
            "points": 30,
            "hints": [
                "Regardez l'analyse URLScan.io",
                "C'est un fournisseur de certificats gratuits"
            ],
            "hint_cost": 10
        }
    ]
}
