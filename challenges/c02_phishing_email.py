"""
Challenge 2 — Analyse d'Email de Phishing
Niveau : 1 (Analyste Junior)
Catégorie : Phishing
"""

ARTIFACT_EMAIL = r"""Return-Path: <notifications-noreply@micros0ft-security.com>
Received: from mail-gateway.micros0ft-security.com (91.234.56.78)
    by mail.redpawn-corp.local (10.0.2.10) with SMTP;
    Wed, 18 Feb 2026 10:23:45 +0100
Received: from localhost (unknown [91.234.56.78])
    by mail-gateway.micros0ft-security.com (Postfix) with ESMTP id A1B2C3D4
    Wed, 18 Feb 2026 10:23:40 +0100
From: "Microsoft 365 Security" <notifications-noreply@micros0ft-security.com>
To: marie.dupont@redpawn-corp.com
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
"""

ARTIFACT_HEADERS_ANALYSIS = """
=== Résumé des vérifications automatiques ===

SPF Check    : FAIL — Le domaine micros0ft-security.com n'autorise PAS 91.234.56.78
DKIM Check   : NONE — Aucune signature DKIM présente
DMARC Check  : FAIL — Politique DMARC non respectée
X-Spam-Score : 7.8 / 10

WHOIS — micros0ft-security.com :
  Registrar    : NameCheap Inc.
  Created      : 2026-02-15 (il y a 3 jours)
  Registrant   : REDACTED FOR PRIVACY
  Name Servers : ns1.shady-hosting.ru, ns2.shady-hosting.ru

WHOIS — 91.234.56.78 :
  Organization : FlyHosting LLC
  Country      : RU (Russia)
  ASN          : AS48693
"""

CHALLENGE = {
    "id": "c02_phishing_email",
    "title": "🎣 L'Hameçon de Microsoft",
    "category": "phishing",
    "level": 1,
    "points_total": 280,
    "estimated_time": "25-35 min",
    "story": """
## 📋 Briefing de Mission

**Date :** 18 février 2026, 11h00  
**Priorité :** HAUTE  
**Source :** Signalement utilisateur — Marie Dupont (Comptabilité)

---

Marie Dupont du service comptabilité a signalé un email suspect via le bouton "Report Phishing" d'Outlook.  
Elle n'a **pas encore cliqué** sur le lien mais vous demande de vérifier.

Votre responsable SOC vous dit :

> *"Marie nous a remonté un email louche de Microsoft. Analyse les headers, le contenu, le domaine — je veux savoir si c'est légitime ou du phishing, et quels sont les IoC à bloquer."*

Analysez l'email et les résultats des vérifications techniques pour répondre aux questions.
    """,
    "artifacts": [
        {
            "name": "email_suspect.eml",
            "type": "email",
            "content": ARTIFACT_EMAIL,
            "description": "Email suspect signalé par Marie Dupont"
        },
        {
            "name": "verification_headers.txt",
            "type": "text",
            "content": ARTIFACT_HEADERS_ANALYSIS,
            "description": "Résultat des vérifications SPF/DKIM/DMARC et WHOIS"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quel est le domaine d'envoi utilisé par l'attaquant ? (domaine dans le From:)",
            "answer": "micros0ft-security.com",
            "flag": "FLAG{micros0ft-security.com}",
            "points": 30,
            "hints": [
                "Regardez l'en-tête 'From:' de l'email",
                "Le domaine utilise un typosquatting avec un zéro"
            ],
            "hint_cost": 10
        },
        {
            "id": "q2",
            "text": "Quelle technique de typosquatting est utilisée dans le nom de domaine ? (quel caractère remplace quel autre ?)",
            "answer": "0 remplace o",
            "flag": "FLAG{0_remplace_o}",
            "points": 40,
            "hints": [
                "Comparez 'micros0ft' avec 'microsoft'",
                "Un chiffre remplace une lettre"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Quelle est l'adresse IP du serveur d'envoi de l'email ?",
            "answer": "91.234.56.78",
            "flag": "FLAG{91.234.56.78}",
            "points": 30,
            "hints": [
                "Cherchez dans les headers 'Received:'",
                "C'est l'IP entre parenthèses dans le premier Received"
            ],
            "hint_cost": 10
        },
        {
            "id": "q4",
            "text": "Quel est le résultat de la vérification SPF ?",
            "answer": "FAIL",
            "flag": "FLAG{FAIL}",
            "points": 30,
            "hints": [
                "Cherchez 'SPF' dans les headers ou l'analyse",
                "Le résultat est un mot anglais en majuscules"
            ],
            "hint_cost": 10
        },
        {
            "id": "q5",
            "text": "Depuis combien de jours le domaine malveillant a-t-il été enregistré (au moment de l'email) ?",
            "answer": "3",
            "flag": "FLAG{3}",
            "points": 40,
            "hints": [
                "Regardez le WHOIS du domaine",
                "Comparez la date de création avec la date de l'email"
            ],
            "hint_cost": 13
        },
        {
            "id": "q6",
            "text": "Quel outil a été utilisé pour envoyer l'email ? (nom et version)",
            "answer": "PHPMailer 6.5.0",
            "flag": "FLAG{PHPMailer_6.5.0}",
            "points": 40,
            "hints": [
                "Cherchez l'en-tête X-Mailer",
                "C'est un outil PHP très utilisé pour l'envoi de mails"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Vers quel domaine malveillant le lien 'Sécuriser mon compte' redirige-t-il réellement ?",
            "answer": "micros0ft-security.com",
            "flag": "FLAG{micros0ft-security.com}",
            "points": 30,
            "hints": [
                "Regardez l'attribut href du lien, pas le texte affiché",
                "Le vrai domaine est au début de l'URL, avant le chemin /auth/login"
            ],
            "hint_cost": 10
        },
        {
            "id": "q8",
            "text": "Quelle est l'adresse email de la victime ciblée ?",
            "answer": "marie.dupont@redpawn-corp.com",
            "flag": "FLAG{marie.dupont@redpawn-corp.com}",
            "points": 20,
            "hints": [
                "Regardez l'en-tête 'To:'"
            ],
            "hint_cost": 7
        },
        {
            "id": "q9",
            "text": "Quel registrar a été utilisé pour enregistrer le domaine malveillant ?",
            "answer": "NameCheap Inc.",
            "flag": "FLAG{NameCheap}",
            "points": 20,
            "hints": [
                "Regardez les résultats WHOIS",
                "C'est un registrar populaire connu"
            ],
            "hint_cost": 7
        }
    ]
}
