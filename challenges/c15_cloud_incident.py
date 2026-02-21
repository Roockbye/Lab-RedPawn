"""
Challenge 15 — Incident Cloud AWS
Niveau : 5 (Threat Hunter)
Catégorie : Sécurité Cloud
"""

ARTIFACT_CLOUDTRAIL = r"""
========== AWS CloudTrail — Analyse d'incident ==========
Compte AWS : 743219876543 (redpawn-production)
Région principale : eu-west-3 (Paris)
Période : 17/02/2026 22:00 — 18/02/2026 06:00 UTC

===== ÉVÉNEMENTS SUSPECTS (filtrés par l'équipe IR) =====

--- EVENT 1 : 17/02/2026 22:14:33 UTC ---
EventName    : ConsoleLogin
EventSource  : signin.amazonaws.com
SourceIP     : 185.234.72.19
UserIdentity : arn:aws:iam::743219876543:user/svc-deploy-ci
MFAUsed      : false
Response     : Success
ErrorCode    : (none)
UserAgent    : Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
additionalEventData:
  LoginTo     : https://eu-west-3.console.aws.amazon.com
  MobileVersion : No
NOTES: Connexion console depuis IP C2 connue, sans MFA.
       Le compte svc-deploy-ci est un compte de service CI/CD.
       Ce compte n'est PAS censé se connecter via la console.

--- EVENT 2 : 17/02/2026 22:18:07 UTC ---
EventName    : CreateAccessKey
EventSource  : iam.amazonaws.com
SourceIP     : 185.234.72.19
UserIdentity : arn:aws:iam::743219876543:user/svc-deploy-ci
RequestParams:
  UserName   : svc-deploy-ci
ResponseElements:
  AccessKey  :
    AccessKeyId  : AKIA3EXAMPLE7BACKDOOR
    Status       : Active
    CreateDate   : 2026-02-17T22:18:07Z
NOTES: Création d'une 2ème clé d'accès pour persistance.

--- EVENT 3 : 17/02/2026 22:22:45 UTC ---
EventName    : CreateUser
EventSource  : iam.amazonaws.com
SourceIP     : 185.234.72.19
UserIdentity : arn:aws:iam::743219876543:user/svc-deploy-ci
RequestParams:
  UserName   : aws-health-monitor
  Path       : /system/
NOTES: Création d'un faux utilisateur dans /system/ pour se fondre
       dans les comptes de service légitimes.

--- EVENT 4 : 17/02/2026 22:23:12 UTC ---
EventName    : AttachUserPolicy
EventSource  : iam.amazonaws.com
SourceIP     : 185.234.72.19
UserIdentity : arn:aws:iam::743219876543:user/svc-deploy-ci
RequestParams:
  UserName   : aws-health-monitor
  PolicyArn  : arn:aws:iam::aws:policy/AdministratorAccess
NOTES: Attribution de la policy AdministratorAccess au faux compte.
       Escalade de privilèges massive.

--- EVENT 5 : 17/02/2026 22:25:00 UTC ---
EventName    : CreateAccessKey
EventSource  : iam.amazonaws.com
SourceIP     : 185.234.72.19
UserIdentity : arn:aws:iam::743219876543:user/svc-deploy-ci
RequestParams:
  UserName   : aws-health-monitor
ResponseElements:
  AccessKey  :
    AccessKeyId  : AKIA3EXAMPLEHEALTHMON
    Status       : Active
NOTES: Création de clé d'accès pour le faux compte admin.

--- EVENT 6 : 17/02/2026 22:45:33 UTC ---
EventName    : ListBuckets
EventSource  : s3.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
AccessKeyId  : AKIA3EXAMPLEHEALTHMON
UserAgent    : aws-cli/2.15.0 Python/3.11.6 Linux/5.15.0
NOTES: L'attaquant utilise maintenant le faux compte depuis une IP
       DIFFÉRENTE — probable VPS de pivot.
       Changement de User-Agent : maintenant aws-cli (plus console).

--- EVENT 7 : 17/02/2026 22:46:10 UTC ---
EventName    : ListObjects
EventSource  : s3.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
RequestParams:
  BucketName : redpawn-client-contracts
  Prefix     : 2026/
NOTES: Énumération du bucket contenant les contrats clients.

--- EVENT 8 : 17/02/2026 22:48:00 — 23:15:00 UTC ---
EventName    : GetObject (x247 events)
EventSource  : s3.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
RequestParams:
  BucketName : redpawn-client-contracts
  Keys       : [247 fichiers téléchargés]
  TotalSize  : 892 MB
NOTES: Exfiltration massive de 247 fichiers depuis le bucket de contrats.
       Durée : 27 minutes

--- EVENT 9 : 17/02/2026 23:20:44 UTC ---
EventName    : GetObject (x18 events)
EventSource  : s3.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
RequestParams:
  BucketName : redpawn-db-backups
  Keys       : [18 fichiers]
  TotalSize  : 3.2 GB
NOTES: Téléchargement des sauvegardes de bases de données.

--- EVENT 10 : 17/02/2026 23:45:22 UTC ---
EventName    : CreateFunction
EventSource  : lambda.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
RequestParams:
  FunctionName : health-check-scheduler
  Runtime      : python3.11
  Handler      : lambda_function.lambda_handler
  Role         : arn:aws:iam::743219876543:role/LambdaAdminRole
  Environment:
    Variables:
      C2_ENDPOINT : "aHR0cHM6Ly8xODUuMjM0LjcyLjE5OjQ0My9hd3MtY2hlY2s="
      EXFIL_BUCKET : "redpawn-db-backups"
NOTES: Création d'une Lambda malveillante pour persistance.
       C2_ENDPOINT est encodé en base64.
       Décodé : https://185.234.72.19:443/aws-check

--- EVENT 11 : 17/02/2026 23:46:00 UTC ---
EventName    : CreateEventSourceMapping
EventSource  : lambda.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
RequestParams:
  FunctionName : health-check-scheduler
  EventSourceArn : arn:aws:sqs:eu-west-3:743219876543:deployment-queue
NOTES: La Lambda est déclenchée par la queue SQS de déploiement.
       Chaque déploiement légitime déclenche la backdoor.

--- EVENT 12 : 18/02/2026 00:12:55 UTC ---
EventName    : StopLogging
EventSource  : cloudtrail.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
RequestParams:
  Name : redpawn-security-trail
ErrorCode    : AccessDeniedException
ErrorMessage : "User is not authorized to perform: cloudtrail:StopLogging"
NOTES: Tentative de désactiver CloudTrail — ÉCHOUÉE grâce au SCP
       (Service Control Policy) de l'Organization qui protège CloudTrail.

--- EVENT 13 : 18/02/2026 00:15:33 UTC ---
EventName    : DeleteTrail
EventSource  : cloudtrail.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
ErrorCode    : AccessDeniedException
NOTES: 2ème tentative de supprimer les logs — encore bloquée par SCP.

--- EVENT 14 : 18/02/2026 01:00:00 UTC ---
EventName    : PutBucketPolicy
EventSource  : s3.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
RequestParams:
  BucketName : redpawn-db-backups
  Policy     : {"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::redpawn-db-backups/*"}]}
NOTES: Modification de la policy du bucket pour le rendre PUBLIC.
       Toutes les sauvegardes DB sont maintenant accessibles à Internet.

===== RÉSUMÉ DE L'ACTIVITÉ IAM =====
Comptes compromis : svc-deploy-ci (credentials volés)
Comptes créés     : aws-health-monitor (Admin)
Clés créées       : 2 (AKIA3EXAMPLE7BACKDOOR, AKIA3EXAMPLEHEALTHMON)
Policies attachées: AdministratorAccess
Lambdas créées    : health-check-scheduler (backdoor)
Buckets exfiltrés : redpawn-client-contracts (892 MB), redpawn-db-backups (3.2 GB)
Anti-forensics    : 2 tentatives de désactiver CloudTrail (échouées)
"""

CHALLENGE = {
    "id": "c15_cloud_incident",
    "title": "☁️ Tempête dans le Cloud",
    "category": "cloud_security",
    "level": 5,
    "points_total": 580,
    "estimated_time": "45-65 min",
    "story": """
## Briefing de Mission

**Date :** 18 février 2026, 07h00
**Priorité :** CRITIQUE
**Source :** Équipe Cloud Security

---

L'attaquant ne s'est pas limité à l'infrastructure on-premise. Les credentials AWS du compte de service CI/CD (`svc-deploy-ci`) ont été extraits pendant la compromission et utilisés pour pivoter dans l'environnement cloud AWS.

> *"Ils sont dans notre AWS. Le compte CI/CD a été compromis et ils ont créé un faux utilisateur admin. On a les logs CloudTrail mais il faut tout reconstituer. Combien de données ont été volées ? Quelle persistance ont-ils mise en place ? Est-ce qu'ils ont touché à nos backups ?"*

Cloud forensics avancée. Montrez que vous savez traquer dans le cloud.
    """,
    "artifacts": [
        {
            "name": "cloudtrail_analysis.txt",
            "type": "log",
            "content": ARTIFACT_CLOUDTRAIL,
            "description": "Analyse CloudTrail — Incident AWS redpawn-production"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quel compte IAM a été utilisé pour l'accès initial à la console AWS ?",
            "answer": "svc-deploy-ci",
            "flag": "FLAG{svc-deploy-ci}",
            "points": 40,
            "hints": [
                "C'est le premier événement ConsoleLogin",
                "C'est un compte de service CI/CD"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Quel est le nom du faux utilisateur IAM créé par l'attaquant pour la persistance ?",
            "answer": "aws-health-monitor",
            "flag": "FLAG{aws-health-monitor}",
            "points": 40,
            "hints": [
                "Cherchez l'événement CreateUser",
                "Il est créé dans le path /system/ pour paraître légitime"
            ],
            "hint_cost": 13
        },
        {
            "id": "q3",
            "text": "Quelle policy AWS a été attachée au faux compte pour obtenir les privilèges maximaux ?",
            "answer": "AdministratorAccess",
            "flag": "FLAG{AdministratorAccess}",
            "points": 40,
            "hints": [
                "Regardez l'événement AttachUserPolicy",
                "C'est la policy AWS la plus permissive possible"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Quelle IP l'attaquant utilise-t-il après le pivot (pas l'IP C2 initiale) ?",
            "answer": "45.89.127.33",
            "flag": "FLAG{45.89.127.33}",
            "points": 50,
            "hints": [
                "L'attaquant change d'IP entre les événements console et CLI",
                "Regardez les événements à partir de l'EVENT 6"
            ],
            "hint_cost": 17
        },
        {
            "id": "q5",
            "text": "Combien de fichiers au total ont été exfiltrés depuis le bucket redpawn-client-contracts ?",
            "answer": "247",
            "flag": "FLAG{247}",
            "points": 40,
            "hints": [
                "Regardez l'EVENT 8 — GetObject events"
            ],
            "hint_cost": 13
        },
        {
            "id": "q6",
            "text": "Quel volume TOTAL de données a été exfiltré depuis les 2 buckets S3 (en GB, arrondi au dixième) ?",
            "answer": "4.1",
            "flag": "FLAG{4.1}",
            "points": 50,
            "hints": [
                "Additionnez les tailles : un bucket de 892 MB et un de 3.2 GB",
                "892 MB ~ 0.9 GB + 3.2 GB = 4.1 GB"
            ],
            "hint_cost": 17
        },
        {
            "id": "q7",
            "text": "Quel est le nom de la fonction Lambda malveillante créée pour la persistance ?",
            "answer": "health-check-scheduler",
            "flag": "FLAG{health-check-scheduler}",
            "points": 40,
            "hints": [
                "Regardez l'événement CreateFunction"
            ],
            "hint_cost": 13
        },
        {
            "id": "q8",
            "text": "Quel service AWS déclenche la Lambda malveillante ? (type de source)",
            "answer": "SQS",
            "flag": "FLAG{SQS}",
            "points": 50,
            "hints": [
                "Regardez l'événement CreateEventSourceMapping",
                "L'ARN de la source contient le type de service"
            ],
            "hint_cost": 17
        },
        {
            "id": "q9",
            "text": "Quelle protection a empêché l'attaquant de désactiver CloudTrail ?",
            "answer": "SCP",
            "flag": "FLAG{SCP}",
            "points": 60,
            "hints": [
                "C'est mentionné dans les NOTES de l'EVENT 12",
                "Service Control Policy — politique de l'Organization AWS"
            ],
            "hint_cost": 20
        },
        {
            "id": "q10",
            "text": "Qu'a fait l'attaquant au bucket redpawn-db-backups pour maximiser les dégâts ? (action API)",
            "answer": "PutBucketPolicy",
            "flag": "FLAG{PutBucketPolicy}",
            "points": 50,
            "hints": [
                "C'est le dernier événement majeur",
                "Il a rendu le bucket accessible à tout le monde"
            ],
            "hint_cost": 17
        },
        {
            "id": "q11",
            "text": "Combien de tentatives anti-forensics (suppression de logs) l'attaquant a-t-il effectuées ?",
            "answer": "2",
            "flag": "FLAG{2}",
            "points": 30,
            "hints": [
                "StopLogging + DeleteTrail = 2 tentatives"
            ],
            "hint_cost": 10
        },
        {
            "id": "q12",
            "text": "Le MFA était-il activé lors de la connexion console initiale ?",
            "answer": "false",
            "flag": "FLAG{false}",
            "points": 40,
            "hints": [
                "Regardez le champ MFAUsed dans l'EVENT 1"
            ],
            "hint_cost": 13
        }
    ]
}
