"""
Challenge 15 — Incident Cloud AWS
Niveau : 5 (Threat Hunter)
Catégorie : Sécurité Cloud
"""

ARTIFACT_CLOUDTRAIL = r"""
========== AWS CloudTrail — Analyse d'incident ==========
Compte AWS : 743219876543 (redpawn-production)
Région principale : eu-west-3 (Paris)
Période : 17/02/2026 20:00 — 18/02/2026 06:00 UTC
Total événements dans la période : 1,247
Ci-dessous : événements pertinents extraits (non filtrés — inclut le trafic légitime)

===== ÉVÉNEMENTS CHRONOLOGIQUES =====

--- 17/02/2026 20:02:14 UTC ---
EventName    : AssumeRole
EventSource  : sts.amazonaws.com
SourceIP     : 10.0.3.10
UserIdentity : arn:aws:iam::743219876543:role/GitLabCI-Runner
Response     : Success
UserAgent    : aws-sdk-go/1.44.298

--- 17/02/2026 20:05:33 UTC ---
EventName    : DescribeInstances
EventSource  : ec2.amazonaws.com
SourceIP     : 10.0.3.10
UserIdentity : arn:aws:sts::743219876543:assumed-role/GitLabCI-Runner/session-1708200533
Response     : Success
UserAgent    : aws-sdk-go/1.44.298

--- 17/02/2026 20:12:45 UTC ---
EventName    : PutObject
EventSource  : s3.amazonaws.com
SourceIP     : 10.0.3.10
UserIdentity : arn:aws:sts::743219876543:assumed-role/GitLabCI-Runner/session-1708200533
RequestParams:
  BucketName : redpawn-ci-artifacts
  Key        : builds/webapp/v2.4.1/webapp-2.4.1.zip
ResponseElements:
  ETag       : "a3b2c1d4e5f6..."
UserAgent    : aws-sdk-go/1.44.298

--- 17/02/2026 20:15:00 UTC ---
EventName    : GetParameter
EventSource  : ssm.amazonaws.com
SourceIP     : 10.0.3.10
UserIdentity : arn:aws:sts::743219876543:assumed-role/GitLabCI-Runner/session-1708200533
RequestParams:
  Name       : /production/webapp/database-url
  WithDecryption : true
Response     : Success
UserAgent    : aws-sdk-go/1.44.298

--- 17/02/2026 20:30:22 UTC ---
EventName    : UpdateFunctionCode
EventSource  : lambda.amazonaws.com
SourceIP     : 10.0.3.10
UserIdentity : arn:aws:sts::743219876543:assumed-role/GitLabCI-Runner/session-1708200533
RequestParams:
  FunctionName : redpawn-webapp-api
  S3Bucket   : redpawn-ci-artifacts
  S3Key      : builds/webapp/v2.4.1/webapp-2.4.1.zip
Response     : Success
UserAgent    : aws-sdk-go/1.44.298

--- 17/02/2026 20:45:11 UTC ---
EventName    : DescribeDBInstances
EventSource  : rds.amazonaws.com
SourceIP     : 52.47.76.88
UserIdentity : arn:aws:iam::743219876543:user/dba-team
MFAUsed      : true
Response     : Success
UserAgent    : aws-cli/2.15.0 Python/3.11.6 Linux/5.15.0

--- 17/02/2026 21:00:00 UTC ---
EventName    : GetBucketLogging
EventSource  : s3.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/aws-config-role
Response     : Success
UserAgent    : config.amazonaws.com

--- 17/02/2026 21:05:44 UTC ---
EventName    : DescribeAlarms
EventSource  : monitoring.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/CloudWatchEventsRole
Response     : Success
UserAgent    : events.amazonaws.com

--- 17/02/2026 21:15:33 UTC ---
EventName    : Invoke
EventSource  : lambda.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/APIGatewayRole
RequestParams:
  FunctionName : redpawn-webapp-api
Response     : Success
UserAgent    : apigateway.amazonaws.com

--- 17/02/2026 21:22:00 UTC ---
EventName    : ConsoleLogin
EventSource  : signin.amazonaws.com
SourceIP     : 86.247.123.45
UserIdentity : arn:aws:iam::743219876543:user/j.dupont
MFAUsed      : true
Response     : Success
UserAgent    : Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
NOTES: Connexion légitime de l'admin j.dupont — MFA activé.

--- 17/02/2026 21:25:00 UTC ---
EventName    : DescribeInstances
EventSource  : ec2.amazonaws.com
SourceIP     : 86.247.123.45
UserIdentity : arn:aws:iam::743219876543:user/j.dupont
Response     : Success
UserAgent    : Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)

--- 17/02/2026 21:30:00 UTC ---
EventName    : GetBucketAcl
EventSource  : s3.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/aws-config-role
Response     : Success
UserAgent    : config.amazonaws.com

--- 17/02/2026 21:35:22 UTC ---
EventName    : ConsoleLogin
EventSource  : signin.amazonaws.com
SourceIP     : 86.247.123.45
UserIdentity : arn:aws:iam::743219876543:user/j.dupont
MFAUsed      : true
Response     : Failure
ErrorCode    : Failed authentication
UserAgent    : Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)
NOTES: Échec de reconnexion — probablement session expirée, tentative répétée.

--- 17/02/2026 21:36:00 UTC ---
EventName    : ConsoleLogin
EventSource  : signin.amazonaws.com
SourceIP     : 86.247.123.45
UserIdentity : arn:aws:iam::743219876543:user/j.dupont
MFAUsed      : true
Response     : Success
UserAgent    : Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)

--- 17/02/2026 21:45:00 UTC ---
EventName    : Invoke
EventSource  : lambda.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/APIGatewayRole
RequestParams:
  FunctionName : redpawn-webapp-api
Response     : Success
UserAgent    : apigateway.amazonaws.com

--- 17/02/2026 22:00:00 UTC ---
EventName    : PutMetricData
EventSource  : monitoring.amazonaws.com
SourceIP     : 10.0.4.30
UserIdentity : arn:aws:iam::743219876543:role/EC2-CloudWatch-Role
Response     : Success
UserAgent    : aws-sdk-python/1.28.0

--- 17/02/2026 22:05:00 UTC ---
EventName    : GetBucketVersioning
EventSource  : s3.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/aws-config-role
Response     : Success
UserAgent    : config.amazonaws.com

--- 17/02/2026 22:10:00 UTC ---
EventName    : Invoke
EventSource  : lambda.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/APIGatewayRole
RequestParams:
  FunctionName : redpawn-webapp-api
Response     : Success
UserAgent    : apigateway.amazonaws.com

--- 17/02/2026 22:14:33 UTC ---  *** ÉVÉNEMENT SUSPECT ***
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

--- 17/02/2026 22:15:00 UTC ---
EventName    : Invoke
EventSource  : lambda.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/APIGatewayRole
RequestParams:
  FunctionName : redpawn-webapp-api
Response     : Success
UserAgent    : apigateway.amazonaws.com

--- 17/02/2026 22:18:07 UTC ---  *** ÉVÉNEMENT SUSPECT ***
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

--- 17/02/2026 22:20:00 UTC ---
EventName    : PutMetricData
EventSource  : monitoring.amazonaws.com
SourceIP     : 10.0.4.30
UserIdentity : arn:aws:iam::743219876543:role/EC2-CloudWatch-Role
Response     : Success
UserAgent    : aws-sdk-python/1.28.0

--- 17/02/2026 22:22:45 UTC ---  *** ÉVÉNEMENT SUSPECT ***
EventName    : CreateUser
EventSource  : iam.amazonaws.com
SourceIP     : 185.234.72.19
UserIdentity : arn:aws:iam::743219876543:user/svc-deploy-ci
RequestParams:
  UserName   : aws-health-monitor
  Path       : /system/
NOTES: Création d'un faux utilisateur dans /system/ pour se fondre
       dans les comptes de service légitimes.

--- 17/02/2026 22:23:12 UTC ---  *** ÉVÉNEMENT SUSPECT ***
EventName    : AttachUserPolicy
EventSource  : iam.amazonaws.com
SourceIP     : 185.234.72.19
UserIdentity : arn:aws:iam::743219876543:user/svc-deploy-ci
RequestParams:
  UserName   : aws-health-monitor
  PolicyArn  : arn:aws:iam::aws:policy/AdministratorAccess
NOTES: Attribution de la policy AdministratorAccess au faux compte.
       Escalade de privilèges massive.

--- 17/02/2026 22:25:00 UTC ---  *** ÉVÉNEMENT SUSPECT ***
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

--- 17/02/2026 22:30:00 UTC ---
EventName    : Invoke
EventSource  : lambda.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/APIGatewayRole
RequestParams:
  FunctionName : redpawn-webapp-api
Response     : Success
UserAgent    : apigateway.amazonaws.com

--- 17/02/2026 22:35:00 UTC ---
EventName    : GetBucketEncryption
EventSource  : s3.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/aws-config-role
Response     : Success
UserAgent    : config.amazonaws.com

--- 17/02/2026 22:40:00 UTC ---
EventName    : PutMetricData
EventSource  : monitoring.amazonaws.com
SourceIP     : 10.0.4.30
UserIdentity : arn:aws:iam::743219876543:role/EC2-CloudWatch-Role
Response     : Success
UserAgent    : aws-sdk-python/1.28.0

--- 17/02/2026 22:45:33 UTC ---  *** ÉVÉNEMENT SUSPECT ***
EventName    : ListBuckets
EventSource  : s3.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
AccessKeyId  : AKIA3EXAMPLEHEALTHMON
UserAgent    : aws-cli/2.15.0 Python/3.11.6 Linux/5.15.0
NOTES: L'attaquant utilise maintenant le faux compte depuis une IP
       DIFFÉRENTE — probable VPS de pivot.
       Changement de User-Agent : maintenant aws-cli (plus console).

--- 17/02/2026 22:46:10 UTC ---  *** ÉVÉNEMENT SUSPECT ***
EventName    : ListObjects
EventSource  : s3.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
RequestParams:
  BucketName : redpawn-client-contracts
  Prefix     : 2026/
NOTES: Énumération du bucket contenant les contrats clients.

--- 17/02/2026 22:48:00 — 23:15:00 UTC ---  *** EXFILTRATION ***
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

--- 17/02/2026 23:00:00 UTC ---
EventName    : Invoke
EventSource  : lambda.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/APIGatewayRole
RequestParams:
  FunctionName : redpawn-webapp-api
Response     : Success
UserAgent    : apigateway.amazonaws.com

--- 17/02/2026 23:05:00 UTC ---
EventName    : CreateSnapshot
EventSource  : ec2.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/DLM-Lifecycle-Role
RequestParams:
  VolumeId   : vol-0a1b2c3d4e5f6g7h8
Response     : Success
NOTES: Snapshot automatique de sauvegarde — DLM lifecycle légitime.

--- 17/02/2026 23:10:00 UTC ---
EventName    : PutMetricData
EventSource  : monitoring.amazonaws.com
SourceIP     : 10.0.4.30
UserIdentity : arn:aws:iam::743219876543:role/EC2-CloudWatch-Role
Response     : Success
UserAgent    : aws-sdk-python/1.28.0

--- 17/02/2026 23:20:44 UTC ---  *** ÉVÉNEMENT SUSPECT ***
EventName    : GetObject (x18 events)
EventSource  : s3.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
RequestParams:
  BucketName : redpawn-db-backups
  Keys       : [18 fichiers]
  TotalSize  : 3.2 GB
NOTES: Téléchargement des sauvegardes de bases de données.

--- 17/02/2026 23:30:00 UTC ---
EventName    : GetBucketPolicy
EventSource  : s3.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/aws-config-role
Response     : Success
UserAgent    : config.amazonaws.com

--- 17/02/2026 23:35:00 UTC ---
EventName    : Invoke
EventSource  : lambda.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/APIGatewayRole
RequestParams:
  FunctionName : redpawn-webapp-api
Response     : Success
UserAgent    : apigateway.amazonaws.com

--- 17/02/2026 23:40:00 UTC ---
EventName    : PutMetricData
EventSource  : monitoring.amazonaws.com
SourceIP     : 10.0.4.30
UserIdentity : arn:aws:iam::743219876543:role/EC2-CloudWatch-Role
Response     : Success
UserAgent    : aws-sdk-python/1.28.0

--- 17/02/2026 23:45:22 UTC ---  *** ÉVÉNEMENT SUSPECT ***
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

--- 17/02/2026 23:46:00 UTC ---  *** ÉVÉNEMENT SUSPECT ***
EventName    : CreateEventSourceMapping
EventSource  : lambda.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
RequestParams:
  FunctionName : health-check-scheduler
  EventSourceArn : arn:aws:sqs:eu-west-3:743219876543:deployment-queue
NOTES: La Lambda est déclenchée par la queue SQS de déploiement.
       Chaque déploiement légitime déclenche la backdoor.

--- 17/02/2026 23:50:00 UTC ---
EventName    : SendMessage
EventSource  : sqs.amazonaws.com
SourceIP     : 10.0.3.10
UserIdentity : arn:aws:sts::743219876543:assumed-role/GitLabCI-Runner/session-1708235000
RequestParams:
  QueueUrl   : https://sqs.eu-west-3.amazonaws.com/743219876543/deployment-queue
Response     : Success
NOTES: Message SQS légitime du pipeline CI.

--- 18/02/2026 00:00:00 UTC ---
EventName    : PutMetricData
EventSource  : monitoring.amazonaws.com
SourceIP     : 10.0.4.30
UserIdentity : arn:aws:iam::743219876543:role/EC2-CloudWatch-Role
Response     : Success
UserAgent    : aws-sdk-python/1.28.0

--- 18/02/2026 00:05:00 UTC ---
EventName    : Invoke
EventSource  : lambda.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/APIGatewayRole
RequestParams:
  FunctionName : redpawn-webapp-api
Response     : Success
UserAgent    : apigateway.amazonaws.com

--- 18/02/2026 00:12:55 UTC ---  *** ÉVÉNEMENT SUSPECT ***
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

--- 18/02/2026 00:15:33 UTC ---  *** ÉVÉNEMENT SUSPECT ***
EventName    : DeleteTrail
EventSource  : cloudtrail.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
ErrorCode    : AccessDeniedException
NOTES: 2ème tentative de supprimer les logs — encore bloquée par SCP.

--- 18/02/2026 00:20:00 UTC ---
EventName    : PutMetricData
EventSource  : monitoring.amazonaws.com
SourceIP     : 10.0.4.30
UserIdentity : arn:aws:iam::743219876543:role/EC2-CloudWatch-Role
Response     : Success
UserAgent    : aws-sdk-python/1.28.0

--- 18/02/2026 00:30:00 UTC ---
EventName    : GetBucketTagging
EventSource  : s3.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/aws-config-role
Response     : Success
UserAgent    : config.amazonaws.com

--- 18/02/2026 00:45:00 UTC ---
EventName    : Invoke
EventSource  : lambda.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/APIGatewayRole
RequestParams:
  FunctionName : redpawn-webapp-api
Response     : Success
UserAgent    : apigateway.amazonaws.com

--- 18/02/2026 01:00:00 UTC ---  *** ÉVÉNEMENT SUSPECT ***
EventName    : PutBucketPolicy
EventSource  : s3.amazonaws.com
SourceIP     : 45.89.127.33
UserIdentity : arn:aws:iam::743219876543:user/aws-health-monitor
RequestParams:
  BucketName : redpawn-db-backups
  Policy     : {"Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::redpawn-db-backups/*"}]}
NOTES: Modification de la policy du bucket pour le rendre PUBLIC.
       Toutes les sauvegardes DB sont maintenant accessibles à Internet.

--- 18/02/2026 01:15:00 UTC ---
EventName    : PutMetricData
EventSource  : monitoring.amazonaws.com
SourceIP     : 10.0.4.30
UserIdentity : arn:aws:iam::743219876543:role/EC2-CloudWatch-Role
Response     : Success
UserAgent    : aws-sdk-python/1.28.0

--- 18/02/2026 02:00:00 UTC ---
EventName    : CreateSnapshot
EventSource  : ec2.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/DLM-Lifecycle-Role
RequestParams:
  VolumeId   : vol-0a1b2c3d4e5f6g7h8
Response     : Success
NOTES: Snapshot automatique de sauvegarde — DLM lifecycle légitime.

--- 18/02/2026 03:00:00 UTC ---
EventName    : GetBucketLogging
EventSource  : s3.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/aws-config-role
Response     : Success
UserAgent    : config.amazonaws.com

--- 18/02/2026 04:00:00 UTC ---
EventName    : Invoke
EventSource  : lambda.amazonaws.com
SourceIP     : AWS Internal
UserIdentity : arn:aws:iam::743219876543:role/APIGatewayRole
RequestParams:
  FunctionName : redpawn-webapp-api
Response     : Success
UserAgent    : apigateway.amazonaws.com

--- 18/02/2026 05:00:00 UTC ---
EventName    : PutMetricData
EventSource  : monitoring.amazonaws.com
SourceIP     : 10.0.4.30
UserIdentity : arn:aws:iam::743219876543:role/EC2-CloudWatch-Role
Response     : Success
UserAgent    : aws-sdk-python/1.28.0

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

> *"Ils sont dans notre AWS. On a exporté les logs CloudTrail bruts de la nuit dernière — il y a plus de 1200 événements. Beaucoup sont légitimes : CI/CD, monitoring CloudWatch, Config, API Gateway... À toi de séparer le bruit du signal, reconstituer la timeline de l'attaque, et me dire exactement ce qui s'est passé. Combien de données ont été volées ? Quelle persistance ont-ils mise en place ? Est-ce qu'ils ont touché à nos backups ?"*

Cloud forensics avancée. Montrez que vous savez traquer dans le cloud au milieu du bruit légitime.
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
            "flag": "REDPAWN{svc-deploy-ci}",
            "points": 40,
            "hints": [
                "Cherchez le premier événement ConsoleLogin depuis une IP externe suspecte",
                "C'est un compte de service CI/CD qui ne devrait pas se connecter via la console"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Quel est le nom du faux utilisateur IAM créé par l'attaquant pour la persistance ?",
            "answer": "aws-health-monitor",
            "flag": "REDPAWN{aws-health-monitor}",
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
            "flag": "REDPAWN{AdministratorAccess}",
            "points": 40,
            "hints": [
                "Cherchez l'événement AttachUserPolicy dans les logs IAM",
                "C'est la policy AWS la plus permissive possible"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Quelle IP l'attaquant utilise-t-il après le pivot (pas l'IP C2 initiale) ?",
            "answer": "45.89.127.33",
            "flag": "REDPAWN{45.89.127.33}",
            "points": 50,
            "hints": [
                "L'attaquant change d'IP entre les opérations console et CLI",
                "Comparez les SourceIP des événements IAM et S3 du faux compte"
            ],
            "hint_cost": 17
        },
        {
            "id": "q5",
            "text": "Combien de fichiers au total ont été exfiltrés depuis le bucket redpawn-client-contracts ?",
            "answer": "247",
            "flag": "REDPAWN{247}",
            "points": 40,
            "hints": [
                "Cherchez les événements GetObject massifs depuis le faux compte"
            ],
            "hint_cost": 13
        },
        {
            "id": "q6",
            "text": "Quel volume TOTAL de données a été exfiltré depuis les 2 buckets S3 (en GB, arrondi au dixième) ?",
            "answer": "4.1",
            "flag": "REDPAWN{4.1}",
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
            "flag": "REDPAWN{health-check-scheduler}",
            "points": 40,
            "hints": [
                "Cherchez l'événement CreateFunction dans les logs Lambda"
            ],
            "hint_cost": 13
        },
        {
            "id": "q8",
            "text": "Quel service AWS déclenche la Lambda malveillante ?",
            "answer": "SQS",
            "flag": "REDPAWN{SQS}",
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
            "flag": "REDPAWN{SCP}",
            "points": 60,
            "hints": [
                "Regardez les événements CloudTrail avec AccessDeniedException",
                "Service Control Policy — politique de l'Organization AWS"
            ],
            "hint_cost": 20
        },
        {
            "id": "q10",
            "text": "Qu'a fait l'attaquant au bucket redpawn-db-backups pour maximiser les dégâts ?",
            "answer": "PutBucketPolicy",
            "flag": "REDPAWN{PutBucketPolicy}",
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
            "flag": "REDPAWN{2}",
            "points": 30,
            "hints": [
                "StopLogging + DeleteTrail = 2 tentatives"
            ],
            "hint_cost": 10
        },
        {
            "id": "q12",
            "text": "Le MFA était-il activé lors de la connexion console initiale ? (oui/non)",
            "answer": "non",
            "flag": "REDPAWN{non}",
            "points": 40,
            "hints": [
                "Regardez le champ MFAUsed dans l'EVENT 1"
            ],
            "hint_cost": 13
        }
    ]
}
