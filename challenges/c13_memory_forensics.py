"""
Challenge 13 — Forensique Mémoire
Niveau : 4 (Expert SOC)
Catégorie : Forensics Mémoire
"""

ARTIFACT_VOLATILITY = r"""
========== VOLATILITY 3 — ANALYSE MÉMOIRE — SRV-DC-01 ==========
Image : SRV-DC-01_memory_20260218_1430.raw (8 GB)
Profil : Win2019x64_18363
Date acquisition : 18/02/2026 14:30 UTC

===== vol3 -f memory.raw windows.pslist =====
PID    PPID   ImageFileName          CreateTime                 Threads  Handles  SessionId
4      0      System                 2026-02-10 08:00:01        168      -        -
104    4      Registry               2026-02-10 08:00:01        4        -        -
440    4      smss.exe               2026-02-10 08:00:05        2        30       -
556    548    csrss.exe              2026-02-10 08:00:07        10       543      0
620    548    wininit.exe            2026-02-10 08:00:08        1        78       0
636    612    csrss.exe              2026-02-10 08:00:08        12       289      1
684    620    services.exe           2026-02-10 08:00:09        6        243      0
692    620    lsass.exe              2026-02-10 08:00:09        8        792      0
788    684    svchost.exe            2026-02-10 08:00:10        12       387      0
856    684    svchost.exe            2026-02-10 08:00:10        8        267      0
1124   684    svchost.exe            2026-02-10 08:00:12        15       412      0
1456   684    spoolsv.exe            2026-02-10 08:00:15        7        189      0
1892   684    MsMpEng.exe            2026-02-10 08:00:20        24       567      0
2104   684    svchost.exe            2026-02-10 08:00:22        4        156      0
2340   1124   WmiPrvSE.exe           2026-02-10 08:00:25        8        213      0
3216   684    dns.exe                2026-02-10 08:01:00        3        89       0
3492   636    explorer.exe           2026-02-17 09:15:33        18       892      1
3780   3492   notepad.exe            2026-02-18 11:45:12        1        45       1
4012   684    svchost.exe            2026-02-18 12:03:44        6        134      0
4188   4012   RuntimeBroker.exe      2026-02-18 12:03:47        3        112      1
5540   692    lsass.exe              2026-02-18 13:22:08        2        48       0
6312   856    WerFault.exe           2026-02-18 13:45:01        5        134      0
7204   1124   dllhost.exe            2026-02-18 14:01:33        6        187      0
7896   4012   svchost.exe            2026-02-18 14:15:22        4        98       0

===== vol3 -f memory.raw windows.pstree =====
[...extrait pertinent...]
* 684   620    services.exe
** 4012  684    svchost.exe
*** 4188 4012   RuntimeBroker.exe
** 7896  4012   svchost.exe
* 692   620    lsass.exe
** 5540  692    lsass.exe

===== vol3 -f memory.raw windows.netscan =====
Proto  LocalAddr        LocalPort  ForeignAddr      ForeignPort  State        PID    Owner
TCP    10.0.1.10        445        10.0.3.45        49832        ESTABLISHED  4      System
TCP    10.0.1.10        135        10.0.3.45        49841        ESTABLISHED  856    svchost.exe
TCP    10.0.1.10        49667      185.234.72.19    443          ESTABLISHED  5540   lsass.exe
TCP    10.0.1.10        49670      185.234.72.19    8443         ESTABLISHED  4012   svchost.exe
TCP    10.0.1.10        49671      91.234.56.78     80           CLOSE_WAIT   7896   svchost.exe
TCP    10.0.1.10        53         0.0.0.0          0            LISTENING    3216   dns.exe
UDP    10.0.1.10        53         *                *                         3216   dns.exe
TCP    10.0.1.10        88         0.0.0.0          0            LISTENING    692    lsass.exe
TCP    10.0.1.10        389        0.0.0.0          0            LISTENING    692    lsass.exe

===== vol3 -f memory.raw windows.malfind =====
PID: 5540 (lsass.exe)
  Address: 0x00000214A3B50000
  Protection: PAGE_EXECUTE_READWRITE
  Flags: COMMIT
  Hex Dump:
    4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00    MZ..............
    B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................

PID: 4012 (svchost.exe)
  Address: 0x000001F8C2100000
  Protection: PAGE_EXECUTE_READWRITE
  Flags: COMMIT
  Hex Dump:
    FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51    .H........AQAPRQ
    56 48 31 D2 65 48 8B 52 60 48 8B 52 18 48 8B 52    VH1.eH.R`H.R.H.R
    20 48 8B 72 50 48 0F B7 4A 4A 4D 31 C9 48 31 C0     H.rPH..JJM1.H1.

PID: 7896 (svchost.exe)
  Address: 0x00000230B4A00000
  Protection: PAGE_EXECUTE_READWRITE
  Flags: COMMIT
  Hex Dump:
    4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00    MZ..............
    B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......
    E8 00 00 00 00 5B 48 81 EB 05 10 40 00 48 8D 9B    .....[H....@.H..

===== vol3 -f memory.raw windows.dlllist --pid 5540 =====
PID 5540 (lsass.exe):
Base               Size       Path
0x00007FF6A1000000 0x00023000 C:\Windows\System32\lsass.exe
0x00007FFB12300000 0x001E7000 C:\Windows\System32\ntdll.dll
0x00007FFB11A00000 0x000BD000 C:\Windows\System32\kernel32.dll
0x00007FFB0F800000 0x00087000 C:\Windows\System32\ws2_32.dll
0x00000214A3B50000 0x00045000 (Inconnu - pas de chemin sur disque)

===== vol3 -f memory.raw windows.handles --pid 4012 =====
[...extrait...]
Offset             PID   Handle  Type     GrantedAccess  Name
0xFFFF928045A12080 4012  0x0044  Mutant   0x001F0001     \Sessions\1\BaseNamedObjects\PERS1ST_M0DUL3
0xFFFF928045B34090 4012  0x0088  File     0x00120089     \Device\NamedPipe\svcctl
0xFFFF928045C56100 4012  0x00CC  Key      0x000F003F     \REGISTRY\MACHINE\SOFTWARE\Microsoft\Cryptography

===== vol3 -f memory.raw windows.cmdline =====
PID 5540: lsass.exe
PID 4012: C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule
PID 7896: C:\Windows\System32\svchost.exe

===== vol3 -f memory.raw windows.registry.hivelist =====
[...standard, pas d'anomalie notable...]

===== vol3 -f memory.raw windows.svcscan =====
[...extrait suspect...]
Service: WinDefHealthCheck
  Display: Windows Defender Health Monitoring
  Binary: C:\Windows\Temp\health_check.exe
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 4012
  Type: SERVICE_WIN32_OWN_PROCESS

===== TIMELINE RÉSUMÉ =====
12:03:44 — PID 4012 (svchost.exe) créé
12:03:47 — PID 4188 (RuntimeBroker.exe) créé par PID 4012
13:22:08 — PID 5540 (lsass.exe) créé
13:22:15 — Connexion réseau PID 5540 vers 185.234.72.19:443
14:01:33 — PID 7204 (dllhost.exe) créé
14:15:22 — PID 7896 (svchost.exe) créé
14:15:30 — Connexion réseau PID 7896 vers 91.234.56.78:80
"""

CHALLENGE = {
    "id": "c13_memory_forensics",
    "title": "🧠 Le Fantôme dans la RAM",
    "category": "memory_forensics",
    "level": 4,
    "points_total": 520,
    "estimated_time": "40-60 min",
    "story": """
## Briefing de Mission

**Date :** 18 février 2026, 15h00
**Priorité :** CRITIQUE
**Source :** Équipe DFIR

---

L'équipe forensique a réalisé un dump mémoire du contrôleur de domaine **SRV-DC-01** pendant l'incident. L'analyse Volatility 3 révèle plusieurs processus suspects et des injections mémoire.

> *"On a dumpé la RAM du DC. Il y a clairement de l'injection de processus, du process hollowing, et au moins un faux lsass. Analyse le rapport Volatility et dis-moi exactement ce qui tourne dans cette machine."*

C'est de la forensique mémoire pure. Montrez que vous maîtrisez Volatility.
    """,
    "artifacts": [
        {
            "name": "volatility_report.txt",
            "type": "forensic_report",
            "content": ARTIFACT_VOLATILITY,
            "description": "Rapport Volatility 3 — Analyse mémoire SRV-DC-01"
        }
    ],
    "questions": [
        {
            "id": "q1",
            "text": "Quel PID correspond au faux processus lsass.exe (le processus injecté, pas le légitime) ?",
            "answer": "5540",
            "flag": "REDPAWN{5540}",
            "points": 40,
            "hints": [
                "Regardez la sortie pstree — il y a deux lsass.exe",
                "Le vrai lsass a le PID 692, le faux est son 'enfant'"
            ],
            "hint_cost": 13
        },
        {
            "id": "q2",
            "text": "Quelle séquence hexadécimale (5 premiers octets) identifie le shellcode Cobalt Strike/Meterpreter dans le PID 4012 ?",
            "answer": "FC 48 83 E4 F0",
            "flag": "REDPAWN{FC4883E4F0}",
            "points": 60,
            "hints": [
                "C'est le prologue classique d'un shellcode x64",
                "Regardez la sortie malfind du PID 4012"
            ],
            "hint_cost": 20
        },
        {
            "id": "q3",
            "text": "Quel type de protection mémoire est utilisé par toutes les zones injectées (acronyme Windows) ?",
            "answer": "PAGE_EXECUTE_READWRITE",
            "flag": "REDPAWN{PAGE_EXECUTE_READWRITE}",
            "points": 40,
            "hints": [
                "C'est une permission mémoire qui permet lecture + écriture + exécution",
                "En abrégé parfois RWX"
            ],
            "hint_cost": 13
        },
        {
            "id": "q4",
            "text": "Quel est le nom du mutex créé par le processus malveillant PID 4012 ?",
            "answer": "PERS1ST_M0DUL3",
            "flag": "REDPAWN{PERS1ST_M0DUL3}",
            "points": 50,
            "hints": [
                "Regardez la sortie windows.handles pour le PID 4012",
                "C'est un objet de type 'Mutant'"
            ],
            "hint_cost": 17
        },
        {
            "id": "q5",
            "text": "Par quel faux nom de service Windows le processus PID 4012 a-t-il été lancé ?",
            "answer": "WinDefHealthCheck",
            "flag": "REDPAWN{WinDefHealthCheck}",
            "points": 50,
            "hints": [
                "Regardez la sortie svcscan",
                "Il se fait passer pour un service Windows Defender"
            ],
            "hint_cost": 17
        },
        {
            "id": "q6",
            "text": "Combien de processus au total identifiez-vous comme suspects dans cette analyse mémoire ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 40,
            "hints": [
                "Cherchez les mentions '(SUSPECT)' dans la sortie pstree"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Quelle technique d'injection est utilisée sur le PID 7896 (svchost.exe) ?",
            "answer": "Reflective DLL injection",
            "flag": "REDPAWN{Reflective_DLL_injection}",
            "points": 50,
            "hints": [
                "C'est mentionné dans la sortie malfind pour ce PID",
                "C'est une technique qui charge une DLL directement en mémoire sans passer par le disque"
            ],
            "hint_cost": 17
        },
        {
            "id": "q8",
            "text": "Quel port distant utilise la connexion C2 du faux lsass (PID 5540) ?",
            "answer": "443",
            "flag": "REDPAWN{443}",
            "points": 30,
            "hints": [
                "Regardez netscan pour le PID 5540"
            ],
            "hint_cost": 10
        },
        {
            "id": "q9",
            "text": "Qu'est-ce qui prouve que le svchost.exe PID 7896 n'est PAS légitime ?",
            "answer": "-k",
            "flag": "REDPAWN{-k}",
            "points": 60,
            "hints": [
                "Les vrais svchost.exe sont toujours lancés avec un paramètre spécifique",
                "Regardez la sortie cmdline — comparez PID 4012 (qui a -k netsvcs) et PID 7896"
            ],
            "hint_cost": 20
        },
        {
            "id": "q10",
            "text": "Quel binaire est associé au faux service WinDefHealthCheck sur disque ?",
            "answer": "health_check.exe",
            "flag": "REDPAWN{health_check.exe}",
            "points": 50,
            "hints": [
                "Regardez le champ Binary dans svcscan",
                "Le chemin complet est dans C:\\Windows\\Temp\\"
            ],
            "hint_cost": 17
        },
        {
            "id": "q11",
            "text": "Les 2 premiers octets du dump mémoire du faux lsass (PID 5540) indiquent quel type de fichier injecté ?",
            "answer": "PE",
            "flag": "REDPAWN{PE}",
            "points": 50,
            "hints": [
                "4D 5A en hexadécimal = 'MZ' en ASCII",
                "MZ est la signature d'un fichier exécutable Windows (Portable Executable)"
            ],
            "hint_cost": 17
        }
    ]
}
