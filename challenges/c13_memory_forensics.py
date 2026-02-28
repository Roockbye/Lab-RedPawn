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

===== vol3 -f memory.raw windows.info =====
Variable                    Value
Kernel Base                 0xf80062a00000
DTB                         0x1aa000
Symbols                     ntkrnlmp.pdb
Is64Bit                     True
IsPAE                       False
Primary Layer               Intel
KdDebuggerDataBlock         0xf80062e0a0a0
NTBuildNumber               18363
NTBuildLab                  18363.1.amd64fre.19h1_release
CSDVersion                  0
KdVersionBlock              0xf80062e0a0b8
Major / Minor               15.18363

===== vol3 -f memory.raw windows.pslist =====
PID    PPID   ImageFileName          CreateTime                 Threads  Handles  SessionId
4      0      System                 2026-02-10 08:00:01        168      -        -
104    4      Registry               2026-02-10 08:00:01        4        -        -
340    4      MemCompression         2026-02-10 08:00:03        48       -        -
440    4      smss.exe               2026-02-10 08:00:05        2        30       -
556    548    csrss.exe              2026-02-10 08:00:07        10       543      0
564    548    csrss.exe              2026-02-10 08:00:07        11       510      2
620    548    wininit.exe            2026-02-10 08:00:08        1        78       0
636    612    csrss.exe              2026-02-10 08:00:08        12       289      1
668    612    winlogon.exe           2026-02-10 08:00:08        4        123      1
684    620    services.exe           2026-02-10 08:00:09        6        243      0
692    620    lsass.exe              2026-02-10 08:00:09        8        792      0
744    684    svchost.exe            2026-02-10 08:00:09        7        198      0
788    684    svchost.exe            2026-02-10 08:00:10        12       387      0
832    684    svchost.exe            2026-02-10 08:00:10        9        312      0
856    684    svchost.exe            2026-02-10 08:00:10        8        267      0
916    684    svchost.exe            2026-02-10 08:00:11        5        187      0
968    684    svchost.exe            2026-02-10 08:00:11        14       423      0
1024   684    svchost.exe            2026-02-10 08:00:12        6        198      0
1080   684    svchost.exe            2026-02-10 08:00:12        8        256      0
1124   684    svchost.exe            2026-02-10 08:00:12        15       412      0
1200   684    svchost.exe            2026-02-10 08:00:13        4        167      0
1268   684    svchost.exe            2026-02-10 08:00:13        7        234      0
1340   684    svchost.exe            2026-02-10 08:00:14        5        189      0
1456   684    spoolsv.exe            2026-02-10 08:00:15        7        189      0
1524   684    svchost.exe            2026-02-10 08:00:16        3        123      0
1608   684    VGAuthService.exe      2026-02-10 08:00:17        2        67       0
1644   684    vmtoolsd.exe           2026-02-10 08:00:18        8        234      0
1700   684    svchost.exe            2026-02-10 08:00:18        4        145      0
1756   684    MsMpEng.exe            2026-02-10 08:00:19        28       612      0
1892   684    MsMpEng.exe            2026-02-10 08:00:20        24       567      0
1948   684    msdtc.exe              2026-02-10 08:00:20        9        178      0
2032   684    svchost.exe            2026-02-10 08:00:21        5        156      0
2104   684    svchost.exe            2026-02-10 08:00:22        4        156      0
2200   684    svchost.exe            2026-02-10 08:00:23        6        201      0
2284   684    NisSrv.exe             2026-02-10 08:00:24        5        134      0
2340   1124   WmiPrvSE.exe           2026-02-10 08:00:25        8        213      0
2420   684    dfsrs.exe              2026-02-10 08:00:26        14       367      0
2488   684    dfssvc.exe             2026-02-10 08:00:26        3        89       0
2560   684    ismserv.exe            2026-02-10 08:00:27        4        112      0
2680   684    Microsoft.ActiveDirec  2026-02-10 08:00:28        7        234      0
2800   684    svchost.exe            2026-02-10 08:00:29        3        98       0
2912   684    ntfrs.exe              2026-02-10 08:00:30        8        267      0
3008   1124   WmiPrvSE.exe           2026-02-10 08:00:31        6        178      0
3100   684    svchost.exe            2026-02-10 08:00:32        4        134      0
3216   684    dns.exe                2026-02-10 08:01:00        3        89       0
3300   684    svchost.exe            2026-02-10 08:01:01        5        156      0
3388   684    svchost.exe            2026-02-10 08:01:02        3        112      0
3492   636    explorer.exe           2026-02-17 09:15:33        18       892      1
3612   3492   SearchUI.exe           2026-02-17 09:15:40        8        345      1
3700   3492   RuntimeBroker.exe      2026-02-17 09:15:42        3        112      1
3780   3492   notepad.exe            2026-02-18 11:45:12        1        45       1
3856   684    svchost.exe            2026-02-18 11:50:00        4        134      0
3934   3492   taskhostw.exe          2026-02-18 12:00:15        3        98       1
4012   684    svchost.exe            2026-02-18 12:03:44        6        134      0
4100   684    svchost.exe            2026-02-18 12:03:45        3        89       0
4188   4012   RuntimeBroker.exe      2026-02-18 12:03:47        3        112      1
4300   684    SearchIndexer.exe      2026-02-18 12:10:00        12       456      0
4412   1124   WmiPrvSE.exe           2026-02-18 12:15:22        4        134      0
4520   684    svchost.exe            2026-02-18 12:30:00        3        98       0
4640   684    TiWorker.exe           2026-02-18 12:45:11        5        167      0
4780   3492   ServerManager.exe      2026-02-18 12:50:00        6        234      1
4900   684    svchost.exe            2026-02-18 13:00:00        4        123      0
5012   684    svchost.exe            2026-02-18 13:05:00        3        89       0
5120   684    MpCmdRun.exe           2026-02-18 13:10:15        2        67       0
5244   1124   unsecapp.exe           2026-02-18 13:15:00        3        78       0
5360   684    svchost.exe            2026-02-18 13:20:00        4        112      0
5540   692    lsass.exe              2026-02-18 13:22:08        2        48       0
5660   684    svchost.exe            2026-02-18 13:30:00        3        98       0
5780   3492   mmc.exe                2026-02-18 13:35:22        5        234      1
5900   684    svchost.exe            2026-02-18 13:40:00        4        134      0
6012   1124   WmiPrvSE.exe           2026-02-18 13:42:00        6        178      0
6120   684    svchost.exe            2026-02-18 13:43:00        3        89       0
6312   856    WerFault.exe           2026-02-18 13:45:01        5        134      0
6440   684    svchost.exe            2026-02-18 13:50:00        3        98       0
6560   3492   dsa.msc                2026-02-18 13:52:00        4        156      1
6700   684    svchost.exe            2026-02-18 13:55:00        3        89       0
6812   684    svchost.exe            2026-02-18 13:58:00        4        112      0
6934   684    svchost.exe            2026-02-18 14:00:00        3        98       0
7060   684    svchost.exe            2026-02-18 14:00:30        4        123      0
7204   1124   dllhost.exe            2026-02-18 14:01:33        6        187      0
7340   684    svchost.exe            2026-02-18 14:05:00        3        89       0
7500   684    svchost.exe            2026-02-18 14:10:00        4        112      0
7620   684    svchost.exe            2026-02-18 14:12:00        3        98       0
7740   3492   eventvwr.exe           2026-02-18 14:13:00        5        189      1
7896   4012   svchost.exe            2026-02-18 14:15:22        4        98       0
8020   684    svchost.exe            2026-02-18 14:20:00        3        89       0
8140   684    svchost.exe            2026-02-18 14:25:00        4        134      0

===== vol3 -f memory.raw windows.pstree =====
0      PID: 4     System
. 104  PID: 104   Registry
. 340  PID: 340   MemCompression
. 440  PID: 440   smss.exe
0      PID: 556   csrss.exe
0      PID: 564   csrss.exe
0      PID: 620   wininit.exe
. 684  PID: 684   services.exe
.. 744  PID: 744   svchost.exe
.. 788  PID: 788   svchost.exe
.. 832  PID: 832   svchost.exe
.. 856  PID: 856   svchost.exe
... 6312 PID: 6312 WerFault.exe
.. 916  PID: 916   svchost.exe
.. 968  PID: 968   svchost.exe
.. 1024 PID: 1024  svchost.exe
.. 1080 PID: 1080  svchost.exe
.. 1124 PID: 1124  svchost.exe
... 2340 PID: 2340 WmiPrvSE.exe
... 3008 PID: 3008 WmiPrvSE.exe
... 4412 PID: 4412 WmiPrvSE.exe
... 5244 PID: 5244 unsecapp.exe
... 6012 PID: 6012 WmiPrvSE.exe
... 7204 PID: 7204 dllhost.exe
.. 1200 PID: 1200  svchost.exe
.. 1268 PID: 1268  svchost.exe
.. 1340 PID: 1340  svchost.exe
.. 1456 PID: 1456  spoolsv.exe
.. 1524 PID: 1524  svchost.exe
.. 1608 PID: 1608  VGAuthService.exe
.. 1644 PID: 1644  vmtoolsd.exe
.. 1700 PID: 1700  svchost.exe
.. 1756 PID: 1756  MsMpEng.exe
.. 1892 PID: 1892  MsMpEng.exe
.. 1948 PID: 1948  msdtc.exe
.. 2032 PID: 2032  svchost.exe
.. 2104 PID: 2104  svchost.exe
.. 2200 PID: 2200  svchost.exe
.. 2284 PID: 2284  NisSrv.exe
.. 2420 PID: 2420  dfsrs.exe
.. 2488 PID: 2488  dfssvc.exe
.. 2560 PID: 2560  ismserv.exe
.. 2680 PID: 2680  Microsoft.ActiveDirec
.. 2800 PID: 2800  svchost.exe
.. 2912 PID: 2912  ntfrs.exe
.. 3100 PID: 3100  svchost.exe
.. 3216 PID: 3216  dns.exe
.. 3300 PID: 3300  svchost.exe
.. 3388 PID: 3388  svchost.exe
.. 3856 PID: 3856  svchost.exe
.. 4012 PID: 4012  svchost.exe              <<<< SUSPECT: service faux WinDefHealthCheck
... 4188 PID: 4188 RuntimeBroker.exe
... 7896 PID: 7896 svchost.exe              <<<< SUSPECT: enfant illégitime de 4012
.. 4100 PID: 4100  svchost.exe
.. 4300 PID: 4300  SearchIndexer.exe
.. 4520 PID: 4520  svchost.exe
.. 4640 PID: 4640  TiWorker.exe
.. 4900 PID: 4900  svchost.exe
.. 5012 PID: 5012  svchost.exe
.. 5120 PID: 5120  MpCmdRun.exe
.. 5360 PID: 5360  svchost.exe
.. 5660 PID: 5660  svchost.exe
.. 5900 PID: 5900  svchost.exe
.. 6120 PID: 6120  svchost.exe
.. 6440 PID: 6440  svchost.exe
.. 6700 PID: 6700  svchost.exe
.. 6812 PID: 6812  svchost.exe
.. 6934 PID: 6934  svchost.exe
.. 7060 PID: 7060  svchost.exe
.. 7340 PID: 7340  svchost.exe
.. 7500 PID: 7500  svchost.exe
.. 7620 PID: 7620  svchost.exe
.. 8020 PID: 8020  svchost.exe
.. 8140 PID: 8140  svchost.exe
. 692  PID: 692   lsass.exe
.. 5540 PID: 5540  lsass.exe                <<<< SUSPECT: duplicata illégitime de lsass
0      PID: 636   csrss.exe
0      PID: 668   winlogon.exe
. 3492 PID: 3492  explorer.exe
.. 3612 PID: 3612 SearchUI.exe
.. 3700 PID: 3700 RuntimeBroker.exe
.. 3780 PID: 3780 notepad.exe
.. 3934 PID: 3934 taskhostw.exe
.. 4780 PID: 4780 ServerManager.exe
.. 5780 PID: 5780 mmc.exe
.. 6560 PID: 6560 dsa.msc
.. 7740 PID: 7740 eventvwr.exe

===== vol3 -f memory.raw windows.netscan =====
Proto  LocalAddr        LocalPort  ForeignAddr      ForeignPort  State        PID    Owner
TCP    10.0.1.10        445        10.0.2.20        49800        ESTABLISHED  4      System
TCP    10.0.1.10        445        10.0.2.21        49810        ESTABLISHED  4      System
TCP    10.0.1.10        445        10.0.2.22        49820        ESTABLISHED  4      System
TCP    10.0.1.10        445        10.0.3.45        49832        ESTABLISHED  4      System
TCP    10.0.1.10        445        10.0.3.10        49840        ESTABLISHED  4      System
TCP    10.0.1.10        135        10.0.2.20        49835        ESTABLISHED  856    svchost.exe
TCP    10.0.1.10        135        10.0.3.45        49841        ESTABLISHED  856    svchost.exe
TCP    10.0.1.10        135        10.0.3.10        49845        ESTABLISHED  856    svchost.exe
TCP    10.0.1.10        389        10.0.2.20        49850        ESTABLISHED  692    lsass.exe
TCP    10.0.1.10        389        10.0.2.21        49855        ESTABLISHED  692    lsass.exe
TCP    10.0.1.10        389        10.0.2.22        49860        ESTABLISHED  692    lsass.exe
TCP    10.0.1.10        389        10.0.3.10        49865        ESTABLISHED  692    lsass.exe
TCP    10.0.1.10        389        10.0.3.45        49870        ESTABLISHED  692    lsass.exe
TCP    10.0.1.10        88         10.0.2.20        49880        ESTABLISHED  692    lsass.exe
TCP    10.0.1.10        88         10.0.2.21        49885        ESTABLISHED  692    lsass.exe
TCP    10.0.1.10        88         10.0.3.45        49890        ESTABLISHED  692    lsass.exe
TCP    10.0.1.10        636        10.0.2.20        49895        ESTABLISHED  692    lsass.exe
TCP    10.0.1.10        3268       10.0.2.22        49900        ESTABLISHED  692    lsass.exe
TCP    10.0.1.10        49667      185.234.72.19    443          ESTABLISHED  5540   lsass.exe
TCP    10.0.1.10        49670      185.234.72.19    8443         ESTABLISHED  4012   svchost.exe
TCP    10.0.1.10        49671      91.234.56.78     80           CLOSE_WAIT   7896   svchost.exe
TCP    10.0.1.10        53         0.0.0.0          0            LISTENING    3216   dns.exe
TCP    10.0.1.10        88         0.0.0.0          0            LISTENING    692    lsass.exe
TCP    10.0.1.10        135        0.0.0.0          0            LISTENING    856    svchost.exe
TCP    10.0.1.10        389        0.0.0.0          0            LISTENING    692    lsass.exe
TCP    10.0.1.10        445        0.0.0.0          0            LISTENING    4      System
TCP    10.0.1.10        636        0.0.0.0          0            LISTENING    692    lsass.exe
TCP    10.0.1.10        3268       0.0.0.0          0            LISTENING    692    lsass.exe
TCP    10.0.1.10        3269       0.0.0.0          0            LISTENING    692    lsass.exe
TCP    10.0.1.10        5985       0.0.0.0          0            LISTENING    4      System
TCP    10.0.1.10        5986       0.0.0.0          0            LISTENING    4      System
TCP    10.0.1.10        9389       0.0.0.0          0            LISTENING    2680   Microsoft.ActiveDirec
TCP    10.0.1.10        49152      0.0.0.0          0            LISTENING    668    winlogon.exe
TCP    10.0.1.10        49153      0.0.0.0          0            LISTENING    684    services.exe
TCP    10.0.1.10        49154      0.0.0.0          0            LISTENING    692    lsass.exe
TCP    10.0.1.10        49155      0.0.0.0          0            LISTENING    692    lsass.exe
UDP    10.0.1.10        53         *                *                         3216   dns.exe
UDP    10.0.1.10        88         *                *                         692    lsass.exe
UDP    10.0.1.10        123        *                *                         968    svchost.exe
UDP    10.0.1.10        389        *                *                         692    lsass.exe
UDP    10.0.1.10        464        *                *                         692    lsass.exe
UDP    10.0.1.10        500        *                *                         692    lsass.exe
UDP    10.0.1.10        4500       *                *                         692    lsass.exe
UDP    10.0.1.10        5353       *                *                         1268   svchost.exe
UDP    10.0.1.10        5355       *                *                         1268   svchost.exe

===== vol3 -f memory.raw windows.malfind =====
PID: 5540 (lsass.exe)
  Address: 0x00000214A3B50000
  Protection: PAGE_EXECUTE_READWRITE
  Flags: COMMIT
  Tag: VadS
  Hex Dump:
    4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00    MZ..............
    B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......
    00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00    ................

PID: 4012 (svchost.exe)
  Address: 0x000001F8C2100000
  Protection: PAGE_EXECUTE_READWRITE
  Flags: COMMIT
  Tag: VadS
  Hex Dump:
    FC 48 83 E4 F0 E8 C0 00 00 00 41 51 41 50 52 51    .H........AQAPRQ
    56 48 31 D2 65 48 8B 52 60 48 8B 52 18 48 8B 52    VH1.eH.R`H.R.H.R
    20 48 8B 72 50 48 0F B7 4A 4A 4D 31 C9 48 31 C0     H.rPH..JJM1.H1.

PID: 7896 (svchost.exe)
  Address: 0x00000230B4A00000
  Protection: PAGE_EXECUTE_READWRITE
  Flags: COMMIT
  Tag: VadS
  Hex Dump:
    4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00    MZ..............
    B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00    ........@.......
    E8 00 00 00 00 5B 48 81 EB 05 10 40 00 48 8D 9B    .....[H....@.H..

===== vol3 -f memory.raw windows.vadinfo --pid 5540 =====
[...extrait pertinent...]
VAD Address:  0x00000214A3B50000
  Start:      0x00000214A3B50000
  End:        0x00000214A3B94FFF
  Tag:        VadS
  Protection: PAGE_EXECUTE_READWRITE
  PrivateMemory: 1
  CommitCharge: 69 pages (282624 bytes)
  VadType:    VadNone

VAD Address:  0x00000214A4000000
  Start:      0x00000214A4000000
  End:        0x00000214A404FFFF
  Tag:        Vad
  Protection: PAGE_READWRITE
  PrivateMemory: 0
  CommitCharge: 80 pages (327680 bytes)
  FileObject: \Device\HarddiskVolume2\Windows\System32\lsass.exe

===== vol3 -f memory.raw windows.dlllist --pid 5540 =====
PID 5540 (lsass.exe):
Base               Size       Path
0x00007FF6A1000000 0x00023000 C:\Windows\System32\lsass.exe
0x00007FFB12300000 0x001E7000 C:\Windows\System32\ntdll.dll
0x00007FFB11A00000 0x000BD000 C:\Windows\System32\kernel32.dll
0x00007FFB10E00000 0x0007C000 C:\Windows\System32\KERNELBASE.dll
0x00007FFB0FA00000 0x000A3000 C:\Windows\System32\ADVAPI32.dll
0x00007FFB0F800000 0x00087000 C:\Windows\System32\ws2_32.dll
0x00007FFB0F600000 0x00052000 C:\Windows\System32\RPCRT4.dll
0x00007FFB0F400000 0x00034000 C:\Windows\System32\SspiCli.dll
0x00007FFB0F200000 0x00028000 C:\Windows\System32\CRYPT32.dll
0x00007FFB0F000000 0x0001E000 C:\Windows\System32\bcrypt.dll
0x00007FFB0EE00000 0x00047000 C:\Windows\System32\sechost.dll
0x00000214A3B50000 0x00045000 (Inconnu - pas de chemin sur disque)

===== vol3 -f memory.raw windows.dlllist --pid 4012 =====
PID 4012 (svchost.exe):
Base               Size       Path
0x00007FF7E2A00000 0x00014000 C:\Windows\System32\svchost.exe
0x00007FFB12300000 0x001E7000 C:\Windows\System32\ntdll.dll
0x00007FFB11A00000 0x000BD000 C:\Windows\System32\kernel32.dll
0x00007FFB10E00000 0x0007C000 C:\Windows\System32\KERNELBASE.dll
0x00007FFB0FA00000 0x000A3000 C:\Windows\System32\ADVAPI32.dll
0x00007FFB0F800000 0x00087000 C:\Windows\System32\ws2_32.dll
0x00007FFB0F600000 0x00052000 C:\Windows\System32\RPCRT4.dll
0x00007FFB0F400000 0x00034000 C:\Windows\System32\SspiCli.dll
0x00007FFB0F200000 0x00028000 C:\Windows\System32\CRYPT32.dll
0x00007FFB0EE00000 0x00047000 C:\Windows\System32\sechost.dll
0x00007FFB0E400000 0x00089000 C:\Windows\System32\schedsvc.dll

===== vol3 -f memory.raw windows.dlllist --pid 7896 =====
PID 7896 (svchost.exe):
Base               Size       Path
0x00007FF7E2A00000 0x00014000 C:\Windows\System32\svchost.exe
0x00007FFB12300000 0x001E7000 C:\Windows\System32\ntdll.dll
0x00007FFB11A00000 0x000BD000 C:\Windows\System32\kernel32.dll
0x00007FFB10E00000 0x0007C000 C:\Windows\System32\KERNELBASE.dll
0x00007FFB0F800000 0x00087000 C:\Windows\System32\ws2_32.dll
0x00007FFB0F600000 0x00052000 C:\Windows\System32\RPCRT4.dll
0x00007FFB0EE00000 0x00047000 C:\Windows\System32\sechost.dll
0x00000230B4A00000 0x00078000 (Inconnu - pas de chemin sur disque)

===== vol3 -f memory.raw windows.handles --pid 4012 =====
Offset             PID   Handle  Type     GrantedAccess  Name
0xFFFF928045A12080 4012  0x0004  Event    0x001F0003     \KernelObjects\LowMemoryCondition
0xFFFF928045A23090 4012  0x0008  Event    0x001F0003     \KernelObjects\HighMemoryCondition
0xFFFF928045A34100 4012  0x000C  Directory 0x0003        \KnownDlls
0xFFFF928045A45110 4012  0x0010  Key      0x000F003F     \REGISTRY\MACHINE\SYSTEM\CurrentControlSet\Services\Schedule
0xFFFF928045A56120 4012  0x0014  File     0x00120089     \Device\HarddiskVolume2\Windows\System32\Tasks
0xFFFF928045A67130 4012  0x0018  Section  0x000F001F     \Sessions\1\Windows\SharedSection
0xFFFF928045A78140 4012  0x001C  Event    0x001F0003     \BaseNamedObjects\SchedServiceEvent
0xFFFF928045A89150 4012  0x0020  Thread   0x001FFFFF     (unnamed)
0xFFFF928045A9A160 4012  0x0024  Token    0x000F01FF     (unnamed)
0xFFFF928045AAB170 4012  0x0028  File     0x00120089     \Device\NamedPipe\epmapper
0xFFFF928045ABC180 4012  0x002C  Key      0x000F003F     \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion
0xFFFF928045ACD190 4012  0x0030  Mutant   0x001F0001     \BaseNamedObjects\SchedServiceMutex
0xFFFF928045ADE1A0 4012  0x0034  Event    0x001F0003     \BaseNamedObjects\TaskSchedulerReady
0xFFFF928045AEF1B0 4012  0x0038  File     0x00120089     \Device\Afd\Endpoint
0xFFFF928045B001C0 4012  0x003C  Key      0x000F003F     \REGISTRY\MACHINE\SOFTWARE\Microsoft\Cryptography\Defaults
0xFFFF928045B111D0 4012  0x0040  Section  0x000F001F     \BaseNamedObjects\windows_shell_global_counters
0xFFFF928045B221E0 4012  0x0044  Mutant   0x001F0001     \Sessions\1\BaseNamedObjects\PERS1ST_M0DUL3
0xFFFF928045B331F0 4012  0x0048  File     0x00100080     \Device\HarddiskVolume2\Windows\Temp\health_check.exe
0xFFFF928045B34090 4012  0x0088  File     0x00120089     \Device\NamedPipe\svcctl
0xFFFF928045C56100 4012  0x00CC  Key      0x000F003F     \REGISTRY\MACHINE\SOFTWARE\Microsoft\Cryptography
0xFFFF928045C67110 4012  0x00D0  Key      0x000F003F     \REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run

===== vol3 -f memory.raw windows.handles --pid 5540 =====
Offset             PID   Handle  Type     GrantedAccess  Name
0xFFFF928046A12080 5540  0x0004  Event    0x001F0003     (unnamed)
0xFFFF928046A23090 5540  0x0008  Token    0x000F01FF     (unnamed)
0xFFFF928046A34100 5540  0x000C  Thread   0x001FFFFF     (unnamed)
0xFFFF928046A45110 5540  0x0010  Process  0x001FFFFF     lsass.exe (PID 692)
0xFFFF928046A56120 5540  0x0014  File     0x00120089     \Device\Afd\Endpoint
0xFFFF928046A67130 5540  0x0018  Key      0x000F003F     \REGISTRY\MACHINE\SAM
0xFFFF928046A78140 5540  0x001C  Key      0x000F003F     \REGISTRY\MACHINE\SECURITY
0xFFFF928046A89150 5540  0x0020  Section  0x000F001F     \BaseNamedObjects\SamSs

===== vol3 -f memory.raw windows.cmdline =====
PID    Process            CommandLine
4      System             (none)
104    Registry           (none)
340    MemCompression     (none)
440    smss.exe           \SystemRoot\System32\smss.exe
556    csrss.exe          %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
620    wininit.exe        wininit.exe
668    winlogon.exe       winlogon.exe
684    services.exe       C:\Windows\System32\services.exe
692    lsass.exe          C:\Windows\System32\lsass.exe
744    svchost.exe        C:\Windows\System32\svchost.exe -k DcomLaunch -p
788    svchost.exe        C:\Windows\System32\svchost.exe -k RPCSS -p
832    svchost.exe        C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p
856    svchost.exe        C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted -p -s NcbService
916    svchost.exe        C:\Windows\System32\svchost.exe -k LocalServiceNoNetwork -p
968    svchost.exe        C:\Windows\System32\svchost.exe -k netsvcs -p -s W32Time
1024   svchost.exe        C:\Windows\System32\svchost.exe -k LocalService -p
1080   svchost.exe        C:\Windows\System32\svchost.exe -k NetworkService -p
1124   svchost.exe        C:\Windows\System32\svchost.exe -k DcomLaunch -p -s LSM
1200   svchost.exe        C:\Windows\System32\svchost.exe -k netsvcs -p -s ProfSvc
1268   svchost.exe        C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp
1340   svchost.exe        C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog
1456   spoolsv.exe        C:\Windows\System32\spoolsv.exe
1608   VGAuthService.exe  "C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe"
1644   vmtoolsd.exe       "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
1756   MsMpEng.exe        "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2302.7-0\MsMpEng.exe"
1892   MsMpEng.exe        "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2302.7-0\MsMpEng.exe"
2284   NisSrv.exe         "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2302.7-0\NisSrv.exe"
2420   dfsrs.exe          C:\Windows\System32\dfsrs.exe
3216   dns.exe            C:\Windows\System32\dns.exe
3492   explorer.exe       C:\Windows\explorer.exe
4012   svchost.exe        C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule
5120   MpCmdRun.exe       "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2302.7-0\MpCmdRun.exe" -Scan -ScanType 1
5540   lsass.exe          C:\Windows\System32\lsass.exe
7896   svchost.exe        C:\Windows\System32\svchost.exe

===== vol3 -f memory.raw windows.registry.hivelist =====
Offset              FileFullPath
0xffffe00000027000  \SystemRoot\System32\Config\SAM
0xffffe00000042000  \SystemRoot\System32\Config\SECURITY
0xffffe00000058000  \SystemRoot\System32\Config\SOFTWARE
0xffffe0000006e000  \SystemRoot\System32\Config\SYSTEM
0xffffe00000084000  \SystemRoot\System32\Config\DEFAULT
0xffffe0000009a000  \??\C:\Users\Administrator\ntuser.dat
0xffffe000000b0000  \??\C:\Users\Administrator\AppData\Local\Microsoft\Windows\UsrClass.dat
0xffffe000000c6000  \SystemRoot\System32\Config\BBI
0xffffe000000dc000  \SystemRoot\System32\Config\DRIVERS
0xffffe000000f2000  \??\C:\Windows\ServiceProfiles\LocalService\ntuser.dat
0xffffe00000108000  \??\C:\Windows\ServiceProfiles\NetworkService\ntuser.dat

===== vol3 -f memory.raw windows.svcscan =====
[...liste partielle — services pertinents...]
Service: Schedule
  Display: Task Scheduler
  Binary: C:\Windows\System32\svchost.exe -k netsvcs -p -s Schedule
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 4012
  Type: SERVICE_WIN32_OWN_PROCESS

Service: WinDefHealthCheck
  Display: Windows Defender Health Monitoring
  Binary: C:\Windows\Temp\health_check.exe
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 4012
  Type: SERVICE_WIN32_OWN_PROCESS

Service: Dnscache
  Display: DNS Client
  Binary: C:\Windows\System32\svchost.exe -k NetworkService -p -s Dnscache
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 1080
  Type: SERVICE_WIN32_SHARE_PROCESS

Service: W32Time
  Display: Windows Time
  Binary: C:\Windows\System32\svchost.exe -k netsvcs -p -s W32Time
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 968
  Type: SERVICE_WIN32_SHARE_PROCESS

Service: Dhcp
  Display: DHCP Client
  Binary: C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s Dhcp
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 1268
  Type: SERVICE_WIN32_SHARE_PROCESS

Service: EventLog
  Display: Windows Event Log
  Binary: C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p -s EventLog
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 1340
  Type: SERVICE_WIN32_SHARE_PROCESS

Service: Spooler
  Display: Print Spooler
  Binary: C:\Windows\System32\spoolsv.exe
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 1456
  Type: SERVICE_WIN32_OWN_PROCESS

Service: DFSR
  Display: DFS Replication
  Binary: C:\Windows\System32\dfsrs.exe
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 2420
  Type: SERVICE_WIN32_OWN_PROCESS

Service: DNS
  Display: DNS Server
  Binary: C:\Windows\System32\dns.exe
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 3216
  Type: SERVICE_WIN32_OWN_PROCESS

Service: NTDS
  Display: Active Directory Domain Services
  Binary: C:\Windows\System32\lsass.exe
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 692
  Type: SERVICE_WIN32_SHARE_PROCESS

Service: WinDefend
  Display: Microsoft Defender Antivirus Service
  Binary: "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2302.7-0\MsMpEng.exe"
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 1756
  Type: SERVICE_WIN32_OWN_PROCESS

Service: vmtools
  Display: VMware Tools
  Binary: "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe"
  State: SERVICE_RUNNING
  Start: SERVICE_AUTO_START
  PID: 1644
  Type: SERVICE_WIN32_OWN_PROCESS

===== vol3 -f memory.raw windows.registry.printkey --key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" =====
Key: Software\Microsoft\Windows\CurrentVersion\Run
  Last Write Time: 2026-02-18 12:04:01
  Val Name             Type       Data
  SecurityHealth       REG_EXPAND_SZ  %ProgramFiles%\Windows Defender\MSASCuiL.exe
  VMware User Process  REG_SZ     "C:\Program Files\VMware\VMware Tools\vmtoolsd.exe" -n vmusr

===== TIMELINE RÉSUMÉ =====
12:03:44 — PID 4012 (svchost.exe) créé — service WinDefHealthCheck (FAUX SERVICE)
12:03:47 — PID 4188 (RuntimeBroker.exe) créé par PID 4012
13:22:08 — PID 5540 (lsass.exe) créé — FAUX LSASS (parent: PID 692 lsass légitime)
13:22:15 — Connexion réseau PID 5540 vers 185.234.72.19:443 (C2)
14:01:33 — PID 7204 (dllhost.exe) créé
14:15:22 — PID 7896 (svchost.exe) créé par PID 4012 — SANS paramètre -k
14:15:30 — Connexion réseau PID 7896 vers 91.234.56.78:80 (staging server)
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
            "text": "Combien de processus au total identifiez-vous comme suspects/malveillants dans cette analyse mémoire ?",
            "answer": "3",
            "flag": "REDPAWN{3}",
            "points": 40,
            "hints": [
                "Comptez les processus signalés comme suspects dans le pstree",
                "Ce sont les processus avec des connexions externes anormales et/ou des injections mémoire"
            ],
            "hint_cost": 13
        },
        {
            "id": "q7",
            "text": "Quelle technique d'injection est utilisée sur le PID 7896 (svchost.exe) ? (indice : la DLL est chargée sans toucher le disque)",
            "answer": "Reflective DLL injection",
            "flag": "REDPAWN{Reflective_DLL_injection}",
            "points": 50,
            "hints": [
                "Dans windows.dlllist pour PID 7896, une DLL n'a pas de chemin sur disque",
                "Combiné avec le dump mémoire MZ dans malfind — c'est une DLL chargée en mémoire pure"
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
