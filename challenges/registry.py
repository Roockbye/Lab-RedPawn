"""
Registre central de tous les challenges du lab SOC.
Chaque challenge est un dictionnaire avec :
  - id, title, category, level, points_total
  - story : le briefing / contexte narratif
  - artifacts : les artefacts générés (logs, emails, scripts…)
  - questions : liste de questions avec flag, hints, points
"""

from challenges.c01_brute_force import CHALLENGE as C01
from challenges.c02_phishing_email import CHALLENGE as C02
from challenges.c03_siem_triage import CHALLENGE as C03
from challenges.c04_webshell import CHALLENGE as C04
from challenges.c05_lateral_movement import CHALLENGE as C05
from challenges.c06_malware_script import CHALLENGE as C06
from challenges.c07_dns_exfil import CHALLENGE as C07
from challenges.c08_ransomware_ir import CHALLENGE as C08
from challenges.c09_apt_persistence import CHALLENGE as C09
from challenges.c10_full_attack_chain import CHALLENGE as C10
from challenges.c11_insider_threat import CHALLENGE as C11
from challenges.c12_supply_chain import CHALLENGE as C12
from challenges.c13_memory_forensics import CHALLENGE as C13
from challenges.c14_pcap_analysis import CHALLENGE as C14
from challenges.c15_cloud_incident import CHALLENGE as C15
from challenges.c16_malware_reverse import CHALLENGE as C16
from challenges.c17_threat_hunting import CHALLENGE as C17
from challenges.c18_final_exam import CHALLENGE as C18

ALL_CHALLENGES = [C01, C02, C03, C04, C05, C06, C07, C08, C09, C10, C11, C12,
                  C13, C14, C15, C16, C17, C18]

def get_challenge(challenge_id):
    for c in ALL_CHALLENGES:
        if c["id"] == challenge_id:
            return c
    return None

def get_challenges_by_level(level):
    return [c for c in ALL_CHALLENGES if c["level"] == level]

def get_challenges_by_category(category):
    return [c for c in ALL_CHALLENGES if c["category"] == category]
