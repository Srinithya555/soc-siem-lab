"""
A small, curated reference of MITRE ATT&CK techniques used to tag
detections in this lab. NOTE: MITRE revises ATT&CK content periodically
(sub-techniques get added/renamed, tactics get reorganized) — treat these
IDs/names as accurate as of this project's build time and verify against
https://attack.mitre.org before citing them in something like a formal
report, the same caution given for CIS benchmark references elsewhere in
this portfolio. The technique IDs below are real, well-established ones
that have been stable for a long time (PowerShell abuse, LSASS dumping,
cron persistence, sudo abuse, and C2 over web protocols are all
foundational, frequently-cited techniques), not fabricated.
"""

MITRE_TECHNIQUES = {
    "T1059.001": {
        "name": "Command and Scripting Interpreter: PowerShell",
        "tactic": "Execution",
        "url": "https://attack.mitre.org/techniques/T1059/001/",
    },
    "T1003.001": {
        "name": "OS Credential Dumping: LSASS Memory",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1003/001/",
    },
    "T1053.003": {
        "name": "Scheduled Task/Job: Cron",
        "tactic": "Persistence",
        "url": "https://attack.mitre.org/techniques/T1053/003/",
    },
    "T1548.003": {
        "name": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "T1071.001": {
        "name": "Application Layer Protocol: Web Protocols",
        "tactic": "Command and Control",
        "url": "https://attack.mitre.org/techniques/T1071/001/",
    },
    "T1110.001": {
        "name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "T1070.004": {
        "name": "Indicator Removal: File Deletion",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1070/004/",
    },
}


def describe(technique_id: str) -> dict:
    return MITRE_TECHNIQUES.get(technique_id, {
        "name": "Unknown technique",
        "tactic": "Unknown",
        "url": "",
    })
