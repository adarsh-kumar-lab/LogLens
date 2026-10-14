"""Mapping of our detection rules to the MITRE ATT&CK framework + our 6-stage attack story."""

STAGES = ["Reconnaissance", "Access attempts", "Exploitation", "Compromise", "Data theft", "Disruption"]

# rule -> (tactic, technique id, technique name, stage index or None)
RULES = {
    "WEB_SCANNER":      ("Reconnaissance",   "T1595.002", "Vulnerability Scanning", 0),
    "SSH_BRUTE_FORCE":  ("Credential Access", "T1110.001", "Password Guessing", 1),
    "WEB_LOGIN_BRUTE":  ("Credential Access", "T1110.004", "Credential Stuffing", 1),
    "WEB_SQLI":         ("Initial Access",    "T1190",     "Exploit Public-Facing Application (SQLi)", 2),
    "WEB_XSS":          ("Initial Access",    "T1190",     "Exploit Public-Facing Application (XSS)", 2),
    "WEB_TRAVERSAL":    ("Initial Access",    "T1190",     "Exploit Public-Facing Application (Path Traversal)", 2),
    "SSH_COMPROMISE":   ("Initial Access",    "T1078",     "Valid Accounts", 3),
    "OFFHOURS_LOGIN":   ("Initial Access",    "T1078",     "Valid Accounts (unusual time/source)", 3),
    "EXFIL_LARGE":      ("Collection",        "T1213",     "Data from Information Repositories", 4),
    "WEB_FLOOD":        ("Impact",            "T1499.002", "Service Exhaustion Flood", 5),
    "TRAFFIC_SPIKE":    ("Impact",            "T1498",     "Network Denial of Service", 5),
    "AUTH_FAIL_SPIKE":  ("Credential Access", "T1110",     "Brute Force", 1),
    "ML_IP_ANOMALY":    ("Anomaly",           "-",         "Behavioural outlier (Isolation Forest)", None),
}

NEXT_MOVE = {
    0: "Probing is the first step. Expect password guessing or exploit attempts against anything it found.",
    1: "If one password is guessed, the next event will be a successful login followed by data access.",
    2: "Watch for web shells, new admin accounts and unusual outbound traffic. The attacker is testing for a way in.",
    3: "Attacker has valid access. Expect data staging and download next. Kill sessions and reset passwords now.",
    4: "Data has probably already left the network. Contain the host and start incident response.",
    5: "Service degradation continues while the flood lasts. Rate-limit or block upstream (WAF / CDN).",
}

ACTIONS = {
    0: "Block or rate-limit the scanning IP; remove exposed files (.git, .env, backups).",
    1: "Disable SSH password login (use keys), enable fail2ban, add MFA to login pages.",
    2: "Use parameterised queries, enable a WAF rule-set (OWASP CRS), validate and encode all input.",
    3: "Force-logout the account, rotate its password/keys, review ~/.ssh/authorized_keys and sudo history.",
    4: "Identify exactly what was downloaded, notify the data owner, check whether it has to be reported.",
    5: "Turn on connection / request rate limits and put the site behind a CDN or WAF.",
}
