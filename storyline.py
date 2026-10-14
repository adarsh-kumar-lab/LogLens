"""UNIQUE FEATURE: Attack Storyline Reconstruction.

Normal IDS dashboards show a flat list of alerts: "SSH brute force", "404 flood", "big download"...
A student (or a tired analyst) has to work out in their head that these 4 alerts are ONE attacker.

This module does that automatically:
  1. groups every alert by attacker IP,
  2. orders them in time and places them on a 6-stage kill chain
        Reconnaissance -> Access attempts -> Exploitation -> Compromise -> Data theft -> Disruption
  3. writes the story in plain English (who, what, when, how long between steps),
  4. decides a verdict (did the attack SUCCEED or was it only an ATTEMPT?),
  5. predicts the attacker's most likely NEXT move and lists what to do,
  6. creates ready-to-run firewall commands.
"""
from collections import defaultdict
from .mitre import STAGES, NEXT_MOVE, ACTIONS

SEV_W = {"critical": 30, "high": 20, "medium": 10, "low": 4}


def _dur(sec):
    sec = int(sec)
    if sec < 90:
        return f"{sec}s"
    if sec < 5400:
        return f"{round(sec / 60)} min"
    return f"{sec / 3600:.1f} h"


def build_incidents(alerts, ip_table, events):
    by_ip = defaultdict(list)
    for a in alerts:
        if a["ip"]:
            by_ip[a["ip"]].append(a)
    ml = {r["ip"]: r for r in ip_table}
    ev_stats = defaultdict(lambda: {"events": 0, "web": 0, "ssh": 0, "bytes": 0})
    for e in events:
        s = ev_stats[e["ip"]]
        s["events"] += 1
        s["web" if e["source"] == "web" else "ssh"] += 1
        s["bytes"] += e["bytes"]

    incidents = []
    for ip, al in by_ip.items():
        al.sort(key=lambda a: a["epoch"])
        rule_alerts = [a for a in al if a["rule"] not in ("ML_IP_ANOMALY",)]
        stages = sorted({a["stage"] for a in al if a["stage"] is not None})
        rules = {a["rule"] for a in al}

        # ---- risk score (0-100)
        best = {}
        for a in al:
            best[a["rule"]] = max(best.get(a["rule"], 0), SEV_W[a["severity"]])
        risk = sum(best.values()) * 0.8 + 8 * max(0, len(stages) - 1) + 0.15 * ml.get(ip, {}).get("score", 0)
        risk = int(min(100, round(risk)))

        # ---- verdict
        if rules & {"SSH_COMPROMISE", "EXFIL_LARGE"}:
            verdict, vclass = "Likely compromised", "bad"
            vtext = "The attacker got in. Treat the account and data as breached."
        elif "OFFHOURS_LOGIN" in rules:
            verdict, vclass = "Suspicious access", "bad"
            vtext = "A login that looks unusual. Confirm with the account owner before anything else."
        elif "WEB_FLOOD" in rules:
            verdict, vclass = "Service attack", "warn"
            vtext = "Aimed at availability, not data. Check whether the site slowed down or went offline."
        elif "WEB_SQLI" in rules and any(a.get("success_hits") for a in al):
            verdict, vclass = "Attack in progress", "warn"
            vtext = "Some injection requests got a normal response. Review the application logs for those URLs."
        elif rule_alerts:
            verdict, vclass = "Attempt, no breach seen", "warn"
            vtext = "Attack traffic was seen but nothing in the logs shows it succeeded."
        else:
            verdict, vclass = "Unusual, needs a look", "info"
            vtext = "Only the anomaly model flagged this IP. No known attack signature matched."

        # ---- story (one sentence per alert, with time gaps)
        steps, prev = [], None
        specific_stages = {a["stage"] for a in al if a["rule"] not in ("ML_IP_ANOMALY", "TRAFFIC_SPIKE", "AUTH_FAIL_SPIKE")}
        for a in al:
            if a["rule"] == "ML_IP_ANOMALY" and a.get("confirmed_by_rules"):
                continue  # explained by rules already; shown as a note instead
            if a["rule"] in ("TRAFFIC_SPIKE", "AUTH_FAIL_SPIKE") and a["stage"] in specific_stages:
                continue  # same fact as a more specific alert; keep the story short
            gap = "" if prev is None else f"+{_dur(a['epoch'] - prev)}"
            steps.append({"id": a["id"], "ts": a["ts"], "gap": gap, "stage": a["stage"],
                          "stage_name": STAGES[a["stage"]] if a["stage"] is not None else "Anomaly",
                          "severity": a["severity"], "title": a["title"], "story": a["story"],
                          "rule": a["rule"], "technique": a["technique"], "technique_name": a["technique_name"],
                          "evidence": a.get("evidence", [])})
            prev = a["epoch"]
        chain = " > ".join(STAGES[s] for s in stages) if stages else "behavioural outlier"

        furthest = max(stages) if stages else None
        nxt = NEXT_MOVE.get(furthest) if furthest is not None else "No clear attack stage yet. Watch this IP and compare with the raw log lines."
        actions = [ACTIONS[s] for s in stages if s in ACTIONS]
        users = sorted({u for a in al for u in a.get("users", [])})
        st = ev_stats[ip]
        first, last = al[0]["epoch"], max(a["epoch_end"] for a in al)
        headline = (f"{ip} was active for {_dur(last - first)} and went through: {chain}. "
                    f"{vtext}")
        block = [f"sudo ufw deny from {ip} to any", f"sudo iptables -A INPUT -s {ip} -j DROP"]
        if "SSH_BRUTE_FORCE" in rules or "SSH_COMPROMISE" in rules:
            block.append("sudo fail2ban-client set sshd banip " + ip)
        if "SSH_COMPROMISE" in rules and users:
            block.append(f"sudo passwd -l {users[0]}   # lock the stolen account, then reset it")
            block.append(f"sudo pkill -KILL -u {users[0]}   # end its live sessions")
        incidents.append({
            "ip": ip, "risk": risk, "verdict": verdict, "verdict_class": vclass, "verdict_text": vtext,
            "stages": stages, "furthest": furthest, "chain": chain, "headline": headline,
            "steps": steps, "next_move": nxt, "actions": actions, "users": users,
            "alert_count": len(al), "first": al[0]["ts"], "last": al[-1]["ts_end"],
            "duration": _dur(last - first), "ml": ml.get(ip), "stats": st, "block": block,
            "mitre": sorted({f"{a['technique']} {a['technique_name']}" for a in al if a["technique"] != "-"}),
        })
    incidents.sort(key=lambda i: -i["risk"])
    return incidents
