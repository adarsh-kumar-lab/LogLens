"""Orchestrates the whole pipeline: events -> alerts -> incidents -> dashboard numbers."""
import json
import os
from collections import Counter, defaultdict

from .detector import detect_all
from .storyline import build_incidents
from .mitre import STAGES

SEV_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _timeline(events, alerts, bucket_min=10):
    if not events:
        return []
    b = bucket_min * 60
    t0 = events[0]["epoch"] // b * b
    n = (events[-1]["epoch"] - t0) // b + 1
    rows = [{"t": t0 + i * b, "web": 0, "ssh_fail": 0, "ssh_ok": 0, "alerts": 0, "sev": 0, "ips": []} for i in range(n)]
    for e in events:
        r = rows[(e["epoch"] - t0) // b]
        if e["source"] == "web":
            r["web"] += 1
        elif e["outcome"] == "fail":
            r["ssh_fail"] += 1
        else:
            r["ssh_ok"] += 1
    for a in alerts:
        if a["rule"] == "ML_IP_ANOMALY":
            continue
        i = min(n - 1, max(0, (a["epoch"] - t0) // b))
        r = rows[i]
        r["alerts"] += 1
        r["sev"] = max(r["sev"], SEV_ORDER[a["severity"]])
        if a["ip"] and a["ip"] not in r["ips"]:
            r["ips"].append(a["ip"])
    return rows


def evaluate(incidents, truth):
    """Compare flagged IPs with the known attackers (only possible on the sample data)."""
    flagged = {i["ip"] for i in incidents}
    real = set(truth)
    tp, fp, fn = flagged & real, flagged - real, real - flagged
    p = len(tp) / len(flagged) if flagged else 0
    r = len(tp) / len(real) if real else 0
    f1 = 2 * p * r / (p + r) if p + r else 0
    return {"known_attackers": len(real), "found": len(tp), "missed": sorted(fn), "false_alarms": sorted(fp),
            "precision": round(p, 3), "recall": round(r, 3), "f1": round(f1, 3)}


def analyze(events, truth=None, skipped=0):
    alerts, ip_table, method = detect_all(events)
    incidents = build_incidents(alerts, ip_table, events)
    sev = Counter(a["severity"] for a in alerts)
    tactics = Counter(a["tactic"] for a in alerts if a["tactic"] != "Anomaly")
    stage_counts = Counter(s for i in incidents for s in i["stages"])
    ssh_users = Counter(e["user"] for e in events if e["source"] == "ssh" and e["outcome"] == "fail")
    paths = Counter((e["path"] or "").split("?")[0] for e in events if e["source"] == "web" and e["status"] and e["status"] >= 400)
    summary = {
        "events": len(events), "web": sum(1 for e in events if e["source"] == "web"),
        "ssh": sum(1 for e in events if e["source"] == "ssh"), "skipped": skipped,
        "unique_ips": len({e["ip"] for e in events}), "alerts": len(alerts), "severity": dict(sev),
        "incidents": len(incidents), "compromised": sum(1 for i in incidents if i["verdict_class"] == "bad"),
        "from": events[0]["ts"] if events else None, "to": events[-1]["ts"] if events else None,
        "model": method,
    }
    return {
        "summary": summary, "alerts": alerts, "ips": ip_table, "incidents": incidents,
        "timeline": _timeline(events, alerts),
        "tactics": [{"name": k, "count": v} for k, v in tactics.most_common()],
        "stage_counts": [{"name": STAGES[s], "count": stage_counts.get(s, 0)} for s in range(len(STAGES))],
        "top_users": [{"name": k, "count": v} for k, v in ssh_users.most_common(8)],
        "top_errors": [{"name": k, "count": v} for k, v in paths.most_common(8)],
        "evaluation": evaluate(incidents, truth) if truth else None,
    }
