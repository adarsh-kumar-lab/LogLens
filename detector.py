"""Detection engine: 3 layers.

 Layer 1  RULES            - known attack patterns (signatures + thresholds in sliding windows)
 Layer 2  TIME-SERIES      - rolling robust z-score on traffic volume (finds spikes)
 Layer 3  MACHINE LEARNING - Isolation Forest on per-IP behaviour (finds the unknown / low-and-slow)

Rules catch what we already know. ML catches behaviour that is simply *unusual*.
Every alert carries: severity, MITRE technique, evidence lines and a plain-English story sentence.
"""
import re
import math
from collections import defaultdict, Counter
from urllib.parse import unquote

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    HAVE_ML = True
except Exception:  # project still runs without scikit-learn (rules + stats only)
    HAVE_ML = False

from .mitre import RULES

# ----------------------------------------------------------------------------- config
CFG = {
    "ssh_brute_window": 300, "ssh_brute_min": 8,
    "web_login_window": 300, "web_login_min": 10,
    "scan_window": 120, "scan_min_404": 25,
    "flood_per_min": 300,
    "exfil_bytes": 5_000_000,
    "compromise_lookback": 1800, "compromise_min_fails": 5,
    "spike_min_rpm": 60, "spike_z": 6.0, "spike_baseline_min": 60,
    "ml_contamination": 0.12, "ml_min_ips": 12, "ml_min_z": 3.5,
    "offhours": (22, 6),  # login between 22:00 and 06:00 UTC counts as unusual
}

SQLI = re.compile(
    r"(\bunion\b.{0,40}\bselect\b|'\s*or\s*'|\bor\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|;\s*drop\s+table|"
    r"\bsleep\s*\(|\bbenchmark\s*\(|information_schema|\bselect\b.{0,40}\bfrom\b|--\s*$)", re.I)
XSS = re.compile(r"(<\s*script|onerror\s*=|onload\s*=|javascript:|<\s*img[^>]+src)", re.I)
TRAVERSAL = re.compile(r"(\.\./|\.\.\\|\.\.\.\.//|%2e%2e|/etc/passwd|/etc/shadow|boot\.ini)", re.I)
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wpscan|acunetix|nessus|zgrab)", re.I)
LOGIN_PATH = re.compile(r"^/(wp-)?login|^/admin/login|^/signin", re.I)


def _decode(s):
    for _ in range(2):  # double-decode catches %252e style evasion
        s = unquote(s)
    return s


def _episodes(times, window, threshold):
    """Sliding window: returns [(start, end)] where >= threshold events fell inside `window` seconds."""
    out, i, cur = [], 0, None
    for j, t in enumerate(times):
        while t - times[i] > window:
            i += 1
        if j - i + 1 >= threshold:
            s = times[i]
            if cur and s <= cur[1]:
                cur[1] = t
            else:
                if cur:
                    out.append(tuple(cur))
                cur = [s, t]
    if cur:
        out.append(tuple(cur))
    return out


def _mk(rule, severity, ip, start, end, count, title, story, evidence, **extra):
    tactic, tid, tname, stage = RULES[rule]
    a = {"rule": rule, "severity": severity, "ip": ip, "epoch": int(start), "epoch_end": int(end),
         "count": count, "title": title, "story": story, "tactic": tactic, "technique": tid,
         "technique_name": tname, "stage": stage, "evidence": [e["raw"][:220] for e in evidence[:4]]}
    a.update(extra)
    return a


def _iso(epoch):
    import datetime as dt
    return dt.datetime.utcfromtimestamp(epoch).strftime("%Y-%m-%dT%H:%M:%SZ")


# ============================================================================ LAYER 1: rules
def run_rules(events):
    alerts = []
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)
    first_seen = {ip: evs[0]["epoch"] for ip, evs in by_ip.items()}

    for ip, evs in by_ip.items():
        ssh_fail = [e for e in evs if e["source"] == "ssh" and e["outcome"] == "fail"]
        ssh_ok = [e for e in evs if e["source"] == "ssh" and e["outcome"] == "success"]
        web = [e for e in evs if e["source"] == "web"]
        compromised = False

        # ---- SSH brute force
        for s, en in _episodes([e["epoch"] for e in ssh_fail], CFG["ssh_brute_window"], CFG["ssh_brute_min"]):
            seg = [e for e in ssh_fail if s <= e["epoch"] <= en]
            users = Counter(e["user"] for e in seg)
            alerts.append(_mk(
                "SSH_BRUTE_FORCE", "high", ip, s, en, len(seg),
                f"SSH password guessing ({len(seg)} failures)",
                f"Started guessing SSH passwords: {len(seg)} failed logins against {len(users)} different usernames "
                f"in {max(1, round((en - s) / 60))} min.", seg, users=[u for u, _ in users.most_common(8)]))

        # ---- SSH compromise: a success right after many failures
        for ok in ssh_ok:
            prior = [e for e in ssh_fail if ok["epoch"] - CFG["compromise_lookback"] <= e["epoch"] < ok["epoch"]]
            if len(prior) >= CFG["compromise_min_fails"]:
                compromised = True
                alerts.append(_mk(
                    "SSH_COMPROMISE", "critical", ip, ok["epoch"], ok["epoch"], 1,
                    f"Successful login as '{ok['user']}' after {len(prior)} failures",
                    f"Logged in successfully as '{ok['user']}' after {len(prior)} failed attempts. "
                    f"The guessing worked, so the account should be treated as stolen.", [ok] + prior[-2:], users=[ok["user"]]))

        # ---- login at odd hours from an IP never seen before
        for ok in ssh_ok:
            hr = int(_iso(ok["epoch"])[11:13])
            lo, hi = CFG["offhours"][0], CFG["offhours"][1]
            odd = hr >= lo or hr < hi
            if odd and ok["epoch"] == first_seen[ip] and not compromised and len(ssh_ok) <= 2:
                alerts.append(_mk(
                    "OFFHOURS_LOGIN", "high", ip, ok["epoch"], ok["epoch"], 1,
                    f"Night-time login for '{ok['user']}' from a brand-new IP",
                    f"Logged in as '{ok['user']}' at {_iso(ok['epoch'])[11:16]} UTC. This IP had never appeared in the logs before "
                    f"and the login happened outside normal working hours.", [ok], users=[ok["user"]]))

        # ---- web: scanner (404 flood and / or scanner user-agent)
        errs = [e for e in web if e["status"] in (404, 403)]
        ua_hits = [e for e in web if e["ua"] and SCANNER_UA.search(e["ua"])]
        eps = _episodes([e["epoch"] for e in errs], CFG["scan_window"], CFG["scan_min_404"])
        tool = SCANNER_UA.search(ua_hits[0]["ua"]).group(1).lower() if ua_hits else None
        if eps:
            s, en = eps[0][0], eps[-1][1]
            seg = [e for e in errs if s <= e["epoch"] <= en]
            alerts.append(_mk(
                "WEB_SCANNER", "medium", ip, s, en, len(seg),
                f"Website scanning ({len(seg)} requests for missing pages)",
                f"Probed the website for hidden files: {len(seg)} requests hit pages that do not exist"
                + (f", using the tool '{tool}'." if tool else "."), seg, tool=tool))
        elif len(ua_hits) >= 5:
            alerts.append(_mk(
                "WEB_SCANNER", "medium", ip, ua_hits[0]["epoch"], ua_hits[-1]["epoch"], len(ua_hits),
                f"Hacking tool '{tool}' detected",
                f"Identified itself as the security tool '{tool}' ({len(ua_hits)} requests).", ua_hits, tool=tool))

        # ---- web: injection style attacks (decode URL first!)
        for rule, rx, label, sev in (("WEB_SQLI", SQLI, "SQL injection", "high"),
                                      ("WEB_XSS", XSS, "Cross-site scripting (XSS)", "medium"),
                                      ("WEB_TRAVERSAL", TRAVERSAL, "Path traversal", "high")):
            hits = [e for e in web if rx.search(_decode(e["path"]))]
            if hits:
                ok2xx = sum(1 for e in hits if 200 <= e["status"] < 300)
                extra = f" {ok2xx} of them returned HTTP 200, so some may have worked." if ok2xx else " All were rejected by the server."
                alerts.append(_mk(
                    rule, sev if len(hits) >= 3 else "medium", ip, hits[0]["epoch"], hits[-1]["epoch"], len(hits),
                    f"{label} attempts ({len(hits)} requests)",
                    f"Sent {len(hits)} {label.lower()} requests.{extra}", hits, success_hits=ok2xx))

        # ---- web: login brute force (fast)
        logins = [e for e in web if e["method"] == "POST" and LOGIN_PATH.match(e["path"]) and e["status"] in (401, 403)]
        for s, en in _episodes([e["epoch"] for e in logins], CFG["web_login_window"], CFG["web_login_min"]):
            seg = [e for e in logins if s <= e["epoch"] <= en]
            alerts.append(_mk("WEB_LOGIN_BRUTE", "high", ip, s, en, len(seg),
                              f"Web login guessing ({len(seg)} rejected logins)",
                              f"Tried {len(seg)} wrong passwords on the website login page in {max(1, round((en - s) / 60))} min.", seg))

        # ---- web: flood (requests per minute)
        per_min = Counter(e["epoch"] // 60 for e in web)
        hot = sorted(m for m, c in per_min.items() if c >= CFG["flood_per_min"])
        if hot:
            seg = [e for e in web if hot[0] <= e["epoch"] // 60 <= hot[-1]]
            peak = max(per_min[m] for m in hot)
            alerts.append(_mk("WEB_FLOOD", "high", ip, hot[0] * 60, hot[-1] * 60 + 59, len(seg),
                              f"Request flood (peak {peak}/min)",
                              f"Hammered the site with up to {peak:,} requests per minute (a normal visitor sends 1 to 5).", seg, peak_rpm=peak))

        # ---- exfiltration: huge responses
        big = [e for e in web if e["bytes"] >= CFG["exfil_bytes"] and 200 <= (e["status"] or 0) < 300]
        if big:
            mb = sum(e["bytes"] for e in big) / 1e6
            paths = sorted({e["path"].split("?")[0] for e in big})
            alerts.append(_mk("EXFIL_LARGE", "critical", ip, big[0]["epoch"], big[-1]["epoch"], len(big),
                              f"Large data download ({mb:.0f} MB)",
                              f"Downloaded {mb:.0f} MB in {len(big)} request(s) from {', '.join(paths)}. "
                              f"A normal page is under 0.1 MB.", big, mb=round(mb, 1)))
    return alerts


# ============================================================================ LAYER 2: time series
def run_timeseries(events):
    alerts = []
    for kind, rule, src, cond, floor in (
        ("web requests", "TRAFFIC_SPIKE", "web", lambda e: True, CFG["spike_min_rpm"]),
        ("failed SSH logins", "AUTH_FAIL_SPIKE", "ssh", lambda e: e["outcome"] == "fail", 20),
    ):
        evs = [e for e in events if e["source"] == src and cond(e)]
        if not evs:
            continue
        t0, t1 = events[0]["epoch"] // 60, events[-1]["epoch"] // 60
        series = [0] * (t1 - t0 + 1)
        for e in evs:
            series[e["epoch"] // 60 - t0] += 1
        B = CFG["spike_baseline_min"]
        flagged = []
        for i in range(B, len(series)):
            base = sorted(series[i - B:i])
            med = base[B // 2]
            mad = sorted(abs(x - med) for x in base)[B // 2]
            z = (series[i] - med) / (1.4826 * mad + 1.0)
            if series[i] >= floor and z >= CFG["spike_z"]:
                flagged.append((i + t0, series[i], z, med))
        # merge consecutive minutes
        groups, cur = [], []
        for f in flagged:
            if cur and f[0] - cur[-1][0] > 1:
                groups.append(cur)
                cur = []
            cur.append(f)
        if cur:
            groups.append(cur)
        for g in groups:
            s, en = g[0][0] * 60, g[-1][0] * 60 + 59
            seg = [e for e in evs if s <= e["epoch"] <= en]
            top = Counter(e["ip"] for e in seg).most_common(1)[0]
            share = top[1] / len(seg)
            ip = top[0] if share >= 0.6 else None
            peak = max(x[1] for x in g)
            who = f"{share:.0%} of it came from {top[0]}" if ip else "spread over many IPs"
            alerts.append(_mk(rule, "medium", ip, s, en, len(seg),
                              f"Traffic spike: {peak}/min {kind} (normal about {int(g[0][3])})",
                              f"Volume of {kind} jumped to {peak}/min, far above the rolling baseline of ~{int(g[0][3])}/min; {who}.",
                              seg, peak=peak, baseline=int(g[0][3])))
    return alerts


# ============================================================================ LAYER 3: machine learning
FEATURES = [  # key, label, transform
    ("requests", "web requests", "log"), ("peak_rpm", "peak requests/min", "log"),
    ("unique_paths", "distinct URLs", "log"), ("error_ratio", "error rate", "lin"),
    ("auth_fails", "failed logins", "log"), ("ssh_users", "usernames tried", "log"),
    ("mb_out", "MB downloaded", "log"), ("regularity", "robotic timing", "lin"),
]


def ip_features(events):
    by_ip = defaultdict(list)
    for e in events:
        by_ip[e["ip"]].append(e)
    rows = {}
    for ip, evs in by_ip.items():
        web = [e for e in evs if e["source"] == "web"]
        ssh = [e for e in evs if e["source"] == "ssh"]
        per_min = Counter(e["epoch"] // 60 for e in web)
        errs = sum(1 for e in web if e["status"] and e["status"] >= 400)
        wl = sum(1 for e in web if e["status"] in (401, 403) and LOGIN_PATH.match(e["path"] or ""))
        sf = [e for e in ssh if e["outcome"] == "fail"]
        t = [e["epoch"] for e in evs]
        reg = 0.0
        if len(t) >= 15:
            gaps = [b - a for a, b in zip(t, t[1:])]
            mean = sum(gaps) / len(gaps)
            if mean > 0:
                sd = math.sqrt(sum((g - mean) ** 2 for g in gaps) / len(gaps))
                reg = 1 / (1 + sd / mean)
        rows[ip] = {
            "requests": len(web), "peak_rpm": max(per_min.values()) if per_min else 0,
            "unique_paths": len({e["path"] for e in web}), "error_ratio": errs / len(web) if web else 0.0,
            "auth_fails": len(sf) + wl, "ssh_users": len({e["user"] for e in sf}),
            "mb_out": sum(e["bytes"] for e in web) / 1e6, "regularity": reg,
            "events": len(evs), "first": min(t), "last": max(t),
        }
    return rows


def _tf(v, kind):
    return math.log1p(v) if kind == "log" else v


def _median(xs):
    s = sorted(xs)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def run_ml(events):
    """Returns (alerts, ip_table). ip_table has an anomaly score 0-100 for every IP + reasons."""
    feats = ip_features(events)
    ips = list(feats)
    if not ips:
        return [], []
    cols = {k: [_tf(feats[ip][k], kind) for ip in ips] for k, _, kind in FEATURES}
    med = {k: _median(v) for k, v in cols.items()}
    mad = {k: _median([abs(x - med[k]) for x in v]) for k, v in cols.items()}
    zs = {ip: {k: (cols[k][i] - med[k]) / (1.4826 * mad[k] + 0.7) for k, _, _ in FEATURES} for i, ip in enumerate(ips)}
    raw_med = {k: _median([feats[ip][k] for ip in ips]) for k, _, _ in FEATURES}

    # --- model score
    if HAVE_ML and len(ips) >= CFG["ml_min_ips"]:
        X = np.array([[cols[k][i] for k, _, _ in FEATURES] for i in range(len(ips))])
        X = (X - X.mean(0)) / (X.std(0) + 1e-9)
        model = IsolationForest(n_estimators=300, contamination=CFG["ml_contamination"], random_state=42).fit(X)
        raw = -model.score_samples(X)
        flag = model.predict(X) == -1
        method = "Isolation Forest"
    else:  # fallback: max robust z-score
        raw = [max(zs[ip].values()) for ip in ips]
        thr = sorted(raw)[int(len(raw) * (1 - CFG["ml_contamination"]))] if len(raw) > 3 else 1e9
        flag = [r >= thr for r in raw]
        method = "Robust z-score"
    lo, hi = min(raw), max(raw)
    scores = [float(100 * (r - lo) / (hi - lo + 1e-9)) for r in raw]

    fmt = {"requests": lambda v: f"{v:,.0f} web requests", "peak_rpm": lambda v: f"peak {v:,.0f} requests/min",
           "unique_paths": lambda v: f"{v:,.0f} distinct URLs", "error_ratio": lambda v: f"{v:.0%} of requests failed",
           "auth_fails": lambda v: f"{v:,.0f} failed logins", "ssh_users": lambda v: f"{v:,.0f} usernames tried",
           "mb_out": lambda v: f"{v:,.1f} MB downloaded", "regularity": lambda v: f"timing {v:.0%} machine-regular"}
    table, alerts = [], []
    for i, ip in enumerate(ips):
        f = feats[ip]
        top = sorted(((zs[ip][k], k) for k, _, _ in FEATURES), reverse=True)[:3]
        reasons = [{"feature": k, "z": round(z, 1),
                    "text": f"{fmt[k](f[k])} (typical IP: {fmt[k](raw_med[k])})"} for z, k in top if z >= 2.5]
        table.append({"ip": ip, "score": round(scores[i], 1), "flagged": bool(flag[i]), "reasons": reasons,
                      "events": f["events"], "requests": f["requests"], "auth_fails": f["auth_fails"],
                      "mb_out": round(f["mb_out"], 1), "peak_rpm": f["peak_rpm"], "error_ratio": round(f["error_ratio"], 2)})
        if flag[i] and top[0][0] >= CFG["ml_min_z"]:
            k = top[0][1]
            stage = {"auth_fails": 1, "ssh_users": 1, "regularity": 1, "unique_paths": 0, "error_ratio": 0,
                     "peak_rpm": 5, "mb_out": 4}.get(k)
            sev = "high" if scores[i] >= 85 else "medium" if scores[i] >= 60 else "low"
            why = "; ".join(r["text"] for r in reasons) or "unusual overall behaviour"
            a = _mk("ML_IP_ANOMALY", sev, ip, f["first"], f["last"], f["events"],
                    f"Unusual behaviour (anomaly score {scores[i]:.0f}/100)",
                    f"Behaves unlike the other visitors: {why}.", [], ml_score=round(scores[i], 1), reasons=reasons, method=method)
            a["stage"] = stage
            alerts.append(a)
    table.sort(key=lambda r: -r["score"])
    return alerts, table, method


def detect_all(events):
    rule_alerts = run_rules(events)
    ts_alerts = run_timeseries(events)
    ml_alerts, ip_table, method = run_ml(events)
    # keep ML alerts that add information; mark those that rules already explain
    rule_ips = {a["ip"] for a in rule_alerts}
    for a in ml_alerts:
        a["confirmed_by_rules"] = a["ip"] in rule_ips
    alerts = rule_alerts + ts_alerts + ml_alerts
    alerts.sort(key=lambda a: a["epoch"])
    for n, a in enumerate(alerts, 1):
        a["id"] = f"A{n:03d}"
        a["ts"] = _iso(a["epoch"])
        a["ts_end"] = _iso(a["epoch_end"])
    return alerts, ip_table, method
