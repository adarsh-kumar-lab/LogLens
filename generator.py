"""Synthetic log generator (so the project runs without downloading anything).

Creates a realistic last-24h dataset:
  data/access.log  (Apache combined format)
  data/auth.log    (OpenSSH syslog format)
  data/ground_truth.json (which IPs are the attackers -> used to measure our accuracy)

Normal users + normal noise are mixed with 7 different attackers, each with a
different behaviour, so every detector in the project has something to find.
You can replace these files with REAL logs (or Loghub / Kaggle datasets) any time.
"""
import os
import json
import math
import random
import datetime as dt

UA_NORMAL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/118.0 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]
PATHS = ["/", "/index.html", "/products", "/products/12", "/products/48", "/about", "/contact",
         "/static/app.js", "/static/style.css", "/api/items", "/blog/post-1", "/blog/post-2",
         "/cart", "/checkout", "/search?q=laptop", "/search?q=phone", "/login", "/account"]
VALID_USERS = ["alice", "bob", "carol", "deploy", "admin"]
OFFICE_IPS = ["10.0.0.5", "10.0.0.8", "192.168.1.20", "10.0.0.12"]
SSH_GUESSES = ["root", "admin", "ubuntu", "test", "oracle", "postgres", "user", "guest", "pi",
               "ftp", "git", "deploy", "support", "administrator", "mysql", "nagios"]

# ground-truth label for each attacker IP
ATTACKERS = {
    "185.220.101.45": "full attack chain: scan -> SSH brute force -> login -> data theft",
    "45.155.205.12": "SQL injection with sqlmap",
    "103.75.190.7": "XSS + path traversal probing",
    "91.240.118.9": "Nikto web vulnerability scan (404 flood)",
    "198.51.100.77": "HTTP flood on /login (DoS)",
    "203.0.113.50": "low-and-slow credential stuffing on /login",
    "77.88.55.60": "off-hours SSH login from a never-seen IP",
}


def _web(ts, ip, method, path, status, size, ua, ref="-"):
    return (ts, f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} {size} "{ref}" "{ua}"')


def _ssh(ts, msg, host="srv01"):
    return (ts, f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {host} sshd[{random.randint(1000, 9999)}]: {msg}")


def generate(out_dir, seed=7, hours=24):
    rnd = random.Random(seed)
    random.seed(seed)
    end = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None, second=0, microsecond=0)
    start = end - dt.timedelta(hours=hours)
    web, ssh = [], []

    # ---------------- normal website traffic (day/night pattern) ----------------
    users = [f"{rnd.choice([49, 59, 106, 117, 122, 157, 182, 27, 14])}.{rnd.randint(1, 250)}."
             f"{rnd.randint(1, 250)}.{rnd.randint(2, 250)}" for _ in range(48)]
    for m in range(hours * 60):
        t = start + dt.timedelta(minutes=m)
        h = t.hour + t.minute / 60
        load = max(0.35, math.sin(math.pi * (h - 5) / 17))
        mu = 6.5 * load
        for _ in range(max(0, int(rnd.gauss(mu, mu ** 0.5) + 0.5))):
            ts = t + dt.timedelta(seconds=rnd.randint(0, 59))
            r = rnd.random()
            status = 200 if r < 0.88 else 304 if r < 0.94 else 404 if r < 0.97 else 302 if r < 0.995 else 500
            path = rnd.choice(PATHS) if status != 404 else rnd.choice(["/old-page", "/favicon.ico", "/img/x.png"])
            web.append(_web(ts, rnd.choice(users), "GET", path, status, rnd.randint(500, 90000),
                            rnd.choice(UA_NORMAL), "https://www.example.com/"))

    # ---------------- friendly crawler (looks robotic, but harmless) ----------------
    for i in range(150):
        ts = start + dt.timedelta(minutes=i * 9.6 + rnd.uniform(-1, 1))
        web.append(_web(ts, "66.249.66.1", "GET", f"/products/{rnd.randint(1, 60)}", 200,
                        rnd.randint(8000, 40000), "Googlebot/2.1 (+http://www.google.com/bot.html)"))

    # ---------------- normal SSH ----------------
    for d in range(2):
        for hh in range(9, 18):
            day = (end - dt.timedelta(days=d)).replace(hour=hh, minute=0)
            if not (start <= day <= end - dt.timedelta(minutes=5)):
                continue
            for _ in range(rnd.randint(1, 3)):
                u = rnd.choice(VALID_USERS[:4])
                ip = rnd.choice(OFFICE_IPS)
                ts = day + dt.timedelta(minutes=rnd.randint(0, 55), seconds=rnd.randint(0, 59))
                if rnd.random() < 0.22:  # honest typo
                    ssh.append(_ssh(ts - dt.timedelta(seconds=6), f"Failed password for {u} from {ip} port {rnd.randint(30000, 60000)} ssh2"))
                ssh.append(_ssh(ts, f"Accepted password for {u} from {ip} port {rnd.randint(30000, 60000)} ssh2"))
                ssh.append(_ssh(ts, f"pam_unix(sshd:session): session opened for user {u}"))  # noise line

    # ---------------- ATTACKER 1: full chain ----------------
    a = "185.220.101.45"
    t0 = end - dt.timedelta(hours=7, minutes=20)
    recon = ["/admin", "/backup.zip", "/.git/config", "/phpmyadmin/", "/wp-login.php", "/.env", "/config.php",
             "/server-status", "/db.sql", "/admin/login", "/test", "/old", "/uploads/", "/api/v1/users"]
    for i in range(70):
        ts = t0 + dt.timedelta(seconds=i * 2.6)
        web.append(_web(ts, a, "GET", rnd.choice(recon) + (str(i) if i % 3 == 0 else ""), 404, 196,
                        "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"))
    tb = t0 + dt.timedelta(minutes=10)
    times = sorted(rnd.uniform(0, 540) for _ in range(260))
    for s in times:
        u = rnd.choice(SSH_GUESSES)
        inv = "" if u in VALID_USERS else "invalid user "
        ssh.append(_ssh(tb + dt.timedelta(seconds=s), f"Failed password for {inv}{u} from {a} port {rnd.randint(30000, 60000)} ssh2"))
    tl = tb + dt.timedelta(seconds=560)
    ssh.append(_ssh(tl, f"Accepted password for admin from {a} port 41022 ssh2"))
    web.append(_web(tl + dt.timedelta(minutes=2), a, "GET", "/admin/export?table=users", 200, 48_200_000, "curl/7.68.0"))
    web.append(_web(tl + dt.timedelta(minutes=3), a, "GET", "/admin/export?table=orders", 200, 31_500_000, "curl/7.68.0"))

    # ---------------- ATTACKER 2: SQL injection ----------------
    a = "45.155.205.12"
    t0 = end - dt.timedelta(hours=14)
    sqli = ["/products.php?id=1'%20OR%20'1'='1", "/products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
            "/search?q=' OR 1=1--", "/products.php?id=1;DROP TABLE users", "/products.php?id=1 AND sleep(5)",
            "/products.php?id=1%27%20OR%20%271%27%3D%271", "/item?id=5 UNION SELECT table_name FROM information_schema.tables"]
    for i in range(44):
        web.append(_web(t0 + dt.timedelta(seconds=i * 7 + rnd.randint(0, 3)), a, "GET", rnd.choice(sqli).replace(" ", "%20"),
                        rnd.choice([500, 500, 200, 403]), rnd.randint(300, 6000), "sqlmap/1.7.2#stable (https://sqlmap.org)"))

    # ---------------- ATTACKER 3: XSS + traversal ----------------
    a = "103.75.190.7"
    t0 = end - dt.timedelta(hours=10)
    bad = ["/search?q=<script>alert(1)</script>", "/comment?text=%3Cimg%20src=x%20onerror=alert(1)%3E",
           "/download?file=../../../../etc/passwd", "/static/..%2f..%2f..%2fetc/shadow",
           "/page?x=javascript:alert(document.cookie)", "/view?f=....//....//etc/passwd"]
    for i in range(30):
        web.append(_web(t0 + dt.timedelta(seconds=i * 11 + rnd.randint(0, 5)), a, "GET", rnd.choice(bad).replace(" ", "%20"),
                        rnd.choice([400, 403, 200, 404]), rnd.randint(200, 3000), rnd.choice(UA_NORMAL)))

    # ---------------- ATTACKER 4: Nikto scan ----------------
    a = "91.240.118.9"
    t0 = end - dt.timedelta(hours=3)
    for i in range(190):
        web.append(_web(t0 + dt.timedelta(seconds=i * 0.5), a, "GET", f"/{rnd.choice(['cgi-bin', 'admin', 'scripts', 'backup', 'test', 'old'])}/{rnd.randint(100, 999)}.php",
                        404 if rnd.random() < 0.93 else 403, 196, "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:003424)"))

    # ---------------- ATTACKER 5: HTTP flood ----------------
    a = "198.51.100.77"
    t0 = end - dt.timedelta(minutes=100)
    for i in range(1800):
        web.append(_web(t0 + dt.timedelta(seconds=rnd.uniform(0, 59)), a, "GET", "/login",
                        200 if rnd.random() < 0.85 else 503, rnd.randint(2000, 3000), "Mozilla/5.0"))

    # ---------------- ATTACKER 6: low-and-slow stuffing ----------------
    a = "203.0.113.50"
    t0 = end - dt.timedelta(hours=9)
    for i in range(165):
        web.append(_web(t0 + dt.timedelta(seconds=i * 88 + rnd.uniform(-4, 4)), a, "POST", "/login", 401, 512, "python-requests/2.28.1"))

    # ---------------- ATTACKER 7: off-hours login ----------------
    a = "77.88.55.60"
    t = end.replace(hour=3, minute=12, second=41)
    if t > end - dt.timedelta(minutes=10):
        t -= dt.timedelta(days=1)
    if t < start:
        t += dt.timedelta(days=1)
    ssh.append(_ssh(t, f"Accepted password for deploy from {a} port 52814 ssh2"))

    os.makedirs(out_dir, exist_ok=True)
    web.sort(key=lambda x: x[0])
    ssh.sort(key=lambda x: x[0])
    with open(os.path.join(out_dir, "access.log"), "w") as f:
        f.write("\n".join(l for _, l in web) + "\n")
    with open(os.path.join(out_dir, "auth.log"), "w") as f:
        f.write("\n".join(l for _, l in ssh) + "\n")
    with open(os.path.join(out_dir, "ground_truth.json"), "w") as f:
        json.dump(ATTACKERS, f, indent=2)
    return {"web_lines": len(web), "ssh_lines": len(ssh), "dir": out_dir}


if __name__ == "__main__":
    print(generate(os.path.join(os.path.dirname(__file__), "..", "data")))
