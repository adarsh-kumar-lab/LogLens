"""Log parser: turns raw text lines into ONE common event format.

Supported formats
  1. Apache / Nginx "combined" access log   (web traffic)
  2. Linux OpenSSH auth.log / secure        (login attempts)

Every parsed line becomes a dict:
  {ts, epoch, source, ip, user, method, path, status, bytes, ua, outcome, raw}
Lines that are not understood are skipped (and counted), never crash the app.
"""
import re
import calendar
import datetime as dt

APACHE = re.compile(
    r'^(\S+) \S+ (\S+) \[([^\]]+)\] "(\S+) (\S+)(?: [^"]*)?" (\d{3}) (\d+|-) "([^"]*)" "([^"]*)"'
)
SSH_LINE = re.compile(r"^(\w{3})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2}) (\S+) sshd\[\d+\]: (.*)$")
SSH_FAIL = re.compile(r"Failed (?:password|publickey|keyboard-interactive/pam) for (?:invalid user )?(\S+) from (\S+) port (\d+)")
SSH_OK = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (\S+) from (\S+) port (\d+)")

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}


def _epoch(d):
    return calendar.timegm(d.timetuple())


def _iso(d):
    return d.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_web_line(line):
    m = APACHE.match(line)
    if not m:
        return None
    ip, user, ts, method, path, status, size, _ref, ua = m.groups()
    try:
        d = dt.datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        d = (d - d.utcoffset()).replace(tzinfo=None)  # -> naive UTC
    except ValueError:
        return None
    return {
        "ts": _iso(d), "epoch": _epoch(d), "source": "web", "ip": ip,
        "user": None if user == "-" else user, "method": method, "path": path,
        "status": int(status), "bytes": 0 if size == "-" else int(size), "ua": ua,
        "outcome": None, "raw": line[:300],
    }


def parse_ssh_line(line, ref_year, now):
    m = SSH_LINE.match(line)
    if not m:
        return None
    mon, day, hh, mm, ss, _host, msg = m.groups()
    if mon not in MONTHS:
        return None
    try:
        d = dt.datetime(ref_year, MONTHS[mon], int(day), int(hh), int(mm), int(ss))
    except ValueError:
        return None
    if d > now + dt.timedelta(days=2):  # log from last December
        d = d.replace(year=ref_year - 1)
    f = SSH_FAIL.search(msg)
    if f:
        user, ip, _ = f.groups()
        outcome = "fail"
    else:
        o = SSH_OK.search(msg)
        if not o:
            return None
        user, ip, _ = o.groups()
        outcome = "success"
    return {
        "ts": _iso(d), "epoch": _epoch(d), "source": "ssh", "ip": ip, "user": user,
        "method": None, "path": None, "status": None, "bytes": 0, "ua": None,
        "outcome": outcome, "raw": line[:300],
    }


def parse_lines(lines):
    """Auto-detects the format of every line. Returns (events, skipped_count)."""
    now = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None)
    events, skipped = [], 0
    for line in lines:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        ev = parse_web_line(line) or parse_ssh_line(line, now.year, now)
        if ev:
            events.append(ev)
        else:
            skipped += 1
    events.sort(key=lambda e: e["epoch"])
    return events, skipped


def parse_file(path):
    with open(path, "r", errors="replace") as fh:
        return parse_lines(fh)
