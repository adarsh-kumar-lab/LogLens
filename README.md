# LogLens: Cybersecurity Log Analysis and Intrusion Detection Dashboard

Reads web-server and SSH logs, finds attacks with **rules + statistics + machine learning**, and shows them
on a dashboard. The unique feature is **Attack Storyline Reconstruction**: instead of 20 separate alerts you
get one story per attacker (what they did, in which order, whether it worked, and what they will probably do next).

## Run it (3 commands)

```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000 in the browser
```

Windows: use `py -m pip install -r requirements.txt` and `py app.py`. Python 3.9+ needed.
First start creates sample logs by itself (no download needed).

Charts use **Plotly.js** (bundled offline as `static/plotly.min.js`, no internet or extra pip package needed).

## Using the dashboard

| Button / tab | What it does |
|---|---|
| New sample data | Generates a fresh 24 h log set with 7 attackers hidden among ~60 normal IPs |
| Upload logs | Analyse your OWN Apache/Nginx `access.log` and/or OpenSSH `auth.log` (you can pick both at once) |
| Download blocklist | `blocklist.sh` with firewall commands for the risky IPs (review before running) |
| Attack stories | The unique feature. Click an IP on the left |
| All alerts | Every alert with severity, MITRE technique, filter + search |
| IP behaviour scores | ML anomaly score for every IP with the reasons |
| Raw log lines | The original lines for any IP (evidence) |

## Project structure

```
app.py               Flask backend + REST API
core/parser.py       log lines -> common event format (web + ssh)
core/generator.py    realistic sample logs with 7 attacker types + ground truth
core/detector.py     Layer 1 rules, Layer 2 time-series spikes, Layer 3 Isolation Forest
core/mitre.py        rule -> MITRE ATT&CK mapping, 6 kill-chain stages, advice text
core/storyline.py    UNIQUE FEATURE: groups alerts into per-attacker stories + verdict
core/analyze.py      pipeline, dashboard numbers, accuracy check against ground truth
core/db.py           SQLite storage (data/loglens.db)
static/              dashboard (HTML, CSS, JS - SVG charts, no external libraries)
tests/               unit tests: python -m unittest discover -s tests -v
RESEARCH.md          full research notes, method explanation, viva questions, references
```

## REST API

`GET /api/overview` `GET /api/alerts?severity=high&q=ssh` `GET /api/incidents` `GET /api/ips`
`GET /api/events?ip=1.2.3.4` `GET /api/blocklist` `POST /api/sample` `POST /api/upload` (multipart, field `files`)

## Using real data

* Any Apache/Nginx **combined** access log and any Linux `/var/log/auth.log` works as is.
* Public log datasets are listed in `RESEARCH.md` (Loghub, Kaggle web-server logs, etc.).
* Thresholds (window sizes, limits, ML contamination) are in one dictionary: `CFG` in `core/detector.py`.

## Safety note

Only analyse logs you own or have permission to use. The block commands are suggestions: read them before running.
