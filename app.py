"""LogLens - Cybersecurity Log Analysis & Intrusion Detection Dashboard (Flask backend).

Run:   pip install -r requirements.txt
       python app.py          ->  open http://127.0.0.1:5000
"""
import json
import os
import random

from flask import Flask, jsonify, request, send_from_directory, Response

from core import db
from core.analyze import analyze
from core.generator import generate
from core.parser import parse_lines, parse_file

BASE = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(BASE, "data")
app = Flask(__name__, static_folder="static", static_url_path="")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB upload limit


def load_sample(seed=None):
    seed = seed if seed is not None else random.randint(1, 10_000)
    generate(DATA, seed=seed)
    events, skipped = [], 0
    for name in ("access.log", "auth.log"):
        ev, sk = parse_file(os.path.join(DATA, name))
        events += ev
        skipped += sk
    events.sort(key=lambda e: e["epoch"])
    with open(os.path.join(DATA, "ground_truth.json")) as f:
        truth = json.load(f)
    result = analyze(events, truth, skipped)
    result["summary"]["source"] = f"sample data (seed {seed})"
    db.save(events, result)
    return result


def current():
    r = db.load_result()
    return r if r else load_sample(7)


@app.route("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/overview")
def overview():
    r = current()
    return jsonify({k: r[k] for k in ("summary", "timeline", "tactics", "stage_counts", "top_users", "top_errors", "evaluation")})


@app.get("/api/alerts")
def alerts():
    r = current()
    out = r["alerts"]
    sev, ip, q = request.args.get("severity"), request.args.get("ip"), (request.args.get("q") or "").lower()
    if sev:
        out = [a for a in out if a["severity"] == sev]
    if ip:
        out = [a for a in out if a["ip"] == ip]
    if q:
        out = [a for a in out if q in json.dumps(a).lower()]
    return jsonify(out)


@app.get("/api/incidents")
def incidents():
    return jsonify(current()["incidents"])


@app.get("/api/ips")
def ips():
    return jsonify(current()["ips"])


@app.get("/api/events")
def events():
    return jsonify(db.events_for(request.args.get("ip"), min(int(request.args.get("limit", 300)), 2000)))


@app.get("/api/blocklist")
def blocklist():
    lines = ["# LogLens blocklist - review before running!"]
    for i in current()["incidents"]:
        if i["risk"] >= 30:
            lines.append(f"# risk {i['risk']} - {i['verdict']} - {i['chain']}")
            lines += i["block"][:2]
    return Response("\n".join(lines) + "\n", mimetype="text/plain",
                    headers={"Content-Disposition": "attachment; filename=blocklist.sh"})


@app.post("/api/sample")
def sample():
    return jsonify(load_sample()["summary"])


@app.post("/api/upload")
def upload():
    files = request.files.getlist("files")
    if not files:
        return jsonify({"error": "No files received"}), 400
    events, skipped = [], 0
    for f in files:
        ev, sk = parse_lines(f.stream.read().decode("utf-8", "replace").splitlines())
        events += ev
        skipped += sk
    if not events:
        return jsonify({"error": "No recognisable log lines. Use Apache/Nginx combined access logs or OpenSSH auth.log."}), 400
    events.sort(key=lambda e: e["epoch"])
    result = analyze(events, None, skipped)
    result["summary"]["source"] = "uploaded: " + ", ".join(f.filename for f in files)
    db.save(events, result)
    return jsonify(result["summary"])


if __name__ == "__main__":
    db.init()
    if not db.load_result():
        load_sample(7)
    print("\n  LogLens running -> http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
