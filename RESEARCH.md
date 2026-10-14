# LogLens: Research Notes and Project Explanation

*Project topic: Cybersecurity Log Analysis and Intrusion Detection Dashboard (Log Analytics, Anomaly Detection)*
*Subject: Data Analysis and Visualization*

---

## 1. The project in simple words

Every server writes a diary of what happened: who visited which page, who tried to log in, who failed. This diary is called a **log**.
A busy server writes thousands of lines per hour, so no human can read them. Attackers hide inside that noise.

**LogLens** reads the logs, automatically finds the lines that look like an attack, and presents them as charts and
"stories" so a person can understand an incident in one minute.

Data-analysis view of the project (this is what the subject expects):

| Stage | In this project |
|---|---|
| 1. Collect data | Apache access log + SSH auth log (sample or uploaded) |
| 2. Clean / structure | `parser.py` turns messy text into a table: time, IP, user, URL, status, bytes |
| 3. Feature engineering | 8 numbers per IP (requests, peak/min, failed logins, error rate, timing regularity...) |
| 4. Analysis | rules, rolling statistics, Isolation Forest |
| 5. Visualisation | timeline, kill-chain ribbon, bar charts, tables |
| 6. Evaluation | precision / recall against known attackers |

---

## 2. Background you must know

**Log**: a timestamped record of an event. This project uses two types:
* *Web access log* (Apache/Nginx combined format): `IP - - [time] "GET /page HTTP/1.1" 200 5123 "referrer" "user-agent"`
* *SSH auth log* (Linux `/var/log/auth.log`): `Oct 13 09:45:25 srv sshd[6305]: Failed password for root from 1.2.3.4 port 5555 ssh2`

**IDS (Intrusion Detection System)**: software that raises an alert when it sees an attack. Types:
* *Signature-based*: matches known attack patterns (like antivirus). Accurate for known attacks, blind to new ones.
* *Anomaly-based*: learns what is normal and flags what is different. Can catch new attacks, but produces more false alarms.
* *Hybrid*: both. **LogLens is hybrid.**
* NIDS watches network packets, HIDS watches one host (its logs). LogLens is log-based, so it is HIDS-style.

**SIEM**: a product that collects logs from many systems and correlates them (Splunk, Elastic/ELK, Wazuh, IBM QRadar).
LogLens is a small teaching SIEM.

**False positive / false negative**: false positive = normal user flagged. False negative = attack missed. Detection design is always a trade-off between them.

---

## 3. Datasets (real ones you can mention or plug in)

| Dataset | What it is | Use |
|---|---|---|
| **Loghub** (Zhu et al., ISSRE 2023, github.com/logpai/loghub) | Collection of 19 real system log datasets (about 77 GB total), six of them labeled; includes Apache, SSH, HDFS, Linux and others | log parsing and anomaly detection research |
| **Loghub-2.0** | 14 larger datasets, about 3.6 million lines each on average | benchmark for log parsers |
| **CIC-IDS2017** (Canadian Institute for Cybersecurity) | labeled network flows with brute force, DoS, web attacks, infiltration | supervised IDS research |
| **UNSW-NB15** | labeled network traffic with 9 attack families | IDS research |
| **NSL-KDD** | classic cleaned benchmark (KDD'99 successor) | teaching, algorithm comparison |
| **Kaggle: "web server access logs"** | many ready Apache logs | plug into the Upload button |

LogLens reads the **Loghub SSH / Apache-style** formats directly. The built-in generator makes a dataset with *known* answers
(ground truth), which is what lets us compute accuracy honestly. Real public logs rarely come with the answer key.

---

## 4. Method: three detection layers

### Layer 1: Rules (known attacks)
| Rule | Logic | MITRE |
|---|---|---|
| SSH brute force | >= 8 failed logins from one IP inside a 5 min sliding window | T1110.001 |
| SSH compromise | successful login after >= 5 failures from same IP in prior 30 min | T1078 |
| Off-hours login | login 22:00-06:00 UTC from an IP never seen before | T1078 |
| Web scanner | >= 25 requests for 404/403 pages in 2 min, or scanner user-agent (sqlmap, nikto, nmap...) | T1595.002 |
| SQL injection | regex on the **URL-decoded** path: `UNION SELECT`, `' OR '1'='1`, `sleep(`, `information_schema`... | T1190 |
| XSS | `<script`, `onerror=`, `javascript:` | T1190 |
| Path traversal | `../`, `%2e%2e`, `/etc/passwd` | T1190 |
| Login brute force (web) | >= 10 rejected POST /login in 5 min | T1110.004 |
| HTTP flood | >= 300 requests/min from one IP | T1499.002 |
| Large download | one 2xx response >= 5 MB (normal page is under 0.1 MB) | T1213 |

Important detail: attackers encode payloads (`%27%20OR%20%271%27%3D%271`). The detector **decodes the URL twice** before matching.
The sliding-window function `_episodes()` merges overlapping windows so one attack gives one alert, not 200.

### Layer 2: Time-series spikes
For web requests per minute and failed SSH logins per minute, each minute is compared with the **previous 60 minutes**:

`z = (x - median) / (1.4826 * MAD + 1)` and an alert is raised if `z >= 6` and the volume passes a floor.

*Why median/MAD and not mean/standard deviation?* The attack itself would pull the mean up and hide itself. Median and
MAD (median absolute deviation) are **robust** to outliers. The constant 1.4826 makes MAD comparable to a standard deviation.

### Layer 3: Machine learning (Isolation Forest)
* Idea (Liu, Ting, Zhou, 2008): anomalies are few and different, so a random tree can **isolate** them with very few splits.
  Normal points need many splits. Score = how quickly a point is isolated.
* Input: one row per IP with 8 features.

| Feature | Why it matters |
|---|---|
| web requests | scanners/floods send many |
| peak requests/min | flood detection |
| distinct URLs | scanners touch many different paths |
| error rate (4xx/5xx share) | probing hits missing pages |
| failed logins | guessing |
| usernames tried (SSH) | spraying/enumeration |
| MB downloaded | exfiltration |
| robotic timing = 1/(1 + std/mean of gaps) | bots are too regular; humans are bursty |

* Output: score 0-100 per IP, plus **reasons**: robust z-score per feature (median/MAD over all IPs) and the top 3 unusual ones are printed
  as text, e.g. "165 failed logins (typical IP: 0)". This **explainability** matters: an analyst will not trust a black-box number.
* Double gate to reduce false alarms: the forest must flag the IP **and** at least one feature must be strongly unusual (z >= 3.5).
* Why ML at all? The *low-and-slow* attacker sends one wrong password every 88 seconds for hours. No window rule fires.
  Only the behavioural view (165 failures, 100% errors, one URL, perfectly regular timing) exposes it. In the tests this IP is found **only** by ML.

---

## 5. The unique feature: Attack Storyline Reconstruction

**Problem with normal dashboards.** They show a flat list: "SSH brute force", "404 flood", "large download".
The analyst must work out in their head that these are one attacker and that the attack *worked*.

**What LogLens does** (`core/storyline.py`):
1. Groups alerts by source IP.
2. Orders them in time and places each on a **6-stage kill chain**:
   Reconnaissance, Access attempts, Exploitation, Compromise, Data theft, Disruption
   (a simplified form of the Lockheed Martin Cyber Kill Chain and the MITRE ATT&CK tactics).
3. Writes a plain-English story with the time gap between steps ("+9 min later").
4. Gives a **verdict**: *Likely compromised* (login success or big download), *Suspicious access*, *Service attack*,
   *Attack in progress*, *Attempt, no breach seen*, or *Unusual, needs a look*. This answers the question every analyst asks first: **did it work?**
5. **Predicts the next move** from the furthest stage reached (e.g. after a successful login: expect data staging and download).
6. Computes a **risk score** (0-100): severity weights per distinct rule + bonus for each extra stage + ML score.
7. Generates the **response**: actions per stage and ready firewall commands (ufw / iptables / fail2ban / lock account).

Demo story (attacker `185.220.101.45`): scans the website for hidden files, 10 minutes later starts SSH password guessing
(260 tries, 16 usernames), 9 minutes later logs in as `admin`, 2 minutes later downloads 80 MB. The ribbon lights up
Reconnaissance, Access attempts, Compromise, Data theft. Verdict: Likely compromised. Risk 100.

**How it differs from existing tools.** Fail2ban blocks by one rule. ELK/Splunk dashboards show counts and charts and leave correlation
to the analyst. Open-source log analysers on GitHub map findings to MITRE (also done here) but typically present them as a per-detection list.
LogLens's contribution is the *narrative layer*: correlation across **two log sources** (web + SSH) into a single timeline, a success/failure verdict
and a predicted next step. This is a student-scale project, not a replacement for a commercial SIEM; say that in the viva.

---

## 6. Architecture

```
 access.log ─┐                                         ┌── /api/overview ──┐
             ├─> parser ─> events ─> detector ─> alerts ─> storyline ─> incidents ─> SQLite ─┤── /api/incidents ├─> Dashboard (SVG charts)
 auth.log ───┘   (common    (SQLite)  rules                                                  └── /api/alerts ───┘
                  format)             time-series
                                      Isolation Forest
```

Tech: Python 3, Flask (REST API), scikit-learn (Isolation Forest), SQLite, plain JavaScript + SVG (no chart library, works offline).

---

## 7. Results (on the generated dataset)

7 attackers of 7 different kinds hidden among about 60 normal IPs, 8,000+ log lines:

| Attacker behaviour | Found by |
|---|---|
| Full chain (scan, brute force, login, exfiltration) | rules + ML |
| SQL injection (sqlmap) | rules + ML |
| XSS + path traversal | rules + ML |
| Nikto scan | rules + ML |
| HTTP flood | rules + time-series + ML |
| Low-and-slow credential stuffing | **ML only** |
| Off-hours login from new IP | rule |

Tested on 10 different random seeds: **recall 100%, precision 100%** (0 false alarms) in all runs (`tests/test_pipeline.py`).

**Honest limitations (write these in your report, examiners like them):**
* The data is synthetic. The attackers were written by us, so 100% is expected; real logs will give lower numbers.
* Detection is per IP. Attackers behind NAT, Tor or many rotating IPs can be mixed up or split.
* Thresholds are hand-set in `CFG`; a real deployment would tune them per site.
* Only two log sources. Real systems also use firewall, DNS, Windows event and application logs.
* Isolation Forest is unsupervised, so it cannot say *what* the attack is, only that it is unusual (rules and the reasons text fill that gap).

**Future work:** GeoIP map and threat-intel lookups (AbuseIPDB), more log types (Windows Event, firewall), email/Telegram alerts,
LSTM/DeepLog sequence models for application logs, real-time tailing of log files, Sigma rule export.

---

## 8. Viva questions with short answers

1. **What is a log and why analyse it?** A timestamped record of events; it is the only evidence of what happened on a server.
2. **Signature vs anomaly detection?** Signature = known patterns, accurate but blind to new attacks. Anomaly = learns normal, catches new things, more false alarms. We use both.
3. **Why Isolation Forest?** Unsupervised (no labelled attack data needed), fast, handles several features, anomalies are isolated in few splits.
4. **Why median/MAD instead of mean/std?** Attacks inflate the mean and std and hide themselves; median/MAD are robust.
5. **How do you reduce false positives?** Double gate (model flag and strong feature), URL decoding, thresholds with minimum volume, and a verdict that separates attempts from breaches.
6. **What does MITRE ATT&CK give you?** A common language: each alert is tied to a tactic and technique ID, so it can be looked up and compared.
7. **What is new in your project?** The storyline layer: correlation of web and SSH alerts into one timeline per attacker with verdict, next-move prediction and response commands.
8. **How do you know it works?** Ground truth from the generator: precision, recall and F1, repeated over several seeds, plus unit tests. Limitation: synthetic data.
9. **Which attack is only found by ML and why?** Low-and-slow stuffing, because it stays below every rate threshold but looks abnormal in total behaviour.
10. **Can it run on real logs?** Yes, upload any Apache/Nginx combined and OpenSSH auth logs.

---

## 9. Suggested report / PPT outline

1. Introduction and problem statement
2. Literature survey (IDS types, SIEM, Isolation Forest, MITRE ATT&CK, datasets)
3. Requirements and tools
4. System design (architecture, data flow, API)
5. Implementation (parser, 3 detection layers, storyline)
6. Visualisations and screenshots (timeline, kill-chain ribbon, tables)
7. Results and evaluation (table above, confusion numbers)
8. Limitations and future scope
9. Conclusion
10. References

---

## 10. References

* J. Zhu, S. He, P. He, J. Liu, M. R. Lyu. *Loghub: A Large Collection of System Log Datasets for AI-driven Log Analytics.* IEEE ISSRE, 2023. https://github.com/logpai/loghub
* F. T. Liu, K. M. Ting, Z.-H. Zhou. *Isolation Forest.* IEEE ICDM, 2008.
* MITRE ATT&CK knowledge base. https://attack.mitre.org
* E. M. Hutchins, M. J. Cloppert, R. M. Amin. *Intelligence-Driven Computer Network Defense Informed by Analysis of Adversary Campaigns and Intrusion Kill Chains.* Lockheed Martin, 2011.
* I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani. *Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization* (CIC-IDS2017). ICISSP, 2018.
* N. Moustafa, J. Slay. *UNSW-NB15: a comprehensive data set for network intrusion detection systems.* MilCIS, 2015.
* M. Tavallaee et al. *A detailed analysis of the KDD CUP 99 data set* (NSL-KDD). IEEE CISDA, 2009.
* OWASP Top 10 and OWASP Core Rule Set (injection, XSS, traversal patterns).
