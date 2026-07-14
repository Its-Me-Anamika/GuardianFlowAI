# GuardianFlow AI

**AI-Powered Distributed Cybersecurity Monitoring System (MVP)**
A final-year vocational training capstone project.

## 1. Project Overview

GuardianFlow AI is a lightweight, distributed cybersecurity monitoring
system built for academic demonstration. One **server** laptop receives
real-time system telemetry from **two client** laptops over the same
Wi-Fi network. The server:

1. Detects suspicious activity using an **unsupervised Isolation
   Forest** ML model (scikit-learn) — no rule-based hardcoding.
2. Uses a simple **RAG (Retrieval-Augmented Generation)** pipeline to
   ground AI-generated threat explanations in specific incident
   response playbooks, calling the **Google Gemini API**.
3. Generates a **SHA-256 forensic hash** of every threat report to
   prove it was produced by the system at that exact moment.
4. Displays everything on a live, auto-refreshing **web dashboard**.

## 2. Architecture Diagram (ASCII)

```
                        Wi-Fi LAN (same network)
        +------------------+        +------------------+
        |  Client Laptop 2 |        |  Client Laptop 3  |
        |  client.py       |        |  client.py        |
        |  system_monitor  |        |  system_monitor   |
        |  attack_simulator|        |  attack_simulator |
        +---------+--------+        +---------+---------+
                  |  HTTP POST JSON            |  HTTP POST JSON
                  |  (/logs every 5s)          |
                  v                            v
        +-------------------------------------------------+
        |               SERVER LAPTOP 1                    |
        |  Flask app (server.py)                           |
        |    -> storage.py     (CSV logging, dedupe)        |
        |    -> detector.py    (Isolation Forest)            |
        |    -> ai_engine.py   (RAG + Gemini explanation)    |
        |    -> crypto_utils.py(SHA-256 forensic hash)       |
        |                                                    |
        |  Dashboard (templates/index.html + static JS/CSS)  |
        |    -> polls /api/dashboard-data every 5s (fetch)   |
        +-------------------------------------------------+
                          ^
                          |  Browser (http://<server-ip>:5000)
                   +------+------+
                   |   You (PM)   |
                   +-------------+
```

## 3. Folder Structure

```
GuardianFlowAI/
├── server/
│   ├── server.py            # Flask app, routes, orchestration
│   ├── detector.py          # Isolation Forest detection engine
│   ├── ai_engine.py         # RAG + Gemini explanation engine
│   ├── storage.py           # CSV log storage & queries
│   ├── crypto_utils.py      # SHA-256 forensic hashing
│   └── generate_data.py     # Synthetic training data generator
├── client/
│   ├── client.py            # Main client loop (sends logs every 5s)
│   ├── attack_simulator.py  # Simulated attack signatures
│   └── system_monitor.py    # psutil-based telemetry collection
├── dashboard/
│   ├── templates/index.html
│   └── static/{style.css, script.js}
├── playbooks/
│   ├── cryptomining.txt
│   ├── bruteforce.txt
│   └── ddos.txt
├── logs/
│   ├── received_logs.csv    # Created automatically at runtime
│   └── training_data.csv    # Created by generate_data.py
├── requirements.txt
└── README.md
```

## 4. Installation

**Prerequisites:** Python 3.11, VS Code, all three laptops on the same
Wi-Fi network.

On **all three** laptops:

```powershell
git clone <this-repo>   # or copy the GuardianFlowAI folder via USB
cd GuardianFlowAI
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

On the **server laptop only**, set your Gemini API key:

```powershell
$env:GEMINI_API_KEY="your_key_here"
```

## 5. Execution Steps

**Step 1 — Server laptop:** generate synthetic training data (once):
```powershell
python server/generate_data.py
```

**Step 2 — Server laptop:** find its LAN IP address:
```powershell
ipconfig
```
Note the IPv4 address (e.g., `192.168.1.10`).

**Step 3 — Server laptop:** start the server:
```powershell
python server/server.py
```
The dashboard is now live at `http://<server-ip>:5000` (open in a
browser on any device on the same Wi-Fi network).

**Step 4 — Client laptops:** edit `client/client.py` and set:
```python
SERVER_IP = "192.168.1.10"   # the server's actual IP from Step 2
CLIENT_NAME = "Client-Laptop-2"   # unique per machine
```

**Step 5 — Client laptops:** run the client:
```powershell
python client/client.py
```
Choose mode `1` (auto-send normal telemetry) or `2` (interactive
attack simulation menu).

## 6. Demo Procedure

1. Start the server, confirm the dashboard loads and shows "Connected".
2. Start both clients in Normal mode — watch CPU/RAM/logs populate
   live on the dashboard within ~5-10 seconds.
3. On one client, switch to Interactive mode (`2`) and choose an
   attack scenario (e.g., Cryptomining).
4. Observe the dashboard: a new Threat Card appears with the AI-
   generated explanation (grounded in the matching playbook) and its
   SHA-256 forensic hash.
5. Repeat with Brute Force and DDoS scenarios to show playbook-specific
   grounding differs per threat type.
6. Optionally demonstrate error handling by stopping the server while
   a client is running — the client will log retry attempts and
   recover automatically once the server restarts.

## 7. Future Improvements

- Persist historical anomaly scores to visualize trends over time.
- Add authentication between clients and server (API keys/tokens).
- Expand the Isolation Forest feature set with more telemetry signals.
- Add a proper database (SQLite) instead of flat CSV for larger scale.
- Support alerting via email/SMS for Critical-severity threats.
- Containerize for easier multi-machine deployment (future scope).

## 8. Screenshots

*(Insert dashboard screenshots here after running the demo)*

- `screenshots/dashboard-overview.png`
- `screenshots/threat-card-example.png`
- `screenshots/client-terminal.png`
