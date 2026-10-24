# Public WiFi Risk Detector — Lab Setup Guide 🧪

This guide covers the full stack: real detection (Live Mode) + educational simulations (Simulation Mode).

---

## 1. Prerequisites

### All Platforms
- Python ≥ 3.9 and Node.js ≥ 18
- Install Python dependencies: `pip install -r backend/requirements.txt`
- Install frontend dependencies: `cd frontend && npm install`

### Windows
- [Npcap](https://npcap.com/) — required for Scapy ARP scanning
- Run backend **as Administrator** for ARP live-sniff (`sniff()`)
  > Without admin rights, the detector falls back to polling-based ARP checks automatically.

### Linux
- `iproute2` / `iw` / `nmcli` (usually pre-installed)
- Run with `sudo` for Scapy ARP sniffing, or grant cap_net_raw: `sudo setcap cap_net_raw+eip $(which python3)`

### macOS
- `airport` utility (included in macOS)
- Run with `sudo` for Scapy sniffing

---

## 2. Running the Project

### Step 1 — Backend

```bash
cd backend
python app.py
```

On first run it will **auto-generate an API token** and print it:
```
Generated new API token: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
Saved to backend/.env
Set VITE_API_TOKEN=<token> in frontend/.env
```

### Step 2 — Frontend

Create `frontend/.env` with the token from above:
```
VITE_API_TOKEN=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Then start the dev server:
```bash
cd frontend
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## 3. Understanding the Two Modes

| | **Live Detection Mode** | **Simulation Mode** |
|---|---|---|
| **What runs** | Real network checks | Demo overlay only |
| **Alerts** | Actual anomalies found | Educational examples |
| **Risk score** | `live_risk_score` | `sim_risk_score` |
| **UI indicator** | 🟢 Green banner | 🟡 Amber dashed banner |
| **Use case** | Real network monitoring | Teaching / demo |

> **Key difference from the original design:** Real checks and simulations run in **separate layers**. Activating a scenario does NOT disable live detection. Both scores are tracked independently.

---

## 4. Live Detection Checks

### Check 1 — Open Network (+40)
Detects when the connected network has no encryption (Open/None).

**Lab setup**: Set your router/hotspot to Open (no security). The backend will detect it automatically without any simulation.

### Check 2 — Evil Twin (+35)
Passive scan of nearby APs. Flags when multiple BSSIDs advertise the same SSID as your connected network.

**Lab setup** (Kali Linux):
```bash
airgeddon   # or
wifiphisher --essid "YourNetworkSSID"
```
Detection uses `netsh wlan show networks mode=bssid` (Windows) or `nmcli dev wifi list` (Linux/macOS) — **no monitor mode required**.

### Check 3 — ARP Spoofing / MITM (+50)
- **Primary**: Scapy live ARP sniff — tracks every IP→MAC mapping on the wire; flags any MAC change for a known IP.
- **Fallback**: Polling-based gateway MAC comparison every 3 s.

**Lab setup** (Kali Linux):
```bash
sudo arpspoof -i eth0 -t <Host_IP> <Gateway_IP>
sudo arpspoof -i eth0 -t <Gateway_IP> <Host_IP>
```

### Check 4 — DNS Spoofing (+30)
Resolves `google.com` and `cloudflare.com` every ~30 seconds. Compares against known-good IP CIDR ranges (Google AS, Cloudflare AS). Flags IPs outside these ranges.

**Lab setup** (requires control of DNS server):
```bash
# On attacker machine, run dnsspoof or use dnsmasq with spoofed entries
dnsspoof -i eth0 -f /tmp/hosts.txt
```

### Check 5 — SSL Stripping / Captive Portal (+40)
Makes an HTTPS request to Google's `generate_204` endpoint. Flags:
- Redirect to HTTP → SSL stripping
- Non-204 response → captive portal
- TLS error → self-signed cert or MITM

**Lab setup**:
```bash
# Using sslstrip on attacker machine:
sslstrip -l 8080
iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 8080
```

---

## 5. Simulation Scenarios (Lab Demonstrations)

> [!WARNING]
> Simulation mode injects **educational demo data only**. Alerts tagged `[SIM]` are NOT real detections. The UI shows a clear amber banner while a simulation is active.

Access the **🧪 Lab Simulation Panel** at the bottom of the dashboard.

| Scenario | What it teaches |
|---|---|
| **Open WiFi** | Impact of unencrypted networks |
| **Evil Twin AP** | Rogue AP / BSSID spoofing |
| **ARP Spoof/MITM** | Gateway MAC hijacking |
| **DNS Spoof** | Rogue DNS resolver attack |
| **SSL Strip** | HTTPS downgrade attack |
| **Deauth Flood** | 802.11 management frame deauthentication burst (+75 Risk, MITRE T1498.001) |
| **Rogue DHCP** | Rogue DHCP server offering unauthorized gateway lease (+65 Risk, MITRE T1557) |

To trigger programmatically (requires the API token in the `X-API-Token` header):
```bash
curl -X POST http://localhost:5000/api/scenario \
  -H "Content-Type: application/json" \
  -H "X-API-Token: YOUR_TOKEN_HERE" \
  -d '{"scenario": "deauth_flood"}'
```

### Real Lab Setups for Advanced Scenarios (Kali Linux)

#### Scenario A — Deauthentication Flood (`T1498.001`)
Put your wireless interface in monitor mode:
```bash
sudo airmon-ng start wlan0
sudo aireplay-ng --deauth 50 -a <Target_AP_BSSID> -c <Target_Client_MAC> wlan0mon
```
*Detector response*: Flags sliding-window management frame anomaly, classifies vendor of spoofed sender, and creates an alert event in the Live Triage feed.

#### Scenario B — Rogue DHCP Server (`T1557`)
Spin up an unauthorized DHCP server on the same subnet:
```bash
sudo dnsmasq -d -C rogue_dhcp.conf --dhcp-range=192.168.1.100,192.168.1.150,255.255.255.0,1h --dhcp-option=3,192.168.1.254
```
*Detector response*: Compares the offering DHCP server IP against the discovered gateway baseline, flagging any unauthorized DHCP server as a rogue infrastructure threat.

---

## 6. DFIR Case Investigation Workflow

1. **Initialize Case**:
   - Navigate to the UI and click **+ New Case**.
   - Input the **Title**, **Lead Examiner Name**, and **Authorization / Warrant Reference** (e.g. `CASE-2026-WIFI-001`).
   - Check the **Synthetic / Training Environment** toggle if conducting simulation drills.
2. **Review Live Triage & Super-Timeline**:
   - Observe live incoming events over the SSE stream (`/api/stream`).
   - Expand any event drawer to inspect raw telemetry, packet decodes, and evidentiary rationale.
   - Annotate key investigative moments in the **Timeline** tab.
3. **Artifact Registration & Chain of Custody**:
   - In the **Evidence & Custody** tab, upload captured PCAPs or airodump-ng CSVs.
   - Each artifact is immediately stamped with **Dual Cryptographic Hashes** (SHA-256 and MD5) and recorded into the sequential custody ledger.
   - Click **Verify Integrity** to run the cryptographic tamper detection audit.
4. **MITRE ATT&CK® & Threat Intelligence**:
   - Switch to the **ATT&CK Matrix** tab to visualize covered attack techniques and tactic progression.
   - Review the **IOCs** tab to examine mined MAC addresses, BSSIDs, rogue IPs, and export a standardized **STIX 2.1 Threat Report**.
5. **Generate Self-Verifying Forensic Incident Report**:
   - Navigate to the **Reports** tab and click **Generate Forensic Report**.
   - Inspect the compiled HTML investigation report containing the executive summary, evidence catalog, custody ledger, and mitigation actions.
   - Download the verified `.html` report file.
6. **Freeze Case**:
   - In the top `CaseBar`, click **Freeze Case**. The case transitions to `FROZEN`, locking all evidence and ledger logs against modifications for court defensibility.

---

## 7. SQLite History & API

Risk events are logged to `backend/risk_history.db` every ~15 seconds.

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/status` | GET | Live status, check results, sim state |
| `GET /api/history?limit=100` | GET | Last N risk events from SQLite |
| `GET /api/stats` | GET | 24-hour aggregate (max, avg, high-risk count) |
| `GET /api/config` | GET | Current notification / sniff config |
| `POST /api/config` | POST | Update webhook URL, notification interval *(token required)* |
| `POST /api/scenario` | POST | Trigger or reset a simulation scenario *(token required)* |
| `GET /api/cases` | GET | List all investigative cases |
| `POST /api/cases` | POST | Create new case with warrant ref *(token required)* |
| `GET /api/cases/<id>/custody` | GET | Retrieve hash-chained custody ledger |
| `GET /api/cases/<id>/custody/verify` | GET | Cryptographic ledger tamper verification |
| `POST /api/cases/<id>/evidence` | POST | Ingest artifact with dual hashing *(token required)* |
| `GET /api/cases/<id>/reports` | GET | List generated forensic reports |
| `POST /api/cases/<id>/reports` | POST | Generate self-verifying report *(token required)* |
| `GET /api/reports/<id>/download` | GET | Download signed HTML report |
| `GET /api/cases/<id>/stix2` | GET | Export STIX 2.1 Threat Report bundle |

---

## 8. Real Alerting

### Desktop Notifications
Fires automatically when risk crosses a threshold zone (30, 60, 90) or jumps ≥10 points. Powered by `plyer` — no configuration needed.

### Webhook (Discord / Slack / Custom)
Set your webhook URL via the API:
```bash
curl -X POST http://localhost:5000/api/config \
  -H "X-API-Token: YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"webhook_url": "https://discord.com/api/webhooks/..."}'
```

Or set the environment variable before starting the backend:
```bash
ALERT_WEBHOOK_URL=https://... python app.py
```

---

## 9. Academic Disclaimer

All experiments must be conducted in an **isolated lab environment** using networks and devices you own or have explicit permission to test. Unauthorized network access is illegal and unethical. This tool is built for **detection education, incident response training, and network forensics research** only.

