# Public WiFi Risk Detector & DFIR Platform 🛡️📡

An active wireless threat detection engine and research-grade **Digital Forensics & Incident Response (DFIR)** platform designed for SOC analysts, incident responders, and network security researchers.

The platform continuously monitors wireless interfaces for threats, collects volatile forensic snapshots per **RFC 3227**, manages investigative cases with a **cryptographic hash-chained chain of custody ledger**, maps telemetry to **MITRE ATT&CK®**, correlates multi-stage attacks, exports threat intelligence in **STIX 2.1**, and generates **self-verifying forensic investigation reports**.

---

## 🚀 Key Capabilities

### 1. Wireless Detection Engine
*   **Dual Mode Architecture**:
    *   🟢 **Live Detection Layer**: Real-time passive packet sniffing, ARP verification, TLS canary probing, and DNS cross-validation calculating an objective `live_risk_score` (0–100).
    *   🟡 **Educational / Simulation Mode**: Injects reproducible threat scenarios (`evil_twin`, `arp_spoof`, `dns_spoof`, `ssl_strip`, `deauth_flood`, `rogue_dhcp`) without interrupting live background sensors.
*   **Active Threat Checks**:
    *   **Open Network (+40 Risk)**: Detects unencrypted 802.11 associations.
    *   **Evil Twin (+35 Risk)**: Scans for duplicate SSIDs across disparate BSSIDs and signal disparities without requiring monitor mode.
    *   **ARP Poisoning / MITM (+50 Risk)**: Real-time Scapy ARP packet sniffing with gateway MAC baseline drift detection.
    *   **DNS Hijacking & Spoofing (+30 Risk)**: High-speed DNS probe cross-referenced with encrypted DNS-over-HTTPS (DoH) trusted resolvers.
    *   **SSL Stripping & Captive Portals (+40 Risk)**: Probes TLS canary endpoints, detects cleartext redirects and certificate fingerprint anomalies.
    *   **Deauthentication Flooding (+75 Risk)**: Detects 802.11 management frame floods (`T1498.001`) via sliding-window burst counters.
    *   **Rogue DHCP Servers (+65 Risk)**: Identifies unauthorized DHCP OFFERs and rogue gateway assignments (`T1557`).

### 2. DFIR & Forensic Investigation Layer
*   **Case Management & Scope Enforcement**:
    *   Mandatory warrant/authorization tracking (`authorization_ref`), examiner signoff, and immutable case states (`OPEN` $\to$ `FROZEN` $\to$ `CLOSED`).
*   **RFC 3227 Chain of Custody**:
    *   Sequential block ledger linking every evidence ingestion and action with `prev_hash` $\to$ `entry_hash` (SHA-256).
    *   Cryptographic tamper detection (`verify_custody_chain`) detects any post-facto ledger alteration.
    *   Strict order-of-volatility live snapshot collector (registers, ARP tables, routing entries, interface statistics).
*   **Evidence & PCAP Processing**:
    *   Dual-hash ingest (SHA-256 + MD5) on all uploaded or captured artifacts.
    *   Automatic PII & cleartext credential redaction for sensitive forensic captures.
    *   Streaming PCAP reader parsing and Airodump-NG CSV ingestion.
*   **Unified Events & Live Triage**:
    *   Standardized event schema with Server-Sent Events (SSE) live streaming (`/api/stream`).
    *   Event deduplication and watermarking for synthetic training data (`synthetic=true`).
*   **Threat Intel & MITRE ATT&CK®**:
    *   OUI hardware vendor resolution via IEEE registry lookups.
    *   Interactive ATT&CK Matrix navigator with confidence-rated tactic and technique coverage.
    *   Automated IOC mining (MACs, IPs, SSIDs, BSSIDs) and STIX 2.1 Threat Report bundle exporter.
*   **Automated Multi-Stage Attack Correlation**:
    *   Rule 1: *Deauth $\to$ Evil Twin Reconnection* (Credential Phishing).
    *   Rule 2: *ARP Poisoning $\to$ DNS Hijack / TLS Downgrade* (Active Traffic Interception).
    *   Rule 3: *Rogue DHCP Offer $\to$ Captive Portal Harvest* (Rogue Infrastructure).
*   **Self-Verifying Forensic Reports**:
    *   One-click HTML report generation complete with executive summary, evidence catalog, custody ledger, findings matrix, and containment signoff.
    *   Document integrity anchored to the case custody ledger with SHA-256 verification.

---

## 📁 Repository Structure

```
public-wifi-risk-detector/
├── backend/
│   ├── app.py                  # Flask API server, SSE streaming & REST routes
│   ├── detector.py             # Active/passive WiFi sensor & scenario engine
│   ├── capture_analyzer.py     # Live Scapy sniffer & PCAP stream analyzer
│   ├── cases.py                # Case lifecycle, scoping & state transitions
│   ├── custody.py              # RFC 3227 custody ledger & SHA-256 verification
│   ├── events.py               # Unified forensic telemetry & SSE pub/sub
│   ├── enrichment.py           # OUI, DoH, TLS canary & deauth baseline sensors
│   ├── collectors.py           # RFC 3227 volatile system snapshot collector
│   ├── timeline.py             # Super-timeline generation & analyst notes
│   ├── intel.py                # MITRE ATT&CK mapper, IOC miner & STIX 2.1 exporter
│   ├── reporter.py             # Forensic report generator & verification
│   ├── notifier.py             # Desktop (plyer) & webhook alerting
│   ├── db.py                   # SQLite WAL database & migration manager
│   ├── data/
│   │   ├── attack_map.json     # Curated MITRE ATT&CK mapping definitions
│   │   └── oui.txt             # IEEE OUI hardware vendor database
│   ├── tests/                  # Pytest test suite (31/31 unit & integration tests)
│   └── requirements.txt        # Python dependency manifest
├── frontend/
│   ├── src/
│   │   ├── components/         # Modular DFIR React components
│   │   │   ├── CaseBar.jsx     # Active case indicator & freeze controls
│   │   │   ├── NewCaseModal.jsx# Case creation with warrant reference
│   │   │   ├── LiveTriage.jsx  # Real-time SSE telemetry & quick filter
│   │   │   ├── TimelineView.jsx# Interactive chronological super-timeline
│   │   │   ├── EvidencePanel.jsx# Custody ledger & artifact vault
│   │   │   ├── IocTable.jsx    # Mined IOCs & STIX 2.1 download
│   │   │   ├── AttackMatrix.jsx# MITRE ATT&CK matrix coverage
│   │   │   └── ReportsPanel.jsx# Forensic report generation & preview
│   │   ├── App.jsx             # Main dashboard & tab routing
│   │   └── index.css           # Custom dark glassmorphic styling
│   └── package.json            # Node.js manifest
├── DFIR_METHODOLOGY.md         # Comprehensive DFIR technical methodology guide
└── LAB_GUIDE.md                # Attack scenario setup & Kali lab instructions
```

---

## 🛠️ Prerequisites & Installation

### Requirements
*   **Python**: Version $\ge$ 3.9
*   **Node.js**: Version $\ge$ 18
*   **Npcap / Libpcap**: [Npcap](https://npcap.com/) on Windows (install with WinPcap API-compatible mode).

### 1. Backend Setup
```bash
cd backend
pip install -r requirements.txt
python app.py
```
*On first startup, the backend generates an API token in `backend/.env` and prints it to the console.*

### 2. Frontend Setup
```bash
cd frontend
npm install
```
Create `frontend/.env`:
```env
VITE_API_TOKEN=your-generated-token-here
```
Start the frontend development server:
```bash
npm run dev
```
Open **`http://localhost:5173`** in your browser.

---

## 🧪 Automated Testing

The repository includes a comprehensive 31-test suite validating all 7 phases:
```bash
pytest backend/tests -v
```

---

## 📖 Documentation

*   [DFIR_METHODOLOGY.md](DFIR_METHODOLOGY.md) — Comprehensive technical guide detailing the evidentiary chain of custody, RFC 3227 order of volatility, MITRE ATT&CK mapping, and reporting defensibility.
*   [LAB_GUIDE.md](LAB_GUIDE.md) — Step-by-step instructions for recreating realistic Wi-Fi attack scenarios (Evil Twin, Deauth Flooding, Rogue DHCP, ARP Spoofing) using Kali Linux tools in an isolated sandbox.

---

## ⚠️ Academic & Legal Disclaimer

All experiments, scans, and simulated attacks must be conducted strictly within an **authorized, isolated lab environment** using networks and devices owned by the researcher or with explicit written legal authorization. Unauthorized packet capturing, radio jamming, or wireless disruption is illegal. This software is engineered strictly for **defensive digital forensics, incident response research, and network security education**.
