# Digital Forensics & Incident Response (DFIR) Methodology & Standard Operating Procedures

**Document Version:** 2.0.0-dfir  
**Standard:** Wireless Incident Response, Triage, and Evidentiary Integrity Standard  
**Compliance Target:** RFC 3227 (Order of Volatility), NIST SP 800-86, ISO/IEC 27037  

---

## 1. Executive Overview

The **Public WiFi Risk Detector DFIR Platform** provides a research-grade wireless threat detection, live triage, and forensic analysis framework. The architecture is engineered to ensure **defensibility**, **reproducibility**, **cryptographic integrity**, and strict **chain of custody** adherence across all wireless artifacts.

---

## 2. Core Forensic Principles

### Principle 1: Evidence Integrity via Dual Ingest Hashing
- Every external artifact (Wireshark `.pcap`, Airodump `.csv`, or live memory snapshot `.json`) is hashed immediately upon ingest using **SHA-256** and **MD5**.
- Original artifacts are stored in an immutable, read-only evidence store (`backend/evidence_store/`).
- Parsing and deep packet inspection operate exclusively on derived, in-memory structures or streaming iterators (`scapy.PcapReader`), never modifying raw evidence files.

### Principle 2: Cryptographic Append-Only Chain of Custody
- The ledger employs sequential block hash chaining:
  $$\text{entry\_hash} = \text{SHA256}(\text{prev\_hash} \,\|\, \text{ts\_utc} \,\|\, \text{actor} \,\|\, \text{action} \,\|\, \text{artifact\_hash} \,\|\, \text{details\_json} \,\|\, \text{tool\_version})$$
- The initial ledger entry links directly to the `GENESIS_HASH`.
- An automated verification engine (`verify_custody_chain`) re-evaluates all sequential links and compares byte-level hashes of on-disk evidence files to detect tampering, deletion, or bit-rot immediately.

### Principle 3: Order of Volatility (RFC 3227)
Live triage collection captures telemetry in order of volatility from most transient to least transient:
1. **Host Clock & NTP Offset:** Measurement of time drift relative to public NTP sources (drift $>2.0\text{s}$ triggers an evidentiary caveat flag).
2. **ARP Resolution Cache:** Volatile kernel mappings between IP addresses and MAC hardware interfaces.
3. **IP Routing Table:** Active default gateway entries and network subnet interfaces.
4. **DNS Resolver Cache:** Cached hostname lookups and DNS Canary responses.
5. **Active Network Sockets (Netstat / Psutil):** Established TCP/UDP connections, listening daemon ports, and process bindings.
6. **WLAN Interface State & BSSID Survey:** Signal strength (RSSI), channel allocations, radio bands, and encryption parameters.
7. **DHCP Lease Metadata:** Current lease expiration, server identifier, and gateway options.
8. **Non-Volatile Disk Captures:** Retained PCAP / CSV files.

### Principle 4: Defensible Finding Attribution
- Every emitted finding is stored in the unified `events` table with an explicit source reference (`raw_ref`), associating each finding with an evidence ID, packet sequence number, or CLI command output.
- Every finding is classified by **Severity** (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`) and **Forensic Confidence** ($0.0 \text{ to } 1.0$), paired with false-positive operational notes.

### Principle 5: Synthetic Training Isolation
- Laboratory simulations (Open WiFi, Evil Twin AP, ARP Spoof, DNS Spoof, SSL Strip, Deauth Flood, Rogue DHCP) are watermarked `synthetic=true`.
- Synthetic events are tagged `[SYNTHETIC / TRAINING]` in the UI and are strictly excluded from real-case statistics, forensic timelines, and courtroom reports.

### Principle 6: Legal Authority & Redaction
- Prior to creating an investigation case, lead examiners must record an official authorization reference (warrant ID, ticket number, or engagement authorization) and confirm legal compliance.
- Captured cleartext credentials (e.g. HTTP Basic Auth, FTP, Telnet) are automatically redacted in UI presentations and forensic reports (e.g., `user:***`).

---

## 3. MITRE ATT&CK® Enterprise Mapping

| Technique ID | Technique Name | Tactic | Description & Detection Context |
|---|---|---|---|
| **T1040** | Network Sniffing | Credential Access, Discovery | Monitoring open, unencrypted wireless networks where traffic is exposed in plaintext. |
| **T1557** | Adversary-in-the-Middle | Credential Access, Collection | Positioning between devices using rogue Access Points or rogue DHCP servers. |
| **T1557.002** | AitM: ARP Poisoning | Credential Access, Collection | Poisoning ARP tables with gratuitous replies; gateway MAC flapping. |
| **T1565.002** | Transmitted Data Manipulation | Impact | DNS response hijacking and upstream resolver discrepancy against DoH canary answers. |
| **T1498.001** | Direct Network Flood | Impact | 802.11 Deauthentication or Disassociation frame bursts forcing station reconnections. |
| **T1110.002** | Password Cracking | Credential Access | Harvesting 4-way WPA/WPA2 handshakes or PMKID elements for offline cracking. |
| **T1552.001** | Credentials in Files / Cleartext | Credential Access | Transmitting unencrypted passwords across HTTP Basic Auth, FTP, or Telnet sessions. |
| **T1562.001** | Impair Defenses | Defense Evasion | Stripping TLS encryption (SSLstrip) or redirecting HTTPS to HTTP. |

---

## 4. Multi-Stage Correlation Rules Engine

The correlation engine identifies high-confidence composite attack chains across temporal windows ($\Delta t \le 900\text{s}$):

1. **Evil Twin Attack Chain (`RULE_EVIL_TWIN_CHAIN`):**
   - *Logic:* `DEAUTH_FLOOD` / `DEAUTH_BURST` $\to$ new Access Point broadcasting identical SSID / `EVIL_TWIN`.
   - *Impact:* Attacker disconnects legitimate clients to force reconnection to rogue infrastructure.
   - *Severity:* `CRITICAL` (Confidence: $0.98$).
2. **Confirmed AitM Interception Chain (`RULE_CONFIRMED_AITM_CHAIN`):**
   - *Logic:* `ARP_SPOOF` / `MAC_FLAPPING` $\to$ `DNS_SPOOF` / `DOH_DISCREPANCY` $\to$ `SSL_STRIP` / `TLS_CERT_DRIFT`.
   - *Impact:* Full bidirectional adversary-in-the-middle traffic manipulation.
   - *Severity:* `CRITICAL` (Confidence: $0.99$).
3. **Rogue AP Credential Harvesting (`RULE_ROGUE_CREDENTIAL_HARVEST`):**
   - *Logic:* `OPEN_NETWORK` / `EVIL_TWIN` $\to$ `CLEARTEXT_CREDENTIALS` (FTP, HTTP Basic Auth).
   - *Impact:* Active harvesting of user authentication secrets on untrusted infrastructure.
   - *Severity:* `HIGH` (Confidence: $0.95$).
4. **Rogue DHCP Network Hijack (`RULE_DHCP_HIJACK_CHAIN`):**
   - *Logic:* `ROGUE_DHCP` lease offer $\to$ DNS discrepancy or default gateway redirection.
   - *Impact:* Unauthorized DHCP server establishing persistence as local router/resolver.
   - *Severity:* `HIGH` (Confidence: $0.95$).

---

## 5. Standard Operating Procedures (SOP) for Analysts

1. **Initiate Case:** Click `+ New Case` in the Case Bar. Specify Title, Lead Examiner, and Authorization Ref.
2. **Baseline Collection:** Execute `Collect Snapshot` to establish the initial order-of-volatility baseline before investigative actions.
3. **Live Triage & Ingest:** Monitor streaming detections in the **Live Triage** feed or upload capture files (`.pcap` / `.csv`) via the Capture Upload panel.
4. **Review Correlated Chains:** Check the **Timeline** tab for composite attack chains and apply recommended containment actions.
5. **Inspect Threat Indicators:** Review the **IOCs** tab and export indicators in RFC 4180 CSV, JSON, or OASIS STIX 2.1 format for SIEM ingestion.
6. **Verify Chain of Custody:** Open the **Evidence & Custody** tab to certify that zero tampering has occurred.
7. **Generate Final Report:** In the **Reports** tab, click `Generate Sealed HTML Report`. The system commits a final report SHA-256 block into the custody ledger and outputs the formal report.
