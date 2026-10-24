import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, ShieldAlert, Wifi, Activity, RefreshCw,
  FlaskConical, Radio, AlertTriangle, CheckCircle2,
  Bell, Settings, Clock, ShieldCheck
} from 'lucide-react';
import './index.css';
import RiskChart from './RiskChart';
import { CheckGrid } from './CheckBadge';

// DFIR Forensic UI Components
import CaseBar from './components/CaseBar';
import NewCaseModal from './components/NewCaseModal';
import FindingsSummary from './components/FindingsSummary';
import LiveTriage from './components/LiveTriage';
import TimelineView from './components/TimelineView';
import EvidencePanel from './components/EvidencePanel';
import IocTable from './components/IocTable';
import AttackMatrix from './components/AttackMatrix';
import ReportsPanel from './components/ReportsPanel';

const API_BASE = 'http://localhost:5000';
// The API token is injected via the Vite env system.
// Set VITE_API_TOKEN=<your-token> in frontend/.env
const API_TOKEN = import.meta.env.VITE_API_TOKEN || '';

// ── Helpers ──────────────────────────────────────────────────────────────────

function getRiskColor(score) {
  if (score < 30) return 'var(--risk-low)';
  if (score < 60) return 'var(--risk-med)';
  return 'var(--risk-high)';
}

function getRiskLabel(score) {
  if (score < 30) return 'Safe';
  if (score < 60) return 'Elevated';
  if (score < 90) return 'High Risk';
  return 'Critical';
}

function authHeaders() {
  return {
    'Content-Type': 'application/json',
    'X-API-Token': API_TOKEN,
  };
}

// ── Mode Banner ───────────────────────────────────────────────────────────────

function ModeBanner({ mode, activeScenario, demoMode, platform, sniffActive }) {
  if (mode === 'simulation') {
    return (
      <div className="mode-banner mode-banner--sim">
        <FlaskConical size={16} />
        <strong>SIMULATION MODE ACTIVE</strong>
        <span className="mode-banner-sep">|</span>
        <span>Scenario: <code>{activeScenario}</code> — alerts below are educational demos, NOT real detections</span>
      </div>
    );
  }
  if (mode === 'both') {
    return (
      <div className="mode-banner mode-banner--both">
        <AlertTriangle size={16} />
        <strong>LIVE + SIMULATION RUNNING</strong>
        <span className="mode-banner-sep">|</span>
        <span>Real checks are active. Simulation overlay: <code>{activeScenario}</code></span>
      </div>
    );
  }
  if (demoMode) {
    return (
      <div className="mode-banner mode-banner--demo">
        <Radio size={16} />
        <strong>NO WIFI INTERFACE FOUND</strong>
        <span className="mode-banner-sep">|</span>
        <span>Showing demo data. Connect to a network and restart the backend.</span>
      </div>
    );
  }
  return (
    <div className="mode-banner mode-banner--live">
      <CheckCircle2 size={16} />
      <strong>LIVE DETECTION MODE</strong>
      <span className="mode-banner-sep">|</span>
      <span>{platform} · ARP sniff: {sniffActive ? '✓ active' : '⚠ polling fallback'}</span>
    </div>
  );
}

// ── Score Ring ────────────────────────────────────────────────────────────────

function ScoreRing({ liveScore, simScore, mode }) {
  const displayScore = Math.max(liveScore, simScore);
  const color = getRiskColor(displayScore);
  const label = getRiskLabel(displayScore);
  const circumference = 2 * Math.PI * 54;
  const dashOffset = circumference * (1 - displayScore / 100);

  return (
    <div className="score-ring-container">
      <svg width="160" height="160" viewBox="0 0 160 160" className="score-ring-svg">
        {/* Track */}
        <circle cx="80" cy="80" r="54" fill="none"
          stroke="var(--border-color)" strokeWidth="12" />
        {/* Progress */}
        <circle cx="80" cy="80" r="54" fill="none"
          stroke={color} strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={dashOffset}
          transform="rotate(-90 80 80)"
          style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.4s ease' }}
        />
        {/* Score text */}
        <text x="80" y="74" textAnchor="middle"
          fontSize="32" fontWeight="700" fill={color}
          style={{ transition: 'fill 0.4s ease' }}>
          {displayScore}
        </text>
        <text x="80" y="94" textAnchor="middle"
          fontSize="11" fill="var(--text-secondary)">
          {label}
        </text>
      </svg>

      {/* Sub-scores when both modes active */}
      {mode === 'both' && (
        <div className="sub-scores">
          <div className="sub-score">
            <span className="sub-score-label">Live</span>
            <span className="sub-score-val" style={{ color: getRiskColor(liveScore) }}>{liveScore}</span>
          </div>
          <div className="sub-score-divider" />
          <div className="sub-score">
            <span className="sub-score-label">Sim</span>
            <span className="sub-score-val" style={{ color: getRiskColor(simScore) }}>{simScore}</span>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Network Info Card ─────────────────────────────────────────────────────────

function NetworkCard({ network }) {
  const fields = [
    { label: 'SSID',         value: network.ssid },
    { label: 'BSSID',        value: network.bssid },
    { label: 'Encryption',   value: network.encryption },
    { label: 'Channel',      value: network.channel },
    { label: 'Signal',       value: network.signal },
    { label: 'Gateway IP',   value: network.gateway_ip },
    { label: 'Gateway MAC',  value: network.gateway_mac },
    { label: 'DNS Server',   value: network.dns },
    { label: 'Subnet Mask',  value: network.subnet },
  ];
  return (
    <section className="card" aria-label="Network Identity">
      <h2 className="card-title">
        <Wifi size={17} color="var(--accent-cyan)" />
        Network Identity
      </h2>
      <div className="info-grid">
        {fields.map(({ label, value }) => (
          <div className="info-item" key={label}>
            <label>{label}</label>
            <div className="value">{value || '—'}</div>
          </div>
        ))}
      </div>
    </section>
  );
}

// ── Alerts Panel ──────────────────────────────────────────────────────────────

function AlertsPanel({ liveAlerts, simAlerts }) {
  const allAlerts = [
    ...liveAlerts.map((a) => ({ text: a, sim: false })),
    ...simAlerts.map((a)  => ({ text: a, sim: true  })),
  ];

  return (
    <section className="card alerts-section" aria-label="Security Alerts">
      <h2 className="card-title">
        <ShieldAlert size={17} color="var(--risk-high)" />
        Security Alerts
        {allAlerts.length > 0 && (
          <span className="alert-count">{allAlerts.length}</span>
        )}
      </h2>
      <div className="alert-list">
        {allAlerts.length > 0 ? (
          allAlerts.map(({ text, sim }, i) => (
            <div key={i}
              className={`alert-item ${sim ? 'alert-item--sim' : 'alert-item--live'}`}>
              {sim && <span className="alert-sim-tag">SIM</span>}
              <div className="alert-text">{text}</div>
            </div>
          ))
        ) : (
          <div className="alert-empty">
            <Shield size={36} className="alert-empty-icon" />
            <p>No active threats detected.</p>
            <p className="alert-empty-sub">All checks passing.</p>
          </div>
        )}
      </div>
    </section>
  );
}

// ── Simulation Lab Panel ──────────────────────────────────────────────────────

function SimPanel({ activeScenario, onTrigger }) {
  const scenarios = [
    { id: 'open',         label: 'Open WiFi',        desc: 'No encryption' },
    { id: 'evil_twin',    label: 'Evil Twin AP',     desc: 'Rogue BSSID' },
    { id: 'mitm',         label: 'ARP Spoof/MITM',   desc: 'MAC hijack' },
    { id: 'dns',          label: 'DNS Spoof',        desc: 'Rogue resolver' },
    { id: 'ssl',          label: 'SSL Strip',        desc: 'HTTPS downgrade' },
    { id: 'deauth_flood', label: 'Deauth Flood',     desc: '802.11 frame flood' },
    { id: 'rogue_dhcp',   label: 'Rogue DHCP',       desc: 'Conflicting leases' },
  ];

  return (
    <section className="card sim-panel" aria-label="Lab Simulation Panel">
      <h2 className="card-title card-title--sim">
        <FlaskConical size={17} color="var(--accent-blue)" />
        🧪 Lab Simulation Panel
      </h2>
      <div className="sim-warning">
        <AlertTriangle size={13} />
        These scenarios inject <strong>educational demo alerts</strong> as a simulation overlay.
        Real detection runs in parallel and is unaffected.
      </div>
      <div className="sim-btn-row">
        {scenarios.map(({ id, label, desc }) => (
          <button
            key={id}
            id={`sim-btn-${id}`}
            className={`sim-btn ${activeScenario === id ? 'sim-btn--active' : ''}`}
            onClick={() => onTrigger(id)}
            title={desc}
          >
            <span className="sim-btn-label">{label}</span>
            <span className="sim-btn-desc">{desc}</span>
          </button>
        ))}
        <button
          id="sim-btn-reset"
          className="sim-btn sim-btn--reset"
          onClick={() => onTrigger('reset')}
        >
          <RefreshCw size={13} />
          Reset Simulation
        </button>
      </div>
    </section>
  );
}

// ── Stats Bar ─────────────────────────────────────────────────────────────────

function StatsBar({ stats }) {
  if (!stats) return null;
  return (
    <div className="stats-bar">
      <div className="stat-item">
        <Clock size={13} color="var(--text-secondary)" />
        <span className="stat-label">24 h events</span>
        <span className="stat-val">{stats.total_events_24h}</span>
      </div>
      <div className="stat-item">
        <span className="stat-label">Peak risk</span>
        <span className="stat-val" style={{ color: getRiskColor(stats.max_risk_24h) }}>
          {stats.max_risk_24h}
        </span>
      </div>
      <div className="stat-item">
        <span className="stat-label">Avg risk</span>
        <span className="stat-val">{stats.avg_risk_24h}</span>
      </div>
      <div className="stat-item">
        <AlertTriangle size={13} color="var(--risk-high)" />
        <span className="stat-label">High-risk</span>
        <span className="stat-val" style={{ color: 'var(--risk-high)' }}>
          {stats.high_risk_events_24h}
        </span>
      </div>
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [data, setData] = useState({
    network: { ssid: 'Loading…', bssid: '', encryption: '', gateway_ip: '',
               gateway_mac: '', channel: '', signal: '', dns: '', subnet: '' },
    live_risk_score: 0,
    sim_risk_score: 0,
    risk_score: 0,
    live_alerts: [],
    sim_alerts: [],
    alerts: [],
    check_results: {},
    active_scenario: null,
    mode: 'live',
    demo_mode: false,
    platform: '',
    scapy_available: false,
    arp_sniff_active: false,
  });
  const [history, setHistory] = useState([]);
  const [stats, setStats]     = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [apiError, setApiError] = useState(false);
  const [analyzing, setAnalyzing] = useState(false);
  const [uploadError, setUploadError] = useState(null);

  // ── DFIR State ──
  const [activeTab, setActiveTab] = useState('dashboard');
  const [cases, setCases] = useState([]);
  const [activeCase, setActiveCase] = useState(null);
  const [events, setEvents] = useState([]);
  const [isNewCaseModalOpen, setIsNewCaseModalOpen] = useState(false);
  const [isCollectingSnapshot, setIsCollectingSnapshot] = useState(false);
  const [isVerifyingIntegrity, setIsVerifyingIntegrity] = useState(false);

  const handleFileUpload = async (event, endpoint) => {
    const file = event.target.files[0];
    if (!file) return;

    setAnalyzing(true);
    setUploadError(null);

    const formData = new FormData();
    formData.append('file', file);
    if (activeCase) {
      formData.append('case_id', activeCase.case_id);
    }

    try {
      const res = await fetch(`${API_BASE}${endpoint}`, {
        method: 'POST',
        headers: {
          'X-API-Token': API_TOKEN,
        },
        body: formData,
      });

      if (!res.ok) {
        const errJson = await res.json().catch(() => ({}));
        throw new Error(errJson.message || `HTTP ${res.status}`);
      }

      await fetchStatus();
      await fetchHistory();
      await fetchStats();
      await fetchEvents();
    } catch (e) {
      console.error('Upload failed:', e);
      setUploadError(e.message || 'Failed to analyze capture file.');
    } finally {
      setAnalyzing(false);
      event.target.value = '';
    }
  };

  // ── Data fetching ──
  const fetchStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/status`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const json = await res.json();
      setData(json);
      setApiError(false);
      setLastUpdated(new Date());
    } catch (e) {
      console.error('Status fetch error:', e);
      setApiError(true);
    }
  };

  const fetchHistory = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/history?limit=60`);
      const json = await res.json();
      setHistory(json);
    } catch (e) {
      console.error('History fetch error:', e);
    }
  };

  const fetchStats = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/stats`);
      setStats(await res.json());
    } catch (e) {
      console.error('Stats fetch error:', e);
    }
  };

  const fetchCases = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/cases`);
      if (res.ok) {
        const json = await res.json();
        const caseList = json.cases || [];
        setCases(caseList);
        setActiveCase((prev) => {
          if (prev && caseList.some((c) => c.case_id === prev.case_id)) {
            return caseList.find((c) => c.case_id === prev.case_id);
          }
          return caseList.find((c) => c.status !== 'Closed') || caseList[0] || null;
        });
      }
    } catch (e) {
      console.error('Failed to fetch cases:', e);
    }
  };

  const fetchEvents = async () => {
    try {
      const url = activeCase
        ? `${API_BASE}/api/events?case_id=${activeCase.case_id}&limit=50`
        : `${API_BASE}/api/events?limit=50`;
      const res = await fetch(url);
      if (res.ok) {
        const json = await res.json();
        setEvents(json.events || []);
      }
    } catch (e) {
      console.error('Failed to fetch events:', e);
    }
  };

  useEffect(() => {
    fetchStatus();
    fetchHistory();
    fetchStats();
    fetchCases();
    fetchEvents();

    const statusInterval  = setInterval(fetchStatus, 3000);
    const historyInterval = setInterval(fetchHistory, 15000);
    const statsInterval   = setInterval(fetchStats, 30000);
    const eventsInterval  = setInterval(fetchEvents, 6000);
    return () => {
      clearInterval(statusInterval);
      clearInterval(historyInterval);
      clearInterval(statsInterval);
      clearInterval(eventsInterval);
    };
  }, [activeCase]);

  // ── Scenario trigger ──
  const triggerScenario = async (scenario) => {
    try {
      const res = await fetch(`${API_BASE}/api/scenario`, {
        method: 'POST',
        headers: authHeaders(),
        body: JSON.stringify({ scenario }),
      });
      if (res.status === 401) {
        alert('❌ Unauthorised: set VITE_API_TOKEN in frontend/.env');
        return;
      }
      await fetchStatus();
      await fetchEvents();
    } catch (e) {
      console.error('Scenario error:', e);
    }
  };

  // ── Case Handlers ──
  const handleCreateCase = async (caseData) => {
    const res = await fetch(`${API_BASE}/api/cases`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify(caseData),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.message || 'Failed to create case');
    }
    const json = await res.json();
    const created = json.case;
    setCases((prev) => [created, ...prev]);
    setActiveCase(created);

    // Notify backend detector of active case
    fetch(`${API_BASE}/api/detector/active-case`, {
      method: 'POST',
      headers: authHeaders(),
      body: JSON.stringify({ case_id: created.case_id }),
    }).catch(() => {});
  };

  const handleCollectSnapshot = async () => {
    if (!activeCase) return;
    try {
      setIsCollectingSnapshot(true);
      const res = await fetch(`${API_BASE}/api/cases/${activeCase.case_id}/snapshot`, {
        method: 'POST',
        headers: authHeaders(),
      });
      if (res.ok) {
        alert('✓ RFC 3227 Live Evidence Snapshot collected, hashed, and logged to custody.');
        fetchEvents();
      } else {
        const err = await res.json().catch(() => ({}));
        alert(`❌ Snapshot failed: ${err.message || 'Error'}`);
      }
    } catch (e) {
      alert(`❌ Snapshot failed: ${e.message}`);
    } finally {
      setIsCollectingSnapshot(false);
    }
  };

  const handleVerifyIntegrity = async () => {
    if (!activeCase) return;
    try {
      setIsVerifyingIntegrity(true);
      setActiveTab('evidence');
    } finally {
      setIsVerifyingIntegrity(false);
    }
  };

  return (
    <div className="app-container">
      {/* ── Header ── */}
      <header className="header">
        <div>
          <h1 className="header-title">
            <Shield size={24} />
            WiFi Risk Detector
          </h1>
          <p className="header-sub">Digital Forensics & Incident Response (DFIR) Platform · Real Detection + Forensic Triage</p>
        </div>
        <div className="header-right">
          {lastUpdated && (
            <span className="last-updated">
              Updated {lastUpdated.toLocaleTimeString()}
            </span>
          )}
          <div
            className="status-badge"
            style={{
              borderColor: apiError ? 'var(--risk-high)' : 'var(--accent-cyan)',
              color: apiError ? 'var(--risk-high)' : 'var(--accent-cyan)',
            }}
          >
            <Activity size={14} className="pulse" />
            {apiError ? 'Backend Offline' : 'Live'}
          </div>
        </div>
      </header>

      {/* ── Case Bar (Slim Bar Under Header) ── */}
      <CaseBar
        activeCase={activeCase}
        cases={cases}
        onSelectCase={(c) => {
          setActiveCase(c);
          fetch(`${API_BASE}/api/detector/active-case`, {
            method: 'POST',
            headers: authHeaders(),
            body: JSON.stringify({ case_id: c.case_id }),
          }).catch(() => {});
        }}
        onOpenNewCaseModal={() => setIsNewCaseModalOpen(true)}
        onCollectSnapshot={handleCollectSnapshot}
        onVerifyIntegrity={handleVerifyIntegrity}
        isCollectingSnapshot={isCollectingSnapshot}
        isVerifying={isVerifyingIntegrity}
      />

      {/* ── New Case Creation Modal ── */}
      <NewCaseModal
        isOpen={isNewCaseModalOpen}
        onClose={() => setIsNewCaseModalOpen(false)}
        onCreateCase={handleCreateCase}
      />

      {/* ── DFIR Tab Strip ── */}
      <nav className="tab-strip" aria-label="Investigation Navigation">
        <button
          className={`tab-btn ${activeTab === 'dashboard' ? 'active' : ''}`}
          onClick={() => setActiveTab('dashboard')}
        >
          <Activity size={15} />
          <span>Dashboard</span>
        </button>
        <button
          className={`tab-btn ${activeTab === 'triage' ? 'active' : ''}`}
          onClick={() => setActiveTab('triage')}
        >
          <Radio size={15} />
          <span>Live Triage</span>
        </button>
        <button
          className={`tab-btn ${activeTab === 'timeline' ? 'active' : ''}`}
          onClick={() => setActiveTab('timeline')}
        >
          <Clock size={15} />
          <span>Timeline</span>
        </button>
        <button
          className={`tab-btn ${activeTab === 'evidence' ? 'active' : ''}`}
          onClick={() => setActiveTab('evidence')}
        >
          <ShieldCheck size={15} />
          <span>Evidence & Custody</span>
        </button>
        <button
          className={`tab-btn ${activeTab === 'iocs' ? 'active' : ''}`}
          onClick={() => setActiveTab('iocs')}
        >
          <Settings size={15} />
          <span>IOCs</span>
        </button>
        <button
          className={`tab-btn ${activeTab === 'attack' ? 'active' : ''}`}
          onClick={() => setActiveTab('attack')}
        >
          <ShieldAlert size={15} />
          <span>ATT&CK Matrix</span>
        </button>
        <button
          className={`tab-btn ${activeTab === 'reports' ? 'active' : ''}`}
          onClick={() => setActiveTab('reports')}
        >
          <Bell size={15} />
          <span>Reports</span>
        </button>
      </nav>

      {/* ── Tab: Dashboard (Original Page Preserved Unchanged + FindingsSummary) ── */}
      {activeTab === 'dashboard' && (
        <>
          {/* ── Mode Banner ── */}
          <ModeBanner
            mode={data.mode}
            activeScenario={data.active_scenario}
            demoMode={data.demo_mode}
            platform={data.platform}
            sniffActive={data.arp_sniff_active}
          />

          {/* ── Stats bar ── */}
          <StatsBar stats={stats} />

          {/* ── Capture Upload Panel ── */}
          <section className="card upload-section" style={{ marginBottom: '1.25rem' }}>
            <h2 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--accent-blue)' }}>
              <Settings size={17} />
              Analyze Real Capture Session (Airodump-ng / Wireshark)
            </h2>
            
            <div className="upload-container" style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center' }}>
              {/* CSV File Input */}
              <div className="upload-box" style={{ flex: 1, minWidth: '240px' }}>
                <label style={{ display: 'block', fontSize: '0.78rem', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Airodump-ng CSV Scan
                </label>
                <input
                  type="file"
                  accept=".csv"
                  disabled={analyzing}
                  onChange={(e) => handleFileUpload(e, '/api/upload/airodump-csv')}
                  style={{
                    width: '100%',
                    fontSize: '0.82rem',
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid var(--border-color)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '6px 10px',
                    color: 'var(--text-primary)',
                    cursor: analyzing ? 'not-allowed' : 'pointer'
                  }}
                />
              </div>

              {/* PCAP File Input */}
              <div className="upload-box" style={{ flex: 1, minWidth: '240px' }}>
                <label style={{ display: 'block', fontSize: '0.78rem', textTransform: 'uppercase', color: 'var(--text-secondary)', marginBottom: '6px' }}>
                  Wireshark/Airodump PCAP/CAP
                </label>
                <input
                  type="file"
                  accept=".pcap,.cap,.pcapng"
                  disabled={analyzing}
                  onChange={(e) => handleFileUpload(e, '/api/upload/pcap')}
                  style={{
                    width: '100%',
                    fontSize: '0.82rem',
                    background: 'rgba(255,255,255,0.03)',
                    border: '1px solid var(--border-color)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '6px 10px',
                    color: 'var(--text-primary)',
                    cursor: analyzing ? 'not-allowed' : 'pointer'
                  }}
                />
              </div>
            </div>

            {/* Status and Error messages */}
            {analyzing && (
              <div style={{ marginTop: '10px', fontSize: '0.85rem', color: 'var(--accent-cyan)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <Activity size={14} className="pulse" />
                Analyzing capture…
              </div>
            )}

            {uploadError && (
              <div style={{ marginTop: '10px', fontSize: '0.85rem', color: 'var(--risk-high)', display: 'flex', alignItems: 'center', gap: '6px' }}>
                <AlertTriangle size={14} />
                Error: {uploadError}
              </div>
            )}

            {/* Summary Line */}
            {data.capture_analysis && (
              <div style={{
                marginTop: '12px',
                paddingTop: '10px',
                borderTop: '1px solid var(--border-color)',
                fontSize: '0.85rem',
                color: 'var(--text-primary)',
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                flexWrap: 'wrap'
              }}>
                <CheckCircle2 size={15} color="var(--risk-low)" />
                <span>
                  <strong>Capture Analysis Active:</strong> Source: <code>{data.capture_analysis.source}</code>
                </span>
                <span style={{ color: 'var(--text-muted)' }}>|</span>
                <span>
                  Risk Score Contribution: <strong style={{ color: getRiskColor(data.capture_analysis.score) }}>+{data.capture_analysis.score}</strong>
                </span>
                <span style={{ color: 'var(--text-muted)' }}>|</span>
                <span>
                  APs Found: <strong>{data.capture_analysis.result?.networks?.length || 0}</strong>
                </span>
                {data.capture_analysis.result?.packet_count > 0 && (
                  <>
                    <span style={{ color: 'var(--text-muted)' }}>|</span>
                    <span>
                      Packets Analyzed: <strong>{data.capture_analysis.result.packet_count}</strong>
                    </span>
                  </>
                )}
              </div>
            )}
          </section>

          {/* ── Main grid ── */}
          <div className="dashboard-grid">
            {/* Col 1: Score + FindingsSummary + Checks */}
            <div className="col-left">
              <section className="card risk-section" aria-label="Risk Score">
                <ScoreRing
                  liveScore={data.live_risk_score}
                  simScore={data.sim_risk_score}
                  mode={data.mode}
                />
                <div className="risk-label">Overall Risk Score</div>
              </section>

              {/* Added Findings (Severity x Confidence) Card */}
              <FindingsSummary events={events} onNavigateTab={setActiveTab} />

              <section className="card" aria-label="Detection Checks">
                <h2 className="card-title">
                  <CheckCircle2 size={17} color="var(--accent-cyan)" />
                  Detection Checks
                </h2>
                <CheckGrid checkResults={data.check_results} />
              </section>
            </div>

            {/* Col 2: Network Info */}
            <NetworkCard network={data.network} />

            {/* Full-width: Risk History Chart */}
            <section className="card full-width" aria-label="Risk History Chart">
              <RiskChart history={history} />
            </section>

            {/* Full-width: Alerts */}
            <AlertsPanel
              liveAlerts={data.live_alerts || []}
              simAlerts={data.sim_alerts || []}
            />

            {/* Full-width: Sim Lab */}
            <SimPanel
              activeScenario={data.active_scenario}
              onTrigger={triggerScenario}
            />
          </div>
        </>
      )}

      {/* ── Tab: Live Triage ── */}
      {activeTab === 'triage' && (
        <LiveTriage
          activeCase={activeCase}
          apiBase={API_BASE}
          onAddNoteToCase={async (cid, content) => {
            await fetch(`${API_BASE}/api/cases/${cid}/notes`, {
              method: 'POST',
              headers: authHeaders(),
              body: JSON.stringify({ content, author: activeCase?.examiner || 'Analyst' }),
            });
            fetchEvents();
          }}
        />
      )}

      {/* ── Tab: Timeline & Correlations ── */}
      {activeTab === 'timeline' && (
        <TimelineView
          activeCase={activeCase}
          apiBase={API_BASE}
          apiToken={API_TOKEN}
        />
      )}

      {/* ── Tab: Evidence & Custody ── */}
      {activeTab === 'evidence' && (
        <EvidencePanel
          activeCase={activeCase}
          apiBase={API_BASE}
          onVerifyIntegrity={handleVerifyIntegrity}
          isVerifying={isVerifyingIntegrity}
        />
      )}

      {/* ── Tab: IOCs & Threat Intel ── */}
      {activeTab === 'iocs' && (
        <IocTable
          activeCase={activeCase}
          apiBase={API_BASE}
        />
      )}

      {/* ── Tab: MITRE ATT&CK Matrix ── */}
      {activeTab === 'attack' && (
        <AttackMatrix
          activeCase={activeCase}
          apiBase={API_BASE}
        />
      )}

      {/* ── Tab: Reports ── */}
      {activeTab === 'reports' && (
        <ReportsPanel
          activeCase={activeCase}
          apiBase={API_BASE}
        />
      )}
    </div>
  );
}
