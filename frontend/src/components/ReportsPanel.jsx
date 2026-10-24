import React, { useState } from 'react';
import {
  FileText, Download, ShieldCheck, Printer, CheckCircle,
  ExternalLink, AlertCircle
} from 'lucide-react';

export default function ReportsPanel({
  activeCase,
  apiBase = 'http://localhost:5000',
}) {
  const [isGenerating, setIsGenerating] = useState(false);
  const [message, setMessage] = useState('');

  if (!activeCase) {
    return (
      <div className="card" style={{ textAlign: 'center', padding: '3rem' }}>
        <FileText size={36} color="var(--text-secondary)" style={{ margin: '0 auto 1rem' }} />
        <h2 style={{ marginBottom: '8px' }}>No Active Investigation Case Selected</h2>
        <p style={{ color: 'var(--text-secondary)' }}>
          Please select or open a case using the top Case Bar to generate forensic reports.
        </p>
      </div>
    );
  }

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="reports-container">
      {/* ── Action Bar ── */}
      <div className="triage-control-bar" style={{ marginBottom: '1.25rem' }}>
        <div className="triage-control-left">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileText size={17} color="var(--accent-cyan)" />
            <strong>Forensic Incident Report Generator</strong>
          </div>
        </div>

        <div className="triage-control-right">
          <button
            className="btn-primary"
            disabled={isGenerating}
            onClick={async () => {
              setIsGenerating(true);
              try {
                const res = await fetch(`${apiBase}/api/cases/${activeCase.case_id}/report`, {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    'X-API-Token': import.meta.env.VITE_API_TOKEN || '',
                  },
                  body: JSON.stringify({ author: activeCase.examiner }),
                });
                if (res.ok) {
                  const data = await res.json();
                  const rep = data.report;
                  // Trigger download
                  const blob = new Blob([rep.html], { type: 'text/html' });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement('a');
                  a.href = url;
                  a.download = `forensic_report_${activeCase.case_id}.html`;
                  a.click();
                  URL.revokeObjectURL(url);
                  alert(`✓ Report generated & sealed with SHA-256: ${rep.sha256.slice(0, 16)}...`);
                } else {
                  alert('Failed to generate report');
                }
              } catch (e) {
                alert(`Error generating report: ${e.message}`);
              } finally {
                setIsGenerating(false);
              }
            }}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <Download size={14} />
            <span>{isGenerating ? 'Sealing Report…' : 'Generate Sealed HTML Report'}</span>
          </button>

          <button className="btn-secondary" onClick={handlePrint} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Printer size={14} />
            <span>Print / PDF</span>
          </button>
        </div>
      </div>

      {/* ── Report Paper Layout ── */}
      <div className="card report-paper">
        {/* Report Header */}
        <div className="report-header-banner">
          <div>
            <h1 className="report-doc-title">WIRELESS INCIDENT RESPONSE & FORENSIC REPORT</h1>
            <div className="report-doc-sub">CONFIDENTIAL · LAW ENFORCEMENT & DFIR DEFENSE USE ONLY</div>
          </div>
          <div className="report-auth-box">
            <div><strong>AUTH REF:</strong> {activeCase.authorization_ref}</div>
            <div><strong>CASE ID:</strong> {activeCase.case_id}</div>
          </div>
        </div>

        {/* Case Metadata Grid */}
        <div className="report-meta-grid">
          <div className="report-meta-cell">
            <span className="lbl">Case Title:</span>
            <span className="val">{activeCase.title}</span>
          </div>
          <div className="report-meta-cell">
            <span className="lbl">Lead Examiner:</span>
            <span className="val">{activeCase.examiner}</span>
          </div>
          <div className="report-meta-cell">
            <span className="lbl">Status:</span>
            <span className="val">{activeCase.status}</span>
          </div>
          <div className="report-meta-cell">
            <span className="lbl">Opened (UTC):</span>
            <span className="val">{activeCase.created_utc}</span>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="report-section">
          <h2 className="report-heading">1. Executive Summary & Incident Scope</h2>
          <p className="report-paragraph">
            This digital forensic investigation report documents wireless monitoring, anomaly detection, and
            evidentiary artifacts captured for investigation <code>{activeCase.case_id}</code>.
            All collection, parsing, and correlation actions adhered strictly to RFC 3227 order of volatility
            guidelines and maintained an unbroken, SHA-256 hash-chained cryptographic chain of custody.
          </p>
        </div>

        {/* Methodology & Limitations */}
        <div className="report-section">
          <h2 className="report-heading">2. Methodology & Evidentiary Standards</h2>
          <div className="report-bullets">
            <div>• <strong>Integrity Hashing:</strong> Ingest SHA-256 and MD5 computed immediately on collection.</div>
            <div>• <strong>Chain of Custody:</strong> Append-only cryptographic ledger storing prior block hashes.</div>
            <div>• <strong>Time Synchronization:</strong> UTC standard timestamps verified against host NTP drift.</div>
            <div>• <strong>Order of Volatility (RFC 3227):</strong> Volatile ARP cache, active sockets, and BSSID survey prioritized over disk artifacts.</div>
          </div>
        </div>

        {/* Signoff & Manifest Footer */}
        <div className="report-signoff-section">
          <div className="signoff-box">
            <div className="signoff-line" />
            <div className="signoff-text">Lead Examiner Signature: <strong>{activeCase.examiner}</strong></div>
          </div>
          <div className="signoff-box">
            <div className="signoff-line" />
            <div className="signoff-text">Date & Authorization Ref: <strong>{activeCase.authorization_ref}</strong></div>
          </div>
        </div>
      </div>
    </div>
  );
}
