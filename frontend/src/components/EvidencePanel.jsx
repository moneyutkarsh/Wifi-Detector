import React, { useState, useEffect } from 'react';
import {
  ShieldCheck, ShieldAlert, Copy, Check, FileText,
  Lock, RefreshCw, AlertTriangle, Database, CheckCircle2
} from 'lucide-react';

export default function EvidencePanel({
  activeCase,
  apiBase = 'http://localhost:5000',
  onVerifyIntegrity,
  isVerifying,
}) {
  const [evidenceList, setEvidenceList] = useState([]);
  const [custodyChain, setCustodyChain] = useState([]);
  const [verificationResult, setVerificationResult] = useState(null);
  const [copiedHash, setCopiedHash] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchData = async () => {
    if (!activeCase) return;
    setLoading(true);
    try {
      // 1. Fetch evidence items
      const eRes = await fetch(`${apiBase}/api/cases/${activeCase.case_id}/evidence`);
      if (eRes.ok) {
        const eData = await eRes.json();
        setEvidenceList(eData.evidence || []);
      }

      // 2. Fetch custody chain
      const cRes = await fetch(`${apiBase}/api/cases/${activeCase.case_id}/custody`);
      if (cRes.ok) {
        const cData = await cRes.json();
        setCustodyChain(cData.custody_chain || []);
      }

      // 3. Verify custody integrity
      const vRes = await fetch(`${apiBase}/api/cases/${activeCase.case_id}/custody/verify`);
      if (vRes.ok) {
        const vData = await vRes.json();
        setVerificationResult(vData.verification);
      }
    } catch (err) {
      console.error('Error fetching evidence & custody:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, [activeCase]);

  const copyToClipboard = (text, key) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(key);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const isIntact = verificationResult?.is_intact ?? true;

  return (
    <div className="evidence-panel-container">
      {/* ── Cryptographic Integrity Banner ── */}
      <div className={`custody-banner ${isIntact ? 'custody-banner--intact' : 'custody-banner--tampered'}`}>
        <div className="custody-banner-icon">
          {isIntact ? (
            <ShieldCheck size={28} color="var(--risk-low)" />
          ) : (
            <ShieldAlert size={28} color="var(--risk-high)" />
          )}
        </div>
        <div className="custody-banner-content">
          <div className="custody-banner-title">
            {isIntact
              ? 'CHAIN OF CUSTODY VERIFIED: ALL EVIDENCE INTACT'
              : 'CRITICAL WARNING: CHAIN OF CUSTODY INTEGRITY COMPROMISED'}
          </div>
          <div className="custody-banner-sub">
            {isIntact
              ? `Cryptographic validation confirmed: ${verificationResult?.total_custody_entries || custodyChain.length} block entries and ${verificationResult?.verified_evidence_items || evidenceList.length} disk artifacts match genesis hashes.`
              : `Tampering or missing artifacts detected: ${verificationResult?.errors?.length || 1} discrepancy identified.`}
          </div>
        </div>

        <button
          className="btn-verify-again"
          onClick={fetchData}
          disabled={loading || isVerifying}
          title="Re-run SHA-256 and MD5 recalculation over all disk artifacts"
        >
          <RefreshCw size={14} className={loading || isVerifying ? 'pulse' : ''} />
          <span>{loading || isVerifying ? 'Checking…' : 'Re-Verify Chain'}</span>
        </button>
      </div>

      {/* Discrepancy details if tampered */}
      {verificationResult && !isIntact && verificationResult.errors && (
        <div className="card tamper-error-card" style={{ marginBottom: '1.25rem' }}>
          <h3 style={{ color: 'var(--risk-high)', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <AlertTriangle size={16} />
            Detected Evidence Discrepancies
          </h3>
          <ul>
            {verificationResult.errors.map((err, i) => (
              <li key={i} style={{ marginTop: '6px' }}>
                <code>{err.type}</code>: {err.message}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* ── Evidence Inventory Table ── */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <h2 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Database size={17} color="var(--accent-cyan)" />
          Registered Evidence Artifacts ({evidenceList.length})
        </h2>

        <div className="table-responsive">
          <table className="dfir-table">
            <thead>
              <tr>
                <th>Artifact Filename</th>
                <th>Source</th>
                <th>Size</th>
                <th>UTC Ingest Timestamp</th>
                <th>SHA-256 Hash</th>
                <th>MD5 Hash</th>
              </tr>
            </thead>
            <tbody>
              {evidenceList.length === 0 ? (
                <tr>
                  <td colSpan={6} className="empty-table-cell">
                    No evidence files ingested for this case yet. Use "Analyze Real Capture" or "Collect Snapshot" to record artifacts.
                  </td>
                </tr>
              ) : (
                evidenceList.map((item) => (
                  <tr key={item.id} className="dfir-table-row">
                    <td>
                      <strong>{item.original_filename}</strong>
                    </td>
                    <td>
                      <span className="source-tag">{item.source}</span>
                    </td>
                    <td className="mono-cell">{(item.size_bytes / 1024).toFixed(1)} KB</td>
                    <td className="mono-cell">{item.ingest_utc}</td>
                    <td>
                      <div className="hash-chip-wrapper">
                        <code className="hash-chip">{item.sha256?.slice(0, 16)}…</code>
                        <button
                          className="copy-icon-btn"
                          onClick={() => copyToClipboard(item.sha256, `sha-${item.id}`)}
                          title="Copy full SHA-256 hash"
                        >
                          {copiedHash === `sha-${item.id}` ? (
                            <Check size={12} color="var(--risk-low)" />
                          ) : (
                            <Copy size={12} />
                          )}
                        </button>
                      </div>
                    </td>
                    <td>
                      <div className="hash-chip-wrapper">
                        <code className="hash-chip">{item.md5?.slice(0, 12)}…</code>
                        <button
                          className="copy-icon-btn"
                          onClick={() => copyToClipboard(item.md5, `md5-${item.id}`)}
                          title="Copy full MD5 hash"
                        >
                          {copiedHash === `md5-${item.id}` ? (
                            <Check size={12} color="var(--risk-low)" />
                          ) : (
                            <Copy size={12} />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Append-Only Chain of Custody Log Table ── */}
      <div className="card">
        <h2 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Lock size={17} color="var(--accent-cyan)" />
          Append-Only Cryptographic Custody Ledger ({custodyChain.length} Blocks)
        </h2>

        <div className="table-responsive">
          <table className="dfir-table">
            <thead>
              <tr>
                <th style={{ width: '45px' }}>#</th>
                <th style={{ width: '160px' }}>UTC Timestamp</th>
                <th>Action</th>
                <th>Actor</th>
                <th>Previous Block Hash</th>
                <th>Block Entry Hash</th>
              </tr>
            </thead>
            <tbody>
              {custodyChain.length === 0 ? (
                <tr>
                  <td colSpan={6} className="empty-table-cell">
                    No custody ledger entries recorded.
                  </td>
                </tr>
              ) : (
                custodyChain.map((entry, idx) => (
                  <tr key={entry.id || idx} className="dfir-table-row">
                    <td className="mono-cell" style={{ color: 'var(--text-secondary)' }}>
                      {idx + 1}
                    </td>
                    <td className="mono-cell">{entry.ts_utc}</td>
                    <td>
                      <span className="action-tag">{entry.action}</span>
                    </td>
                    <td>{entry.actor}</td>
                    <td>
                      <code className="hash-chip-dim" title={entry.prev_hash}>
                        {entry.prev_hash?.slice(0, 14)}…
                      </code>
                    </td>
                    <td>
                      <div className="hash-chip-wrapper">
                        <code className="hash-chip" title={entry.entry_hash}>
                          {entry.entry_hash?.slice(0, 14)}…
                        </code>
                        <button
                          className="copy-icon-btn"
                          onClick={() => copyToClipboard(entry.entry_hash, `entry-${idx}`)}
                          title="Copy entry hash"
                        >
                          {copiedHash === `entry-${idx}` ? (
                            <Check size={12} color="var(--risk-low)" />
                          ) : (
                            <Copy size={12} />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
