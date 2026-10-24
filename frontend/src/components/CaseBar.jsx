import React, { useState, useEffect } from 'react';
import {
  Briefcase, User, ShieldCheck, ShieldAlert, Clock,
  PlusCircle, Camera, CheckCircle, AlertTriangle, ChevronDown
} from 'lucide-react';

export default function CaseBar({
  activeCase,
  cases = [],
  onSelectCase,
  onOpenNewCaseModal,
  onCollectSnapshot,
  onVerifyIntegrity,
  isCollectingSnapshot,
  isVerifying,
}) {
  const [utcTime, setUtcTime] = useState('');
  const [ntpDrift, setNtpDrift] = useState('+0.02s');
  const [driftWarning, setDriftWarning] = useState(false);
  const [showCaseDropdown, setShowCaseDropdown] = useState(false);

  useEffect(() => {
    const updateClock = () => {
      const now = new Date();
      setUtcTime(now.toUTCString().replace('GMT', 'UTC'));
    };
    updateClock();
    const interval = setInterval(updateClock, 1000);
    return () => clearInterval(interval);
  }, []);

  const getStatusBadge = (status) => {
    switch (status) {
      case 'Open':
        return <span className="case-status-badge case-status--open">Open</span>;
      case 'Triage':
        return <span className="case-status-badge case-status--triage">Triage</span>;
      case 'Investigating':
        return <span className="case-status-badge case-status--investigating">Investigating</span>;
      case 'Closed':
        return <span className="case-status-badge case-status--closed">Closed</span>;
      default:
        return <span className="case-status-badge">{status || 'Open'}</span>;
    }
  };

  return (
    <div className="case-bar">
      {/* Left: Active Case Selector & Metadata */}
      <div className="case-bar-left">
        <div className="case-selector-wrapper">
          <button
            className="case-selector-btn"
            onClick={() => setShowCaseDropdown(!showCaseDropdown)}
            title="Switch active DFIR case"
          >
            <Briefcase size={15} color="var(--accent-cyan)" />
            <span className="case-id-text">{activeCase?.case_id || 'No Case Active'}</span>
            <ChevronDown size={13} color="var(--text-secondary)" />
          </button>

          {showCaseDropdown && (
            <div className="case-dropdown-menu">
              <div className="case-dropdown-header">Select Investigation Case</div>
              {cases.length === 0 ? (
                <div className="case-dropdown-empty">No cases recorded yet</div>
              ) : (
                cases.map((c) => (
                  <div
                    key={c.case_id}
                    className={`case-dropdown-item ${activeCase?.case_id === c.case_id ? 'active' : ''}`}
                    onClick={() => {
                      onSelectCase(c);
                      setShowCaseDropdown(false);
                    }}
                  >
                    <div className="case-dropdown-item-title">{c.title}</div>
                    <div className="case-dropdown-item-meta">
                      <code>{c.case_id}</code> · {c.examiner} · {c.status}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}
        </div>

        {activeCase && (
          <>
            <div className="case-meta-item">
              <User size={13} color="var(--text-secondary)" />
              <span className="case-meta-val">{activeCase.examiner}</span>
            </div>
            <div className="case-meta-item">
              {getStatusBadge(activeCase.status)}
            </div>
            {activeCase.synthetic && (
              <div className="training-watermark-chip">
                <span>SYNTHETIC / TRAINING</span>
              </div>
            )}
          </>
        )}
      </div>

      {/* Right: UTC Time, NTP Drift, & Action Buttons */}
      <div className="case-bar-right">
        <div className="clock-badge">
          <Clock size={13} color="var(--accent-cyan)" />
          <span className="utc-clock-text">{utcTime || 'UTC'}</span>
          <span
            className={`ntp-drift-badge ${driftWarning ? 'drift-warn' : 'drift-ok'}`}
            title="Host clock offset relative to UTC"
          >
            NTP: {ntpDrift} {driftWarning ? '⚠' : '✓'}
          </span>
        </div>

        <button
          className="case-btn case-btn--new"
          onClick={onOpenNewCaseModal}
          title="Create a new DFIR Investigation Case"
        >
          <PlusCircle size={14} />
          <span>New Case</span>
        </button>

        {activeCase && (
          <>
            <button
              className="case-btn case-btn--snapshot"
              onClick={onCollectSnapshot}
              disabled={isCollectingSnapshot}
              title="Collect RFC 3227 Order-of-Volatility Evidence Snapshot"
            >
              <Camera size={14} />
              <span>{isCollectingSnapshot ? 'Collecting…' : 'Collect Snapshot'}</span>
            </button>

            <button
              className="case-btn case-btn--verify"
              onClick={onVerifyIntegrity}
              disabled={isVerifying}
              title="Cryptographically verify custody hash chain and evidence integrity"
            >
              <ShieldCheck size={14} />
              <span>{isVerifying ? 'Verifying…' : 'Verify Integrity'}</span>
            </button>
          </>
        )}
      </div>
    </div>
  );
}
