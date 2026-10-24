import React from 'react';
import { AlertOctagon, AlertTriangle, ShieldCheck, Info, Flame, ChevronRight } from 'lucide-react';

export default function FindingsSummary({ events = [], onNavigateTab }) {
  // Compute counts per severity and mean confidence
  const counts = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  let totalConfidence = 0;
  let eventCount = events.length;

  events.forEach((e) => {
    const sev = (e.severity || 'INFO').toUpperCase();
    if (counts[sev] !== undefined) {
      counts[sev] += 1;
    }
    totalConfidence += Number(e.confidence || 1.0);
  });

  const avgConfidence = eventCount > 0 ? (totalConfidence / eventCount) * 100 : 100;

  // Determine Incident Severity Level
  let sevLevel = 'SEV0';
  let sevLabel = 'Nominal / No Threats';
  let sevClass = 'sev-0';

  if (counts.CRITICAL > 0) {
    sevLevel = 'SEV1';
    sevLabel = 'Critical Incident (Active AitM / Rogue AP)';
    sevClass = 'sev-1';
  } else if (counts.HIGH > 0) {
    sevLevel = 'SEV2';
    sevLabel = 'High Severity (Anomalous ARP / Rogue DHCP)';
    sevClass = 'sev-2';
  } else if (counts.MEDIUM > 0) {
    sevLevel = 'SEV3';
    sevLabel = 'Elevated Risk (Unencrypted Traffic / DoH Mismatch)';
    sevClass = 'sev-3';
  } else if (counts.LOW > 0) {
    sevLevel = 'SEV4';
    sevLabel = 'Low Risk (Minor Drift / Insecure Protocol)';
    sevClass = 'sev-4';
  }

  return (
    <section className="card findings-summary-card" aria-label="Forensic Findings">
      <div className="findings-header">
        <div className="findings-title">
          <Flame size={17} color="var(--risk-high)" />
          <span>Forensic Findings (Severity × Confidence)</span>
        </div>
        <div className={`sev-badge ${sevClass}`}>{sevLevel}</div>
      </div>

      <div className="sev-description">{sevLabel}</div>

      <div className="findings-metrics-grid">
        <div className="finding-metric-box metric--critical">
          <div className="metric-val">{counts.CRITICAL}</div>
          <div className="metric-lbl">Critical</div>
        </div>
        <div className="finding-metric-box metric--high">
          <div className="metric-val">{counts.HIGH}</div>
          <div className="metric-lbl">High</div>
        </div>
        <div className="finding-metric-box metric--medium">
          <div className="metric-val">{counts.MEDIUM}</div>
          <div className="metric-lbl">Medium</div>
        </div>
        <div className="finding-metric-box metric--low">
          <div className="metric-val">{counts.LOW}</div>
          <div className="metric-lbl">Low / Info</div>
        </div>
      </div>

      <div className="findings-confidence-row">
        <span className="conf-label">Average Confidence Rating:</span>
        <div className="conf-bar-wrapper">
          <div
            className="conf-bar-fill"
            style={{ width: `${Math.min(100, Math.max(0, avgConfidence))}%` }}
          />
        </div>
        <span className="conf-val">{avgConfidence.toFixed(0)}%</span>
      </div>

      <div className="findings-action-row">
        <button
          className="btn-link-action"
          onClick={() => onNavigateTab && onNavigateTab('triage')}
        >
          <span>Investigate in Live Triage</span>
          <ChevronRight size={14} />
        </button>
      </div>
    </section>
  );
}
