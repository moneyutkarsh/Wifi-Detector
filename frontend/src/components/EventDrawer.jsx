import React, { useState } from 'react';
import {
  X, ShieldAlert, Tag, ExternalLink, Copy, Check,
  Terminal, FileText, CheckCircle, AlertOctagon, CornerDownRight
} from 'lucide-react';

export default function EventDrawer({ event, onClose, onAddNote, onEscalate }) {
  const [copied, setCopied] = useState(false);
  const [noteText, setNoteText] = useState('');
  const [showNoteInput, setShowNoteInput] = useState(false);

  if (!event) return null;

  const handleCopyId = () => {
    navigator.clipboard.writeText(event.id);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const entities = typeof event.entities === 'string'
    ? (() => { try { return JSON.parse(event.entities); } catch { return {}; } })()
    : (event.entities || {});

  // Generate ASCII / Hex representation of entities for forensic inspection
  const entityJsonStr = JSON.stringify(entities, null, 2);
  const getHexDump = (str) => {
    const bytes = new TextEncoder().encode(str);
    const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(' ');
    return hex.slice(0, 240) + (hex.length > 240 ? ' ... [truncated]' : '');
  };

  const getSeverityBadge = (sev) => {
    const s = (sev || 'INFO').toUpperCase();
    return <span className={`badge-severity badge-severity--${s.toLowerCase()}`}>{s}</span>;
  };

  return (
    <div className="drawer-overlay" onClick={onClose}>
      <div className="drawer-content" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="drawer-header">
          <div className="drawer-header-left">
            <ShieldAlert size={18} color="var(--accent-cyan)" />
            <span className="drawer-title">Event Forensic Inspector</span>
          </div>
          <button className="drawer-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div className="drawer-body">
          {/* Top metadata grid */}
          <div className="drawer-meta-section">
            <div className="drawer-meta-row">
              <span className="meta-label">Event ID:</span>
              <div className="meta-val-with-copy">
                <code>{event.id}</code>
                <button className="copy-icon-btn" onClick={handleCopyId} title="Copy Event ID">
                  {copied ? <Check size={13} color="var(--risk-low)" /> : <Copy size={13} />}
                </button>
              </div>
            </div>

            <div className="drawer-meta-row">
              <span className="meta-label">Timestamp (UTC):</span>
              <span className="meta-val">{event.ts_utc}</span>
            </div>

            <div className="drawer-meta-row">
              <span className="meta-label">Source & Type:</span>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <span className="source-tag">{event.source}</span>
                <strong>{event.type}</strong>
              </div>
            </div>

            <div className="drawer-meta-row">
              <span className="meta-label">Classification:</span>
              <div style={{ display: 'flex', gap: '10px', alignItems: 'center' }}>
                {getSeverityBadge(event.severity)}
                <span className="confidence-pill">
                  Confidence: {((event.confidence || 1.0) * 100).toFixed(0)}%
                </span>
                {event.synthetic && (
                  <span className="training-chip-sm">SYNTHETIC</span>
                )}
              </div>
            </div>

            {event.attack_id && (
              <div className="drawer-meta-row">
                <span className="meta-label">MITRE ATT&CK:</span>
                <a
                  href={`https://attack.mitre.org/techniques/${event.attack_id.replace('.', '/')}/`}
                  target="_blank"
                  rel="noreferrer"
                  className="attack-link-tag"
                >
                  <Tag size={12} />
                  <span>{event.attack_id}</span>
                  <ExternalLink size={11} />
                </a>
              </div>
            )}
          </div>

          {/* Rationale & Explanation */}
          <div className="drawer-section">
            <h3 className="drawer-section-title">Evidentiary Rationale</h3>
            <p className="drawer-text-block">
              {event.rationale || event.summary || 'Telemetry anomaly observed matching detection rule criteria.'}
            </p>
          </div>

          {/* False-Positive Guidance */}
          <div className="drawer-section">
            <h3 className="drawer-section-title">False-Positive & Operational Notes</h3>
            <div className="fp-notes-box">
              <p>
                Verify whether legitimate network administrator activities (such as captive portal authorization,
                enterprise AP fast-roaming 802.11r, or router firmware updates) coincide with this telemetry window.
              </p>
            </div>
          </div>

          {/* Raw Entities & Hex Dump */}
          <div className="drawer-section">
            <h3 className="drawer-section-title">
              <Terminal size={14} />
              <span>Extracted Entities & Payload Inspection</span>
            </h3>
            <div className="code-view-container">
              <div className="code-view-header">JSON Entities</div>
              <pre className="code-pre">{entityJsonStr}</pre>
            </div>

            <div className="code-view-container" style={{ marginTop: '10px' }}>
              <div className="code-view-header">Hex & Byte Preview</div>
              <pre className="code-pre hex-pre">{getHexDump(entityJsonStr)}</pre>
            </div>
          </div>

          {/* Actions & Note Input */}
          <div className="drawer-section" style={{ borderBottom: 'none' }}>
            <h3 className="drawer-section-title">Analyst Actions</h3>
            <div className="drawer-actions-row">
              <button
                className="btn-action btn-action--note"
                onClick={() => setShowNoteInput(!showNoteInput)}
              >
                <FileText size={14} />
                <span>Add Note</span>
              </button>
              <button
                className="btn-action btn-action--escalate"
                onClick={() => onEscalate && onEscalate(event)}
              >
                <AlertOctagon size={14} />
                <span>Escalate Incident</span>
              </button>
            </div>

            {showNoteInput && (
              <div className="drawer-note-input-container">
                <textarea
                  className="form-textarea"
                  rows={2}
                  placeholder="Record investigative note for this specific event..."
                  value={noteText}
                  onChange={(e) => setNoteText(e.target.value)}
                />
                <button
                  className="btn-primary btn-sm"
                  style={{ marginTop: '6px' }}
                  onClick={() => {
                    if (noteText.trim()) {
                      onAddNote && onAddNote(event, noteText.trim());
                      setNoteText('');
                      setShowNoteInput(false);
                    }
                  }}
                >
                  Save Note
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
