import React, { useState, useEffect } from 'react';
import {
  GitCommit, AlertTriangle, ShieldCheck, Download, Plus,
  FileText, Camera, Radio, Filter, Search, ChevronDown, CheckCircle
} from 'lucide-react';

export default function TimelineView({
  activeCase,
  apiBase = 'http://localhost:5000',
  apiToken = '',
}) {
  const [timeline, setTimeline] = useState([]);
  const [correlations, setCorrelations] = useState([]);
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchHost, setSearchHost] = useState('');
  const [newNote, setNewNote] = useState('');
  const [isSubmittingNote, setIsSubmittingNote] = useState(false);
  const [loading, setLoading] = useState(false);

  const fetchTimelineData = async () => {
    if (!activeCase) return;
    setLoading(true);
    try {
      // 1. Fetch Timeline items
      const tUrl = `${apiBase}/api/cases/${activeCase.case_id}/timeline?limit=300`;
      const tRes = await fetch(tUrl);
      if (tRes.ok) {
        const tData = await tRes.json();
        setTimeline(tData.timeline || []);
      }

      // 2. Fetch Correlated Incidents
      const cUrl = `${apiBase}/api/cases/${activeCase.case_id}/timeline/correlations`;
      const cRes = await fetch(cUrl);
      if (cRes.ok) {
        const cData = await cRes.json();
        setCorrelations(cData.incidents || []);
      }
    } catch (e) {
      console.error('Error fetching timeline data:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTimelineData();
  }, [activeCase]);

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNote.trim() || !activeCase) return;

    try {
      setIsSubmittingNote(true);
      const res = await fetch(`${apiBase}/api/cases/${activeCase.case_id}/notes`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-API-Token': apiToken,
        },
        body: JSON.stringify({
          content: newNote.trim(),
          author: activeCase.examiner,
        }),
      });

      if (res.ok) {
        setNewNote('');
        fetchTimelineData();
      }
    } catch (err) {
      console.error('Failed to submit note:', err);
    } finally {
      setIsSubmittingNote(false);
    }
  };

  // Filter items
  const filteredTimeline = timeline.filter((item) => {
    if (sourceFilter !== 'ALL' && (item.source || '').toLowerCase() !== sourceFilter.toLowerCase()) {
      return false;
    }
    if (severityFilter !== 'ALL' && (item.severity || '').toUpperCase() !== severityFilter) {
      return false;
    }
    if (searchHost.trim()) {
      const q = searchHost.toLowerCase();
      const matchSummary = (item.summary || '').toLowerCase().includes(q);
      const matchEntities = JSON.stringify(item.entities || {}).toLowerCase().includes(q);
      if (!matchSummary && !matchEntities) return false;
    }
    return true;
  });

  const getCategoryIcon = (category) => {
    switch (category) {
      case 'SNAPSHOT':
        return <Camera size={14} color="var(--accent-cyan)" />;
      case 'EVIDENCE':
        return <FileText size={14} color="var(--accent-blue)" />;
      case 'NOTE':
        return <FileText size={14} color="var(--risk-med)" />;
      default:
        return <GitCommit size={14} color="var(--accent-purple)" />;
    }
  };

  const getSeverityBadge = (sev) => {
    const s = (sev || 'INFO').toUpperCase();
    return <span className={`badge-severity badge-severity--${s.toLowerCase()}`}>{s}</span>;
  };

  return (
    <div className="timeline-container">
      {/* ── Correlated Multi-Stage Incident Chains ── */}
      {correlations.length > 0 && (
        <section className="card correlation-chains-card" style={{ marginBottom: '1.25rem' }}>
          <h2 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--risk-high)' }}>
            <AlertTriangle size={18} />
            Correlated Multi-Stage Incident Chains ({correlations.length})
          </h2>

          <div className="correlation-grid">
            {correlations.map((inc) => (
              <div key={inc.incident_id} className="correlation-card">
                <div className="correlation-card-top">
                  <span className="badge-severity badge-severity--critical">{inc.severity}</span>
                  <span className="corr-rule-pill">{inc.rule_name}</span>
                  <span className="confidence-pill" style={{ marginLeft: 'auto' }}>
                    Confidence: {(inc.confidence * 100).toFixed(0)}%
                  </span>
                </div>

                <div className="correlation-card-title">{inc.title}</div>
                <p className="correlation-card-summary">{inc.summary}</p>

                {inc.recommendations && inc.recommendations.length > 0 && (
                  <div className="corr-recommendations">
                    <strong>Recommended Containment:</strong>
                    <ul>
                      {inc.recommendations.map((rec, i) => (
                        <li key={i}>{rec}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="corr-contributing-row">
                  <span>Contributing Telemetry IDs:</span>
                  <div className="contributing-ids-list">
                    {inc.contributing_event_ids?.map((id) => (
                      <code key={id} className="id-chip">{id}</code>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      {/* ── Timeline Filter & Export Toolbar ── */}
      <div className="triage-control-bar" style={{ marginBottom: '1rem' }}>
        <div className="triage-control-left">
          <div className="search-box-wrapper">
            <Search size={14} color="var(--text-secondary)" />
            <input
              type="text"
              className="search-input"
              placeholder="Search host IP, MAC, SSID in timeline…"
              value={searchHost}
              onChange={(e) => setSearchHost(e.target.value)}
            />
          </div>

          <select
            className="filter-select"
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
          >
            <option value="ALL">All Sources</option>
            <option value="live">Live Detections</option>
            <option value="pcap">PCAP Extractions</option>
            <option value="snapshot">Snapshots</option>
            <option value="analyst">Analyst Notes</option>
          </select>

          <select
            className="filter-select"
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="INFO">Info</option>
          </select>
        </div>

        <div className="triage-control-right">
          {activeCase && (
            <>
              <a
                href={`${apiBase}/api/cases/${activeCase.case_id}/timeline?format=csv`}
                download={`timeline_${activeCase.case_id}.csv`}
                className="btn-export-link"
              >
                <Download size={13} />
                <span>Export CSV</span>
              </a>
              <a
                href={`${apiBase}/api/cases/${activeCase.case_id}/timeline?format=json`}
                target="_blank"
                rel="noreferrer"
                className="btn-export-link"
              >
                <Download size={13} />
                <span>JSON</span>
              </a>
            </>
          )}
        </div>
      </div>

      {/* ── Add Analyst Note Box ── */}
      {activeCase && (
        <form onSubmit={handleAddNote} className="card add-note-box" style={{ marginBottom: '1.25rem' }}>
          <div className="add-note-header">
            <FileText size={15} color="var(--accent-cyan)" />
            <span>Record Investigative Observation (Chain-of-Custody Logged)</span>
          </div>
          <div className="add-note-input-row">
            <textarea
              className="form-textarea"
              rows={2}
              placeholder="Record forensic observation, containment action, or physical survey finding..."
              value={newNote}
              onChange={(e) => setNewNote(e.target.value)}
            />
            <button
              type="submit"
              className="btn-primary"
              disabled={isSubmittingNote || !newNote.trim()}
              style={{ alignSelf: 'flex-end', minWidth: '120px' }}
            >
              {isSubmittingNote ? 'Saving…' : 'Add Note'}
            </button>
          </div>
        </form>
      )}

      {/* ── Chronological Super-Timeline Stream ── */}
      <div className="card timeline-stream-card">
        <h3 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <GitCommit size={16} color="var(--accent-cyan)" />
          Chronological Event Swimlane ({filteredTimeline.length} entries)
        </h3>

        {filteredTimeline.length === 0 ? (
          <div className="empty-state-box">
            No events found matching current timeline filters.
          </div>
        ) : (
          <div className="timeline-swimlane">
            {filteredTimeline.map((item, idx) => (
              <div key={item.id || idx} className="swimlane-node">
                <div className="swimlane-line" />
                <div className={`swimlane-icon-bubble category--${item.category?.toLowerCase()}`}>
                  {getCategoryIcon(item.category)}
                </div>

                <div className="swimlane-card">
                  <div className="swimlane-card-top">
                    <span className="mono-text time-text">{item.ts_utc}</span>
                    <span className="source-tag">{item.source}</span>
                    {item.severity && getSeverityBadge(item.severity)}
                    {item.attack_id && <span className="attack-pill">{item.attack_id}</span>}
                    {item.synthetic && <span className="training-chip-sm">SYNTHETIC</span>}
                  </div>

                  <div className="swimlane-summary">
                    <strong>{item.type}:</strong> {item.summary}
                  </div>

                  {item.entities && Object.keys(item.entities).length > 0 && (
                    <div className="swimlane-entities-chips">
                      {Object.entries(item.entities).map(([k, v]) => (
                        <div key={k} className="entity-chip">
                          <span className="entity-chip-k">{k}:</span>
                          <span className="entity-chip-v">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
