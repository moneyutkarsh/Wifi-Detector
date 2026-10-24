import React, { useState, useEffect, useRef } from 'react';
import {
  Radio, Play, Pause, Filter, Search, ShieldAlert,
  ChevronRight, ExternalLink, Activity, RefreshCw, Tag
} from 'lucide-react';
import EventDrawer from './EventDrawer';

export default function LiveTriage({
  activeCase,
  apiBase = 'http://localhost:5000',
  onAddNoteToCase,
}) {
  const [events, setEvents] = useState([]);
  const [isPaused, setIsPaused] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [sseConnected, setSseConnected] = useState(false);

  const eventSourceRef = useRef(null);

  // Initial fetch of recent events
  const fetchRecentEvents = async () => {
    try {
      const url = activeCase
        ? `${apiBase}/api/events?case_id=${activeCase.case_id}&limit=100`
        : `${apiBase}/api/events?limit=100`;
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setEvents(data.events || []);
      }
    } catch (e) {
      console.error('Failed to fetch events:', e);
    }
  };

  useEffect(() => {
    fetchRecentEvents();
  }, [activeCase]);

  // Connect to SSE stream
  useEffect(() => {
    if (isPaused) {
      if (eventSourceRef.current) {
        eventSourceRef.current.close();
        eventSourceRef.current = null;
        setSseConnected(false);
      }
      return;
    }

    const sseUrl = `${apiBase}/api/stream`;
    const es = new EventSource(sseUrl);
    eventSourceRef.current = es;

    es.onopen = () => {
      setSseConnected(true);
    };

    es.onmessage = (event) => {
      try {
        const evt = JSON.parse(event.data);
        if (evt && evt.id) {
          setEvents((prev) => {
            // Deduplicate
            if (prev.some((e) => e.id === evt.id)) return prev;
            return [evt, ...prev.slice(0, 199)];
          });
        }
      } catch (err) {
        // Ping or format error
      }
    };

    es.onerror = () => {
      setSseConnected(false);
    };

    return () => {
      es.close();
      eventSourceRef.current = null;
    };
  }, [isPaused, apiBase]);

  // Filter events
  const filteredEvents = events.filter((e) => {
    if (severityFilter !== 'ALL' && (e.severity || '').toUpperCase() !== severityFilter) {
      return false;
    }
    if (sourceFilter !== 'ALL' && (e.source || '').toLowerCase() !== sourceFilter.toLowerCase()) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const typeMatch = (e.type || '').toLowerCase().includes(q);
      const rationaleMatch = (e.rationale || '').toLowerCase().includes(q);
      const entityMatch = JSON.stringify(e.entities || {}).toLowerCase().includes(q);
      const attackMatch = (e.attack_id || '').toLowerCase().includes(q);
      if (!typeMatch && !rationaleMatch && !entityMatch && !attackMatch) {
        return false;
      }
    }
    return true;
  });

  const getSeverityBadge = (sev) => {
    const s = (sev || 'INFO').toUpperCase();
    return <span className={`badge-severity badge-severity--${s.toLowerCase()}`}>{s}</span>;
  };

  return (
    <div className="triage-container">
      {/* Control bar */}
      <div className="triage-control-bar">
        <div className="triage-control-left">
          <div className="stream-status-badge">
            <Activity
              size={14}
              className={sseConnected && !isPaused ? 'pulse' : ''}
              color={isPaused ? 'var(--text-muted)' : sseConnected ? 'var(--accent-cyan)' : 'var(--risk-med)'}
            />
            <span>
              {isPaused ? 'Stream Paused' : sseConnected ? 'Real-Time Stream Active' : 'Polling Fallback'}
            </span>
          </div>

          <button
            className={`btn-pause-toggle ${isPaused ? 'paused' : 'live'}`}
            onClick={() => setIsPaused(!isPaused)}
            title={isPaused ? 'Resume live streaming' : 'Pause stream to freeze view'}
          >
            {isPaused ? <Play size={13} /> : <Pause size={13} />}
            <span>{isPaused ? 'Resume Feed' : 'Pause Feed'}</span>
          </button>

          <button
            className="btn-refresh-sm"
            onClick={fetchRecentEvents}
            title="Refresh events from database"
          >
            <RefreshCw size={13} />
          </button>
        </div>

        <div className="triage-control-right">
          {/* Search */}
          <div className="search-box-wrapper">
            <Search size={14} color="var(--text-secondary)" />
            <input
              type="text"
              className="search-input"
              placeholder="Search type, IP, MAC, attack ID…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          {/* Severity filter */}
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
          </select>

          {/* Source filter */}
          <select
            className="filter-select"
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
          >
            <option value="ALL">All Sources</option>
            <option value="live">Live Detection</option>
            <option value="pcap">PCAP File</option>
            <option value="snapshot">Snapshot</option>
            <option value="analyst">Analyst</option>
          </select>
        </div>
      </div>

      {/* Events Table */}
      <div className="card triage-table-card">
        <div className="triage-table-header-row">
          <span className="count-label">
            Showing <strong>{filteredEvents.length}</strong> events
          </span>
          {activeCase && (
            <span className="case-filter-badge">
              Scoped to Case: <code>{activeCase.case_id}</code>
            </span>
          )}
        </div>

        <div className="table-responsive">
          <table className="dfir-table">
            <thead>
              <tr>
                <th style={{ width: '160px' }}>UTC Timestamp</th>
                <th style={{ width: '110px' }}>Severity</th>
                <th style={{ width: '85px' }}>Source</th>
                <th>Finding / Event Type</th>
                <th>Entities Preview</th>
                <th style={{ width: '110px' }}>ATT&CK</th>
                <th style={{ width: '85px' }}>Confidence</th>
                <th style={{ width: '60px' }}>Inspect</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={8} className="empty-table-cell">
                    No matching events detected in current telemetry window.
                  </td>
                </tr>
              ) : (
                filteredEvents.map((evt) => {
                  const entities = typeof evt.entities === 'string'
                    ? (() => { try { return JSON.parse(evt.entities); } catch { return {}; } })()
                    : (evt.entities || {});

                  const entitySummary = Object.entries(entities)
                    .slice(0, 2)
                    .map(([k, v]) => `${k}: ${v}`)
                    .join(' · ');

                  return (
                    <tr
                      key={evt.id}
                      className="dfir-table-row clickable-row"
                      onClick={() => setSelectedEvent(evt)}
                    >
                      <td className="mono-cell">{evt.ts_utc?.replace('T', ' ').replace('Z', '')}</td>
                      <td>{getSeverityBadge(evt.severity)}</td>
                      <td>
                        <span className="source-tag">{evt.source}</span>
                      </td>
                      <td>
                        <strong>{evt.type}</strong>
                        {evt.synthetic && <span className="training-chip-sm" style={{ marginLeft: '6px' }}>SYN</span>}
                      </td>
                      <td className="entity-preview-cell" title={JSON.stringify(entities)}>
                        {entitySummary || <span style={{ color: 'var(--text-muted)' }}>—</span>}
                      </td>
                      <td>
                        {evt.attack_id ? (
                          <span className="attack-pill">{evt.attack_id}</span>
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>—</span>
                        )}
                      </td>
                      <td>
                        <div className="confidence-mini-bar">
                          <span>{((evt.confidence || 1.0) * 100).toFixed(0)}%</span>
                        </div>
                      </td>
                      <td>
                        <button
                          className="btn-inspect-row"
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedEvent(evt);
                          }}
                          title="Inspect raw event details"
                        >
                          <ChevronRight size={14} />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Slide-out Event Drawer */}
      {selectedEvent && (
        <EventDrawer
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          onAddNote={(evt, note) => {
            if (activeCase && onAddNoteToCase) {
              onAddNoteToCase(activeCase.case_id, note);
            }
          }}
          onEscalate={(evt) => {
            alert(`Event ${evt.id} escalated to high-priority triage incident.`);
          }}
        />
      )}
    </div>
  );
}
