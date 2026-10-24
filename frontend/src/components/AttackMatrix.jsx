import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, ExternalLink, Tag, Info, AlertTriangle, X
} from 'lucide-react';

export default function AttackMatrix({
  activeCase,
  apiBase = 'http://localhost:5000',
}) {
  const [heatmapData, setHeatmapData] = useState(null);
  const [selectedTech, setSelectedTech] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchMatrix = async () => {
    setLoading(true);
    try {
      const url = activeCase
        ? `${apiBase}/api/intel/attack-matrix?case_id=${activeCase.case_id}`
        : `${apiBase}/api/intel/attack-matrix`;
      const res = await fetch(url);
      if (res.ok) {
        const data = await res.json();
        setHeatmapData(data.heatmap || data);
      }
    } catch (e) {
      console.error('Failed to load ATT&CK matrix:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchMatrix();
  }, [activeCase]);

  const matrixItems = heatmapData?.matrix || [];
  const tacticsMap = heatmapData?.tactics || {};

  const getHeatmapClass = (count) => {
    if (!count || count === 0) return 'heat--zero';
    if (count === 1) return 'heat--low';
    if (count <= 3) return 'heat--medium';
    return 'heat--high';
  };

  return (
    <div className="attack-matrix-container">
      {/* ── Summary bar ── */}
      <div className="card" style={{ marginBottom: '1.25rem' }}>
        <div className="attack-summary-header">
          <div className="attack-summary-title">
            <ShieldAlert size={18} color="var(--accent-cyan)" />
            <span>MITRE ATT&CK® Enterprise Wireless & AitM Coverage</span>
          </div>
          <div className="attack-summary-stats">
            <span>Observed ATT&CK Events: <strong>{heatmapData?.total_attack_events || 0}</strong></span>
          </div>
        </div>

        {/* Tactic chips */}
        <div className="tactic-chips-row">
          {Object.entries(tacticsMap).map(([tactic, cnt]) => (
            <div key={tactic} className="tactic-chip">
              <span className="tactic-name">{tactic}</span>
              <span className="tactic-count">{cnt}</span>
            </div>
          ))}
        </div>
      </div>

      {/* ── Techniques Grid ── */}
      <div className="card">
        <h2 className="card-title" style={{ marginBottom: '1rem' }}>
          Technique Heatmap Matrix (Click any technique for mitigation & evidence links)
        </h2>

        <div className="attack-grid">
          {matrixItems.map((tech) => {
            const count = tech.count || 0;
            return (
              <div
                key={tech.technique_id}
                className={`attack-card ${getHeatmapClass(count)}`}
                onClick={() => setSelectedTech(tech)}
              >
                <div className="attack-card-top">
                  <span className="attack-tech-id">{tech.technique_id}</span>
                  {count > 0 && <span className="attack-count-badge">{count} hits</span>}
                </div>
                <div className="attack-card-name">{tech.name}</div>
                <div className="attack-card-tactic">{tech.tactic}</div>
              </div>
            );
          })}
        </div>
      </div>

      {/* ── Detail Modal ── */}
      {selectedTech && (
        <div className="modal-overlay" onClick={() => setSelectedTech(null)}>
          <div className="modal-dialog" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <div className="modal-title">
                <Tag size={18} color="var(--accent-cyan)" />
                <span>
                  {selectedTech.technique_id}: {selectedTech.name}
                </span>
              </div>
              <button className="modal-close-btn" onClick={() => setSelectedTech(null)}>
                <X size={18} />
              </button>
            </div>

            <div className="modal-body">
              <div className="drawer-meta-row" style={{ marginBottom: '10px' }}>
                <span className="meta-label">Tactic:</span>
                <span className="meta-val">{selectedTech.tactic}</span>
              </div>

              <div className="drawer-meta-row" style={{ marginBottom: '10px' }}>
                <span className="meta-label">Observed Hits:</span>
                <span className="meta-val">
                  <strong>{selectedTech.count || 0} occurrences in active case</strong>
                </span>
              </div>

              <div className="drawer-section">
                <h3 className="drawer-section-title">Technique Description</h3>
                <p className="drawer-text-block">{selectedTech.description}</p>
              </div>

              <div style={{ marginTop: '14px', display: 'flex', justifyContent: 'flex-end' }}>
                <a
                  href={selectedTech.url}
                  target="_blank"
                  rel="noreferrer"
                  className="btn-primary"
                  style={{ display: 'inline-flex', alignItems: 'center', gap: '6px' }}
                >
                  <span>View Official MITRE Spec</span>
                  <ExternalLink size={13} />
                </a>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
