import React, { useState, useEffect } from 'react';
import {
  FileCode, Download, Search, Tag, Copy, Check,
  ExternalLink, ShieldAlert, Cpu
} from 'lucide-react';

export default function IocTable({
  activeCase,
  apiBase = 'http://localhost:5000',
}) {
  const [iocs, setIocs] = useState([]);
  const [typeFilter, setTypeFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [copiedKey, setCopiedKey] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchIocs = async () => {
    if (!activeCase) return;
    setLoading(true);
    try {
      const res = await fetch(`${apiBase}/api/cases/${activeCase.case_id}/iocs`);
      if (res.ok) {
        const data = await res.json();
        setIocs(data.iocs || []);
      }
    } catch (e) {
      console.error('Failed to load IOCs:', e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchIocs();
  }, [activeCase]);

  const copyVal = (val, key) => {
    navigator.clipboard.writeText(val);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const filteredIocs = iocs.filter((ioc) => {
    if (typeFilter !== 'ALL' && ioc.ioc_type?.toLowerCase() !== typeFilter.toLowerCase()) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const matchVal = (ioc.ioc_value || '').toLowerCase().includes(q);
      const matchVendor = (ioc.vendor || '').toLowerCase().includes(q);
      const matchAtt = (ioc.attack_ids || []).join(' ').toLowerCase().includes(q);
      if (!matchVal && !matchVendor && !matchAtt) return false;
    }
    return true;
  });

  const getTypeBadge = (type) => {
    switch (type) {
      case 'bssid':
        return <span className="ioc-type-pill ioc-type--bssid">BSSID</span>;
      case 'mac':
        return <span className="ioc-type-pill ioc-type--mac">MAC</span>;
      case 'ipv4':
        return <span className="ioc-type-pill ioc-type--ipv4">IPv4</span>;
      case 'domain':
        return <span className="ioc-type-pill ioc-type--domain">Domain</span>;
      case 'ssid':
        return <span className="ioc-type-pill ioc-type--ssid">SSID</span>;
      case 'cert_sha256':
        return <span className="ioc-type-pill ioc-type--cert">Cert SHA256</span>;
      default:
        return <span className="ioc-type-pill">{type}</span>;
    }
  };

  return (
    <div className="ioc-container">
      {/* ── Toolbar ── */}
      <div className="triage-control-bar" style={{ marginBottom: '1.25rem' }}>
        <div className="triage-control-left">
          <div className="search-box-wrapper">
            <Search size={14} color="var(--text-secondary)" />
            <input
              type="text"
              className="search-input"
              placeholder="Search IOC value, vendor, domain…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
          </div>

          <select
            className="filter-select"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            <option value="ALL">All Indicator Types</option>
            <option value="bssid">BSSIDs (Access Points)</option>
            <option value="mac">MAC Addresses</option>
            <option value="ipv4">IPv4 Addresses</option>
            <option value="domain">Domains / Hostnames</option>
            <option value="ssid">SSIDs</option>
            <option value="cert_sha256">TLS Cert Fingerprints</option>
          </select>
        </div>

        <div className="triage-control-right">
          {activeCase && (
            <>
              <a
                href={`${apiBase}/api/cases/${activeCase.case_id}/iocs?format=csv`}
                download={`iocs_${activeCase.case_id}.csv`}
                className="btn-export-link"
              >
                <Download size={13} />
                <span>Export CSV</span>
              </a>

              <a
                href={`${apiBase}/api/cases/${activeCase.case_id}/iocs?format=stix2`}
                download={`stix2_${activeCase.case_id}.json`}
                className="btn-export-link btn-export--stix"
                title="Download OASIS STIX 2.1 Threat Intel Bundle"
              >
                <FileCode size={13} />
                <span>Export STIX 2.1</span>
              </a>

              <a
                href={`${apiBase}/api/cases/${activeCase.case_id}/iocs?format=json`}
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

      {/* ── IOCs Table ── */}
      <div className="card">
        <h2 className="card-title" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Tag size={17} color="var(--accent-cyan)" />
          Extracted Indicators of Compromise ({filteredIocs.length})
        </h2>

        <div className="table-responsive">
          <table className="dfir-table">
            <thead>
              <tr>
                <th style={{ width: '100px' }}>Type</th>
                <th>Indicator Value</th>
                <th>Hardware Vendor (OUI)</th>
                <th style={{ width: '70px' }}>Count</th>
                <th style={{ width: '150px' }}>First Seen (UTC)</th>
                <th style={{ width: '150px' }}>Last Seen (UTC)</th>
                <th>Triggered ATT&CK</th>
              </tr>
            </thead>
            <tbody>
              {filteredIocs.length === 0 ? (
                <tr>
                  <td colSpan={7} className="empty-table-cell">
                    No threat indicators mined for this case yet. Telemetry events will populate indicators automatically.
                  </td>
                </tr>
              ) : (
                filteredIocs.map((ioc, idx) => (
                  <tr key={idx} className="dfir-table-row">
                    <td>{getTypeBadge(ioc.ioc_type)}</td>
                    <td>
                      <div className="hash-chip-wrapper">
                        <code className="ioc-value-code">{ioc.ioc_value}</code>
                        <button
                          className="copy-icon-btn"
                          onClick={() => copyVal(ioc.ioc_value, `ioc-${idx}`)}
                          title="Copy indicator value"
                        >
                          {copiedKey === `ioc-${idx}` ? (
                            <Check size={12} color="var(--risk-low)" />
                          ) : (
                            <Copy size={12} />
                          )}
                        </button>
                      </div>
                    </td>
                    <td>
                      {ioc.vendor ? (
                        <div style={{ display: 'flex', alignItems: 'center', gap: '5px' }}>
                          <Cpu size={13} color="var(--accent-cyan)" />
                          <span>{ioc.vendor}</span>
                        </div>
                      ) : (
                        <span style={{ color: 'var(--text-muted)' }}>—</span>
                      )}
                    </td>
                    <td className="mono-cell">
                      <strong>{ioc.count}</strong>
                    </td>
                    <td className="mono-cell">{ioc.first_seen?.replace('T', ' ').replace('Z', '')}</td>
                    <td className="mono-cell">{ioc.last_seen?.replace('T', ' ').replace('Z', '')}</td>
                    <td>
                      <div style={{ display: 'flex', gap: '5px', flexWrap: 'wrap' }}>
                        {ioc.attack_ids && ioc.attack_ids.length > 0 ? (
                          ioc.attack_ids.map((tid) => (
                            <span key={tid} className="attack-pill">
                              {tid}
                            </span>
                          ))
                        ) : (
                          <span style={{ color: 'var(--text-muted)' }}>—</span>
                        )}
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
