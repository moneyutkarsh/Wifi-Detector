import React, { useState } from 'react';
import { Shield, X, AlertCircle, CheckSquare, Square } from 'lucide-react';

export default function NewCaseModal({ isOpen, onClose, onCreateCase }) {
  const [title, setTitle] = useState('');
  const [examiner, setExaminer] = useState('');
  const [authRef, setAuthRef] = useState('');
  const [notes, setNotes] = useState('');
  const [synthetic, setSynthetic] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState('');

  if (!isOpen) return null;

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (!title.trim()) {
      setError('Case title is required.');
      return;
    }
    if (!examiner.trim()) {
      setError('Lead examiner name is required.');
      return;
    }
    if (!authRef.trim()) {
      setError('Authorization reference (warrant, ticket, or engagement #) is required.');
      return;
    }
    if (!acknowledged) {
      setError('You must acknowledge investigative authorization to establish a defensible chain of custody.');
      return;
    }

    try {
      setIsSubmitting(true);
      await onCreateCase({
        title: title.trim(),
        examiner: examiner.trim(),
        authorization_ref: authRef.trim(),
        notes: notes.trim(),
        synthetic,
      });
      onClose();
    } catch (err) {
      setError(err.message || 'Failed to create case');
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="modal-overlay">
      <div className="modal-dialog">
        <div className="modal-header">
          <div className="modal-title">
            <Shield size={20} color="var(--accent-cyan)" />
            <span>Open New DFIR Forensic Case</span>
          </div>
          <button className="modal-close-btn" onClick={onClose}>
            <X size={18} />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="modal-body">
          {error && (
            <div className="modal-alert-error">
              <AlertCircle size={16} />
              <span>{error}</span>
            </div>
          )}

          <div className="form-group">
            <label className="form-label">Investigation Title *</label>
            <input
              type="text"
              className="form-input"
              placeholder="e.g. Rogue Access Point Triage - HQ Floor 3"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              required
            />
          </div>

          <div className="form-row">
            <div className="form-group" style={{ flex: 1 }}>
              <label className="form-label">Lead Examiner / Analyst *</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. Investigator Holmes"
                value={examiner}
                onChange={(e) => setExaminer(e.target.value)}
                required
              />
            </div>

            <div className="form-group" style={{ flex: 1 }}>
              <label className="form-label">Authorization Ref / Warrant # *</label>
              <input
                type="text"
                className="form-input"
                placeholder="e.g. ENG-2026-9024 or TICKET-4481"
                value={authRef}
                onChange={(e) => setAuthRef(e.target.value)}
                required
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Initial Notes & Context (Optional)</label>
            <textarea
              className="form-textarea"
              rows={3}
              placeholder="Record initial wireless telemetry triggers or incident scope..."
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
            />
          </div>

          <div className="form-checkbox-row">
            <label className="checkbox-label">
              <input
                type="checkbox"
                checked={synthetic}
                onChange={(e) => setSynthetic(e.target.checked)}
              />
              <span className="checkbox-text">
                <strong>Training / Simulation Mode (Synthetic Data)</strong>
                <br />
                <small style={{ color: 'var(--text-secondary)' }}>
                  Marks evidence as synthetic to exclude from real incident statistics.
                </small>
              </span>
            </label>
          </div>

          <div className="form-ack-box">
            <div
              className="form-ack-check"
              onClick={() => setAcknowledged(!acknowledged)}
              role="checkbox"
              aria-checked={acknowledged}
              tabIndex={0}
            >
              {acknowledged ? (
                <CheckSquare size={18} color="var(--accent-cyan)" />
              ) : (
                <Square size={18} color="var(--text-secondary)" />
              )}
              <span className="form-ack-text">
                I certify that collection and monitoring in this case are conducted in accordance with
                applicable legal authority and corporate rules of engagement.
              </span>
            </div>
          </div>

          <div className="modal-footer">
            <button type="button" className="btn-secondary" onClick={onClose}>
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary"
              disabled={isSubmitting || !acknowledged}
            >
              {isSubmitting ? 'Opening Case…' : 'Open Investigation Case'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
