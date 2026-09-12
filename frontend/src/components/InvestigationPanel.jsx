import { useEffect, useState } from 'react'

function getDotClass(level) {
  switch (level) {
    case 'CRITICAL':
      return 'dot-critical'
    case 'HIGH':
      return 'dot-high'
    case 'MEDIUM':
      return 'dot-medium'
    case 'LOW':
      return 'dot-low'
    default:
      return 'dot-muted'
  }
}

function getDensityBars(level) {
  switch (level) {
    case 'CRITICAL':
      return '████████'
    case 'HIGH':
      return '██████'
    case 'MEDIUM':
      return '████'
    case 'LOW':
      return '██'
    default:
      return '█'
  }
}

function getGuidance(level) {
  switch (level) {
    case 'CRITICAL':
      return {
        action: 'IMMEDIATE CONTAINMENT REQUIRED',
        detail:
          'Correlated threat indicators confirm active intrusion sequence. Recommend immediate network isolation of the source IP, session revocation, and escalation to Tier-2 incident response.',
      }
    case 'HIGH':
      return {
        action: 'PRIORITY TRIAGE & ACTIVE MONITORING',
        detail:
          'Multiple suspicious behavioral indicators triggered. Initiate credential audits, inspect outbound egress volumes, and track connection velocity.',
      }
    case 'MEDIUM':
      return {
        action: 'BEHAVIORAL OBSERVATION',
        detail:
          'Moderate risk activity detected. Cross-reference source IP against authentication logs and internal directory for anomalies.',
      }
    case 'LOW':
    default:
      return {
        action: 'ROUTINE OBSERVATION',
        detail:
          'Telemetry displays minimal suspicious variance. Entity remains in baseline automated monitoring queue.',
      }
  }
}

function InvestigationPanel({ threat, onClose }) {
  const [copied, setCopied] = useState(false)

  // Keyboard accessibility: close on Escape
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  if (!threat) return null

  const levelLower = (threat.risk_level || 'low').toLowerCase()
  const clampedScore = Math.min(100, Math.max(0, threat.risk_score || 0))
  const reasons = Array.isArray(threat.reasons) ? threat.reasons : []
  const guidance = getGuidance(threat.risk_level)

  const handleCopyIp = () => {
    if (threat.source_ip && navigator.clipboard) {
      navigator.clipboard.writeText(threat.source_ip)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  return (
    <div
      className="modal-backdrop-mono"
      onClick={onClose}
      role="presentation"
    >
      <div
        className="modal-dialog-mono"
        role="dialog"
        aria-modal="true"
        aria-labelledby="inv-dialog-title"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="modal-header-mono">
          <div className="modal-title-group">
            <div className="modal-breadcrumbs">
              <span className="mono-tag-small">CASE FILE</span>
              <span className="breadcrumb-slash">/</span>
              <span className={`status-dot ${getDotClass(threat.risk_level)}`}></span>
              <span className="mono-tag-small">{threat.risk_level}</span>
            </div>
            <h2 id="inv-dialog-title" className="modal-title-mono">
              TARGET // {threat.source_ip}
            </h2>
          </div>

          <button
            type="button"
            className="btn-modal-close-mono"
            onClick={onClose}
            aria-label="Close investigation"
            title="Close (Esc)"
          >
            [ ESC ]
          </button>
        </div>

        {/* Body */}
        <div className="modal-body-mono">
          {/* Key Metrics Grid */}
          <div className="modal-metrics-mono">
            {/* Risk Score */}
            <div className="metric-box-mono">
              <span className="box-label-mono">ASSESSED RISK SCORE</span>
              <div className="box-score-row">
                <span className="box-score-num">{threat.risk_score}</span>
                <span className="box-score-denom">/100</span>
              </div>
              <div className="box-bar-mono">
                <div
                  className="box-bar-fill-mono"
                  style={{ width: `${clampedScore}%` }}
                ></div>
              </div>
            </div>

            {/* Risk Level */}
            <div className="metric-box-mono">
              <span className="box-label-mono">SEVERITY LEVEL</span>
              <div className="box-level-row">
                <span className={`status-dot ${getDotClass(threat.risk_level)}`}></span>
                <span className={`mono-level-badge mono-level-badge--${levelLower}`}>
                  {threat.risk_level}
                </span>
              </div>
              <span className="box-density-mono">
                {getDensityBars(threat.risk_level)}
              </span>
            </div>

            {/* Total Indicators */}
            <div className="metric-box-mono">
              <span className="box-label-mono">FLAGGED SIGNALS</span>
              <div className="box-signals-row">
                <span className="box-signals-count">{reasons.length}</span>
                <span className="box-signals-label">INDICATORS</span>
              </div>
              <span className="box-caption-mono">CORRELATED FINDINGS</span>
            </div>
          </div>

          {/* Detection Factors */}
          <div className="modal-section-mono">
            <div className="section-title-row">
              <span className="section-title-mono">CONTRIBUTING DETECTION FACTORS</span>
              <span className="section-count-mono">{reasons.length} TRIGGERED</span>
            </div>

            {reasons.length > 0 ? (
              <div className="factors-list-mono">
                {reasons.map((reason, idx) => (
                  <div key={idx} className="factor-item-mono">
                    <div className="factor-item-num">[{String(idx + 1).padStart(2, '0')}]</div>
                    <div className="factor-item-content">
                      <div className="factor-item-text">{reason}</div>
                      <div className="factor-item-sub">
                        Behavioral telemetry matched deterministic or statistical anomaly threshold.
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="factors-empty-mono">
                <p>[ NO SUSPICIOUS SIGNALS RECORDED FOR THIS ENTITY ]</p>
              </div>
            )}
          </div>

          {/* Incident Response Guidance */}
          <div className="guidance-box-mono">
            <div className="guidance-header-mono">
              <span className={`status-dot ${getDotClass(threat.risk_level)}`}></span>
              <span className="guidance-title-mono">{guidance.action}</span>
            </div>
            <p className="guidance-detail-mono">{guidance.detail}</p>
          </div>
        </div>

        {/* Footer */}
        <div className="modal-footer-mono">
          <div className="footer-meta-mono">
            ENGINE // ISOLATION FOREST + SEQUENCE CORRELATOR
          </div>

          <div className="footer-actions-mono">
            <button
              type="button"
              className="btn-brutalist"
              onClick={handleCopyIp}
            >
              {copied ? '[ IP COPIED ]' : '[ COPY IP ]'}
            </button>

            <button
              type="button"
              className="btn-brutalist btn-brutalist--primary"
              onClick={onClose}
            >
              [ CLOSE CASE ]
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default InvestigationPanel
