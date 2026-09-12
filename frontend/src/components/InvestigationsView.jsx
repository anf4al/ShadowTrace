import { useState } from 'react'

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

function InvestigationsView({
  riskAssessments = [],
  loading = false,
  error = null,
  onSelectThreat,
  selectedThreat,
}) {
  const [filterLevel, setFilterLevel] = useState('ALL')

  const counts = {
    ALL: riskAssessments.length,
    CRITICAL: riskAssessments.filter((a) => a.risk_level === 'CRITICAL').length,
    HIGH: riskAssessments.filter((a) => a.risk_level === 'HIGH').length,
    MEDIUM: riskAssessments.filter((a) => a.risk_level === 'MEDIUM').length,
    LOW: riskAssessments.filter((a) => a.risk_level === 'LOW').length,
  }

  const filteredAssessments = riskAssessments.filter((a) => {
    if (filterLevel === 'ALL') return true
    return a.risk_level === filterLevel
  })

  return (
    <section className="investigations-view">
      {/* View Header */}
      <div className="view-header-row">
        <div className="view-title-block">
          <div className="view-title-wrap">
            <h2 className="view-title">ACTIVE INVESTIGATIONS</h2>
            <span className="view-badge">TRIAGE QUEUE</span>
          </div>
          <p className="view-subtitle">
            Focused security incident analysis and forensic examination records
          </p>
        </div>

        {/* Severity Filter Controls */}
        <div className="investigations-filter-bar">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((lvl) => (
            <button
              key={lvl}
              type="button"
              className={`filter-btn ${filterLevel === lvl ? 'filter-btn--active' : ''}`}
              onClick={() => setFilterLevel(lvl)}
            >
              {lvl !== 'ALL' && <span className={`status-dot ${getDotClass(lvl)}`}></span>}
              <span className="filter-label">{lvl}</span>
              <span className="filter-count">{counts[lvl] || 0}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Loading state */}
      {loading && (
        <div className="view-state-card">
          <span className="state-mono-indicator">[ EXECUTING DETECTION PIPELINE ]</span>
          <p className="state-desc">Retrieving telemetry and evaluating threat scoring models...</p>
        </div>
      )}

      {/* Error state */}
      {!loading && error && (
        <div className="view-state-card view-state-card--error">
          <span className="state-mono-indicator">[ PIPELINE OFFLINE ]</span>
          <p className="state-desc">{error}</p>
        </div>
      )}

      {/* Empty list */}
      {!loading && !error && filteredAssessments.length === 0 && (
        <div className="view-state-card">
          <span className="state-mono-indicator">[ NO INCIDENTS IN QUEUE ]</span>
          <p className="state-desc">
            No entities match the current severity filter ({filterLevel}).
          </p>
        </div>
      )}

      {/* Incident List */}
      {!loading && !error && filteredAssessments.length > 0 && (
        <div className="investigations-list">
          {filteredAssessments.map((assessment) => {
            const isSelected = selectedThreat?.source_ip === assessment.source_ip

            return (
              <div
                key={assessment.source_ip}
                className={`investigation-item ${isSelected ? 'investigation-item--selected' : ''}`}
              >
                <div className="inv-item-top">
                  <div className="inv-item-identity">
                    <span className={`status-dot ${getDotClass(assessment.risk_level)}`}></span>
                    <span className="inv-item-ip">{assessment.source_ip}</span>
                    <span className={`inv-level-tag inv-level-tag--${assessment.risk_level.toLowerCase()}`}>
                      {assessment.risk_level}
                    </span>
                    <span className="inv-density-bars">
                      {getDensityBars(assessment.risk_level)}
                    </span>
                  </div>

                  <div className="inv-item-score">
                    <span className="inv-score-label">RISK:</span>
                    <span className="inv-score-val">{assessment.risk_score}</span>
                    <span className="inv-score-denom">/100</span>
                  </div>
                </div>

                <div className="inv-item-factors">
                  <div className="inv-factors-title">FLAGGED SIGNALS:</div>
                  <div className="inv-factors-tags">
                    {Array.isArray(assessment.reasons) && assessment.reasons.length > 0 ? (
                      assessment.reasons.map((reason, idx) => (
                        <span key={idx} className="mono-tag" title={reason}>
                          {reason}
                        </span>
                      ))
                    ) : (
                      <span className="mono-tag mono-tag--muted">No suspicious indicators recorded</span>
                    )}
                  </div>
                </div>

                <div className="inv-item-actions">
                  <span className="inv-item-status-text">STATUS: PENDING ANALYST REVIEW</span>
                  <button
                    type="button"
                    className="btn-brutalist"
                    onClick={() => onSelectThreat && onSelectThreat(assessment)}
                  >
                    [ OPEN INVESTIGATION ]
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}

export default InvestigationsView
