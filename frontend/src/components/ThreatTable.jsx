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

function ThreatTable({
  riskAssessments = [],
  loading = false,
  error = null,
  selectedThreat = null,
  onSelectThreat,
}) {
  const columns = [
    { key: 'source_ip', label: 'SOURCE IP', align: 'left' },
    { key: 'risk_score', label: 'SCORE', align: 'left' },
    { key: 'risk_level', label: 'LEVEL', align: 'left' },
    { key: 'reasons', label: 'DETECTION FACTORS', align: 'left' },
    { key: 'action', label: 'ACTION', align: 'right' },
  ]

  return (
    <section className="threat-table-panel-mono">
      <div className="panel-header-mono">
        <div className="panel-title-group">
          <h2 className="panel-title-text">THREAT ASSESSMENTS</h2>
          <span className="panel-title-tag">LIVE TELEMETRY</span>
        </div>
        <span className="panel-count-mono">
          {loading
            ? 'ANALYZING...'
            : error
            ? 'API OFFLINE'
            : `${riskAssessments.length} ENTITIES RANKED`}
        </span>
      </div>

      <div className="table-wrap-mono">
        <table className="table-mono">
          <thead>
            <tr>
              {columns.map((col) => (
                <th
                  key={col.key}
                  className={`th-mono ${col.align === 'right' ? 'th-align-right' : ''}`}
                >
                  {col.label}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {/* 1. Loading State */}
            {loading && (
              <tr>
                <td colSpan={columns.length}>
                  <div className="table-state-mono">
                    <span className="state-mono-indicator">[ EXECUTING DETECTION PIPELINE ]</span>
                    <p className="state-mono-sub">
                      Processing behavioral feature vectors and Isolation Forest decision boundaries...
                    </p>
                  </div>
                </td>
              </tr>
            )}

            {/* 2. Error State */}
            {!loading && error && (
              <tr>
                <td colSpan={columns.length}>
                  <div className="table-state-mono table-state-mono--error">
                    <span className="state-mono-indicator">[ PIPELINE CONNECTION FAILED ]</span>
                    <p className="state-mono-sub">
                      Unable to reach FastAPI backend on http://127.0.0.1:8000. Verify the server is running.
                    </p>
                  </div>
                </td>
              </tr>
            )}

            {/* 3. Empty State */}
            {!loading && !error && riskAssessments.length === 0 && (
              <tr>
                <td colSpan={columns.length}>
                  <div className="table-state-mono">
                    <span className="state-mono-indicator">[ NO ENTITIES IDENTIFIED ]</span>
                    <p className="state-mono-sub">
                      Detection pipeline completed with an empty result set.
                    </p>
                  </div>
                </td>
              </tr>
            )}

            {/* 4. Real Data Rows */}
            {!loading &&
              !error &&
              riskAssessments.map((assessment) => {
                const isSelected = selectedThreat?.source_ip === assessment.source_ip
                const levelLower = (assessment.risk_level || 'low').toLowerCase()
                const clampedScore = Math.min(100, Math.max(0, assessment.risk_score || 0))

                return (
                  <tr
                    key={assessment.source_ip}
                    className={`tr-mono tr-mono--${levelLower} ${isSelected ? 'tr-mono--selected' : ''}`}
                  >
                    {/* Source IP */}
                    <td className="td-mono td-ip">
                      <div className="ip-cell-mono">
                        <span className={`status-dot ${getDotClass(assessment.risk_level)}`}></span>
                        <span className="ip-mono-text">{assessment.source_ip}</span>
                      </div>
                    </td>

                    {/* Risk Score */}
                    <td className="td-mono td-score">
                      <div className="score-cell-mono">
                        <div className="score-readout">
                          <span className="score-val">{assessment.risk_score}</span>
                          <span className="score-denom">/100</span>
                        </div>
                        <div className="score-bar-mono">
                          <div
                            className="score-fill-mono"
                            style={{ width: `${clampedScore}%` }}
                          ></div>
                        </div>
                      </div>
                    </td>

                    {/* Risk Level */}
                    <td className="td-mono td-level">
                      <div className="level-cell-mono">
                        <span className={`mono-level-badge mono-level-badge--${levelLower}`}>
                          {assessment.risk_level}
                        </span>
                        <span className="level-density-text">
                          {getDensityBars(assessment.risk_level)}
                        </span>
                      </div>
                    </td>

                    {/* Detection Factors */}
                    <td className="td-mono td-factors">
                      {Array.isArray(assessment.reasons) && assessment.reasons.length > 0 ? (
                        <div className="factors-wrap-mono">
                          {assessment.reasons.map((reason, idx) => (
                            <span key={idx} className="factor-chip-mono" title={reason}>
                              {reason}
                            </span>
                          ))}
                        </div>
                      ) : (
                        <span className="no-factors-mono">No suspicious signals</span>
                      )}
                    </td>

                    {/* Action */}
                    <td className="td-mono td-action">
                      <button
                        type="button"
                        className={`btn-table-action ${isSelected ? 'btn-table-action--active' : ''}`}
                        onClick={() => onSelectThreat && onSelectThreat(assessment)}
                        title={`Investigate ${assessment.source_ip}`}
                      >
                        [ INVESTIGATE ]
                      </button>
                    </td>
                  </tr>
                )
              })}
          </tbody>
        </table>
      </div>
    </section>
  )
}

export default ThreatTable
