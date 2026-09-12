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

function RiskDistribution({ riskAssessments = [], counts: passedCounts, loading = false }) {
  const total = riskAssessments.length

  const counts = passedCounts || {
    CRITICAL: riskAssessments.filter((a) => a.risk_level === 'CRITICAL').length,
    HIGH: riskAssessments.filter((a) => a.risk_level === 'HIGH').length,
    MEDIUM: riskAssessments.filter((a) => a.risk_level === 'MEDIUM').length,
    LOW: riskAssessments.filter((a) => a.risk_level === 'LOW').length,
  }

  const levels = [
    {
      key: 'CRITICAL',
      label: 'CRITICAL',
      density: '████████',
      scoreRange: 'SCORE 80–100',
    },
    {
      key: 'HIGH',
      label: 'HIGH',
      density: '██████',
      scoreRange: 'SCORE 60–79',
    },
    {
      key: 'MEDIUM',
      label: 'MEDIUM',
      density: '████',
      scoreRange: 'SCORE 30–59',
    },
    {
      key: 'LOW',
      label: 'LOW',
      density: '██',
      scoreRange: 'SCORE 0–29',
    },
  ]

  const calculatePercentage = (count) => {
    if (!total || total === 0) return 0
    return Math.round((count / total) * 1000) / 10
  }

  return (
    <section className="distribution-panel-mono">
      <div className="panel-header-mono">
        <div className="panel-title-group">
          <h2 className="panel-title-text">RISK DISTRIBUTION</h2>
          <span className="panel-title-tag">SEVERITY SPREAD</span>
        </div>
        <span className="panel-count-mono">
          {loading ? 'CALCULATING...' : `${total} TOTAL ENTITIES`}
        </span>
      </div>

      {total === 0 && !loading ? (
        <div className="panel-empty-mono">
          <p>[ NO RISK ASSESSMENTS AVAILABLE TO CALCULATE DISTRIBUTION ]</p>
        </div>
      ) : (
        <div className="dist-grid-mono">
          {levels.map((lvl) => {
            const count = counts[lvl.key] || 0
            const percentage = calculatePercentage(count)

            return (
              <div key={lvl.key} className="dist-item-mono">
                <div className="dist-item-header">
                  <div className="dist-item-label-group">
                    <span className={`status-dot ${getDotClass(lvl.key)}`}></span>
                    <span className="dist-item-level">{lvl.label}</span>
                    <span className="dist-item-density">{lvl.density}</span>
                  </div>

                  <div className="dist-item-stats">
                    <span className="dist-item-count">{loading ? '...' : count}</span>
                    <span className="dist-item-pct">
                      {loading ? '' : `(${percentage}%)`}
                    </span>
                  </div>
                </div>

                {/* Proportional horizontal bar */}
                <div className="dist-bar-track-mono">
                  <div
                    className="dist-bar-fill-mono"
                    style={{ width: `${percentage}%` }}
                    title={`${lvl.key}: ${count} entities (${percentage}%)`}
                  ></div>
                </div>

                <div className="dist-item-footer">
                  <span className="dist-item-range">{lvl.scoreRange}</span>
                  <span className="dist-item-units">
                    {count === 1 ? '1 ENTITY' : `${count} ENTITIES`}
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </section>
  )
}

export default RiskDistribution
