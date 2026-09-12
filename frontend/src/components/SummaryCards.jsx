function MetricCard({ title, value, description, dotClass, badge }) {
  return (
    <div className="metric-card-mono">
      <div className="metric-top-row">
        <div className="metric-title-group">
          {dotClass && <span className={`status-dot ${dotClass}`}></span>}
          <span className="metric-label">{title}</span>
        </div>
        {badge && <span className="metric-tag">{badge}</span>}
      </div>

      <div className="metric-num-wrap">
        <span className="metric-num">{value}</span>
      </div>

      <div className="metric-caption">{description}</div>
    </div>
  )
}

function SummaryCards({ riskAssessments = [], loading = false, error = null }) {
  const activeThreatsCount = riskAssessments.filter(
    (item) => item.risk_level === 'HIGH' || item.risk_level === 'CRITICAL'
  ).length

  const criticalRiskCount = riskAssessments.filter(
    (item) => item.risk_level === 'CRITICAL'
  ).length

  const mlAnomaliesCount = riskAssessments.filter(
    (item) =>
      Array.isArray(item.reasons) &&
      item.reasons.includes('Isolation Forest detected anomalous behavior')
  ).length

  const totalAssessedCount = riskAssessments.length

  const formatMetric = (computedValue) => {
    if (loading) return '...'
    if (error) return '—'
    return computedValue
  }

  const metrics = [
    {
      id: 'threats',
      title: 'ACTIVE THREATS',
      value: formatMetric(activeThreatsCount),
      description: 'HIGH & CRITICAL risk entities',
      dotClass: activeThreatsCount > 0 ? 'dot-critical' : 'dot-low',
      badge: activeThreatsCount > 0 ? 'PRIORITY' : 'CLEAR',
    },
    {
      id: 'critical',
      title: 'CRITICAL RISK',
      value: formatMetric(criticalRiskCount),
      description: 'Score 80–100 containment targets',
      dotClass: criticalRiskCount > 0 ? 'dot-critical' : 'dot-low',
      badge: criticalRiskCount > 0 ? 'CONTAIN' : 'ZERO',
    },
    {
      id: 'anomalies',
      title: 'ML ANOMALIES',
      value: formatMetric(mlAnomaliesCount),
      description: 'Isolation Forest outlier predictions',
      dotClass: 'dot-muted',
      badge: 'MODEL',
    },
    {
      id: 'entities',
      title: 'EVALUATED ENTITIES',
      value: formatMetric(totalAssessedCount),
      description: 'Source IP entities assessed',
      dotClass: 'dot-low',
      badge: 'TOTAL',
    },
  ]

  return (
    <section className="summary-grid-mono">
      {metrics.map((m) => (
        <MetricCard
          key={m.id}
          title={m.title}
          value={m.value}
          description={m.description}
          dotClass={m.dotClass}
          badge={m.badge}
        />
      ))}
    </section>
  )
}

export default SummaryCards
