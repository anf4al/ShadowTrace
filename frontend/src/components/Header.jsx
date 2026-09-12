function Header({
  loading = false,
  error = null,
  lastUpdated = null,
  onRefresh,
  activeTab = 'dashboard',
  count = 0,
}) {
  const isDashboard = activeTab === 'dashboard'

  return (
    <header className="soc-header">
      <div className="header-title-block">
        <div className="header-breadcrumb">
          <span className="mono-subtext">SHADOWTRACE</span>
          <span className="breadcrumb-slash">/</span>
          <span className="mono-subtext-active">
            {isDashboard ? 'DASHBOARD' : 'INVESTIGATIONS'}
          </span>
        </div>
        <h1 className="header-title">
          {isDashboard ? 'SECURITY OVERVIEW' : 'INCIDENT INVESTIGATIONS'}
        </h1>
        <p className="header-subtitle">
          {isDashboard
            ? 'Behavioral anomaly detection, Isolation Forest scoring, and sequence correlation'
            : 'Target triage queue and forensic indicator assessments'}
        </p>
      </div>

      <div className="header-actions">
        {lastUpdated && !loading && !error && (
          <span className="header-sync-mono">
            SYNC: <span className="sync-val">{lastUpdated}</span>
          </span>
        )}

        <div className="header-status-pill">
          {loading && (
            <span className="header-status-item">
              <span className="status-dot dot-muted"></span>
              <span className="mono-status-text">ANALYZING</span>
            </span>
          )}
          {error && (
            <span className="header-status-item">
              <span className="status-dot dot-critical"></span>
              <span className="mono-status-text">OFFLINE</span>
            </span>
          )}
          {!loading && !error && (
            <span className="header-status-item">
              <span className="status-dot dot-low"></span>
              <span className="mono-status-text">{count} ENTITIES MONITORED</span>
            </span>
          )}
        </div>

        {onRefresh && (
          <button
            type="button"
            className="btn-brutalist btn-brutalist--header"
            onClick={onRefresh}
            disabled={loading}
            title="Re-run detection pipeline"
          >
            {loading ? '[ RUNNING... ]' : '[ REFRESH ]'}
          </button>
        )}
      </div>
    </header>
  )
}

export default Header
