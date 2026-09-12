function Sidebar({
  loading = false,
  error = null,
  activeTab = 'dashboard',
  onSelectTab,
  onGoHome,
}) {
  const getEngineStatus = () => {
    if (loading) {
      return {
        label: 'ANALYZING',
        detail: 'PIPELINE RUNNING',
        dotClass: 'dot-muted',
      }
    }
    if (error) {
      return {
        label: 'OFFLINE',
        detail: 'CONNECTION ERROR',
        dotClass: 'dot-critical',
      }
    }
    return {
      label: 'ONLINE (V1.0)',
      detail: 'IFOREST + CORRELATOR',
      dotClass: 'dot-low',
    }
  }

  const engine = getEngineStatus()

  return (
    <aside className="soc-sidebar">
      <div className="sidebar-top">
        {/* Brand header */}
        <div
          className="sidebar-brand"
          onClick={onGoHome}
          role="button"
          tabIndex={0}
          title="Return to Home Screen"
        >
          <div className="brand-mark-mono">ST</div>
          <div className="brand-text">
            <span className="brand-name">SHADOWTRACE</span>
            <span className="brand-sub">DEFENSE PLATFORM</span>
          </div>
        </div>

        {/* Navigation Rail */}
        <nav className="sidebar-nav">
          <div className="nav-section-title">NAVIGATION</div>

          <button
            type="button"
            className={`nav-item ${activeTab === 'dashboard' ? 'nav-item--active' : ''}`}
            onClick={() => onSelectTab && onSelectTab('dashboard')}
          >
            <span className="nav-prefix">{activeTab === 'dashboard' ? '■' : '□'}</span>
            <span className="nav-label">DASHBOARD</span>
          </button>

          <button
            type="button"
            className={`nav-item ${activeTab === 'investigations' ? 'nav-item--active' : ''}`}
            onClick={() => onSelectTab && onSelectTab('investigations')}
          >
            <span className="nav-prefix">{activeTab === 'investigations' ? '■' : '□'}</span>
            <span className="nav-label">INVESTIGATIONS</span>
          </button>
        </nav>
      </div>

      {/* Engine Status Footer */}
      <div className="sidebar-footer">
        <div className="engine-status-box">
          <div className="engine-header">
            <span className={`status-dot ${engine.dotClass}`}></span>
            <span className="engine-label">DETECTION ENGINE</span>
          </div>
          <div className="engine-state-mono">{engine.label}</div>
          <div className="engine-detail-mono">{engine.detail}</div>
        </div>
      </div>
    </aside>
  )
}

export default Sidebar
