function Landing({ onRunTest, loading = false }) {
  return (
    <div className="landing-container">
      <div className="landing-content">
        <div className="landing-meta-top">
          <span className="landing-classification">INTERNAL SECURITY TELEMETRY // SOC ENGINE</span>
        </div>

        <h1 className="landing-title">SHADOWTRACE</h1>

        <p className="landing-description">
          Behavioral threat detection using rule-based correlation,
          machine learning anomaly detection, and risk scoring.
        </p>

        <div className="landing-action-wrap">
          <button
            type="button"
            className="btn-run-test"
            onClick={onRunTest}
            disabled={loading}
            autoFocus
          >
            {loading ? (
              <span className="btn-run-test-loading">
                <span className="loading-char-spin">/</span> RUNNING PIPELINE...
              </span>
            ) : (
              <span>[ RUN TEST ]</span>
            )}
          </button>
        </div>

        <div className="landing-meta-bottom">
          <span className="landing-version">VERSION 1.0.0</span>
          <span className="landing-divider">|</span>
          <span className="landing-subsys">ISOLATION FOREST + MULTI-STAGE CORRELATION</span>
        </div>
      </div>
    </div>
  )
}

export default Landing
