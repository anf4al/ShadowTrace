import { useState, useEffect, useMemo } from 'react'
import Landing from './components/Landing'
import Sidebar from './components/Sidebar'
import Header from './components/Header'
import SummaryCards from './components/SummaryCards'
import RiskDistribution from './components/RiskDistribution'
import ThreatTable from './components/ThreatTable'
import InvestigationsView from './components/InvestigationsView'
import InvestigationPanel from './components/InvestigationPanel'
import './App.css'

function App() {
  const [currentScreen, setCurrentScreen] = useState('landing') // 'landing' | 'app'
  const [activeTab, setActiveTab] = useState('dashboard') // 'dashboard' | 'investigations'
  const [riskAssessments, setRiskAssessments] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [lastUpdated, setLastUpdated] = useState(null)
  const [selectedThreat, setSelectedThreat] = useState(null)

  const fetchRisks = async () => {
    try {
      setLoading(true)
      setError(null)

      const response = await fetch('http://127.0.0.1:8000/api/risks')

      if (!response.ok) {
        throw new Error(`API returned HTTP ${response.status}: ${response.statusText}`)
      }

      const data = await response.json()
      setRiskAssessments(data)
      setLastUpdated(new Date().toLocaleTimeString())
    } catch (err) {
      console.error('Failed to fetch threat assessments:', err)
      setError(err.message || 'Unable to retrieve threat assessments from API.')
    } finally {
      setLoading(false)
    }
  }

  // Handle RUN TEST from landing page
  const handleRunTest = async () => {
    setCurrentScreen('app')
    setActiveTab('dashboard')
    await fetchRisks()
  }

  // Memoize risk counts across the four operational threat levels
  const riskCounts = useMemo(() => {
    const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
    for (const item of riskAssessments) {
      if (counts[item.risk_level] !== undefined) {
        counts[item.risk_level] += 1
      }
    }
    return counts
  }, [riskAssessments])

  // Landing Page view
  if (currentScreen === 'landing') {
    return <Landing onRunTest={handleRunTest} loading={loading} />
  }

  // Main Application view
  return (
    <div className="soc-layout">
      <Sidebar
        loading={loading}
        error={error}
        activeTab={activeTab}
        onSelectTab={setActiveTab}
        onGoHome={() => setCurrentScreen('landing')}
      />

      <div className="soc-main">
        <Header
          loading={loading}
          error={error}
          lastUpdated={lastUpdated}
          onRefresh={fetchRisks}
          activeTab={activeTab}
          count={riskAssessments.length}
        />

        <main className="soc-content">
          {activeTab === 'dashboard' && (
            <>
              <SummaryCards
                riskAssessments={riskAssessments}
                loading={loading}
                error={error}
              />
              <RiskDistribution
                riskAssessments={riskAssessments}
                counts={riskCounts}
                loading={loading}
              />
              <ThreatTable
                riskAssessments={riskAssessments}
                loading={loading}
                error={error}
                selectedThreat={selectedThreat}
                onSelectThreat={setSelectedThreat}
              />
            </>
          )}

          {activeTab === 'investigations' && (
            <InvestigationsView
              riskAssessments={riskAssessments}
              loading={loading}
              error={error}
              selectedThreat={selectedThreat}
              onSelectThreat={setSelectedThreat}
            />
          )}
        </main>
      </div>

      {/* Investigation Modal Panel */}
      {selectedThreat && (
        <InvestigationPanel
          threat={selectedThreat}
          onClose={() => setSelectedThreat(null)}
        />
      )}
    </div>
  )
}

export default App
