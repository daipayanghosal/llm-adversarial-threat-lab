import React, { useEffect, useState } from 'react'
import { BarChart3, BookOpen, Plug, Shield, TerminalSquare } from 'lucide-react'
import SandboxView from './components/SandboxView'
import TelemetryView from './components/TelemetryView'
import GrcMatrixView from './components/GrcMatrixView'
import { evaluateOffline, replayData } from './utils/offlineEngine'

const TABS = [
  { id: 'sandbox', label: '1. Try an Attack', icon: TerminalSquare },
  { id: 'telemetry', label: '2. Defense Scoreboard', icon: BarChart3 },
  { id: 'grc', label: '3. Security Rules & Laws', icon: BookOpen },
]

export default function App() {
  const [activeTab, setActiveTab] = useState('sandbox')
  const [connectionMode, setConnectionMode] = useState('offline') // 'offline' | 'live'
  const [tunnelUrl, setTunnelUrl] = useState('http://127.0.0.1:8000')
  const [statusPill, setStatusPill] = useState({ kind: 'offline', label: 'Demo Mode Ready' })

  const [payloads, setPayloads] = useState(replayData.payloads)
  const [scenarios, setScenarios] = useState(replayData.scenarios)
  const [benchmarks, setBenchmarks] = useState(replayData.benchmarks)

  const initialPayload = replayData.payloads[1] || replayData.payloads[0]
  const [selectedPayloadId, setSelectedPayloadId] = useState(initialPayload.id)
  const [prompt, setPrompt] = useState(initialPayload.prompt)
  const [agenticMode, setAgenticMode] = useState(Boolean(initialPayload.agentic))
  const [scenarioId, setScenarioId] = useState(initialPayload.scenario_id || 'clean_inbox')
  const [piiPolicy, setPiiPolicy] = useState('redact')

  const [evalResult, setEvalResult] = useState(() =>
    evaluateOffline({
      prompt: initialPayload.prompt,
      payloadId: initialPayload.id,
      agenticMode: Boolean(initialPayload.agentic),
      scenarioId: initialPayload.scenario_id || 'clean_inbox',
      piiPolicy: 'redact',
    })
  )
  const [isRunning, setIsRunning] = useState(false)
  const [isRefreshingBenchmarks, setIsRefreshingBenchmarks] = useState(false)
  const [evalError, setEvalError] = useState('')

  const normalizedBaseUrl = tunnelUrl.trim().replace(/\/+$/, '')

  const checkLiveConnection = async (baseUrl = normalizedBaseUrl) => {
    setEvalError('')
    setStatusPill({ kind: 'checking', label: 'Connecting...' })
    try {
      const resp = await fetch(`${baseUrl}/health`, { method: 'GET' })
      if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
      const data = await resp.json()
      setStatusPill({
        kind: 'connected',
        label: data.ollama_reachable ? 'Live Colab GPU Connected' : 'Local Backend Connected',
      })

      const [pResp, bResp] = await Promise.all([
        fetch(`${baseUrl}/api/payloads`),
        fetch(`${baseUrl}/api/benchmarks`),
      ])
      if (pResp.ok) {
        const pJson = await pResp.json()
        setPayloads(pJson.payloads || replayData.payloads)
        setScenarios(pJson.scenarios || replayData.scenarios)
      }
      if (bResp.ok) {
        setBenchmarks(await bResp.json())
      }
    } catch (err) {
      setStatusPill({ kind: 'error', label: 'Not Connected' })
      setEvalError(`Could not reach ${baseUrl}. Make sure the backend or Colab tunnel is running.`)
    }
  }

  useEffect(() => {
    if (connectionMode === 'offline') {
      setStatusPill({ kind: 'offline', label: 'Demo Mode Ready' })
      setPayloads(replayData.payloads)
      setScenarios(replayData.scenarios)
      setBenchmarks(replayData.benchmarks)
      setEvalError('')
    } else {
      checkLiveConnection()
    }
  }, [connectionMode])

  const handleSelectPayload = (id) => {
    setSelectedPayloadId(id)
    setEvalError('')
    if (id === 'CUSTOM') return
    const found = payloads.find((p) => p.id === id)
    if (!found) return
    const nextAgentic = Boolean(found.agentic)
    const nextScenario = found.scenario_id || 'clean_inbox'
    setPrompt(found.prompt)
    setAgenticMode(nextAgentic)
    setScenarioId(nextScenario)

    if (connectionMode === 'offline') {
      setEvalResult(
        evaluateOffline({
          prompt: found.prompt,
          payloadId: found.id,
          agenticMode: nextAgentic,
          scenarioId: nextScenario,
          piiPolicy,
        })
      )
    }
  }

  const handleRunEvaluation = async () => {
    setEvalError('')
    if (connectionMode === 'offline') {
      setEvalResult(
        evaluateOffline({
          prompt,
          payloadId: selectedPayloadId,
          agenticMode,
          scenarioId,
          piiPolicy,
        })
      )
      return
    }

    setIsRunning(true)
    try {
      const resp = await fetch(`${normalizedBaseUrl}/api/evaluate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          prompt,
          payload_id: selectedPayloadId === 'CUSTOM' ? null : selectedPayloadId,
          agentic_mode: agenticMode,
          scenario_id: scenarioId,
          pii_policy: piiPolicy,
        }),
      })
      if (!resp.ok) {
        throw new Error(`HTTP ${resp.status}`)
      }
      setEvalResult(await resp.json())
    } catch (err) {
      setEvalError(`Could not run evaluation: ${err.message}`)
    } finally {
      setIsRunning(false)
    }
  }

  const handleRefreshLiveBenchmarks = async () => {
    if (connectionMode !== 'live') return
    setIsRefreshingBenchmarks(true)
    try {
      const resp = await fetch(`${normalizedBaseUrl}/api/benchmarks?refresh=true`)
      if (resp.ok) {
        setBenchmarks(await resp.json())
      }
    } finally {
      setIsRefreshingBenchmarks(false)
    }
  }

  const handleInspectFromOtherTab = (payloadId) => {
    handleSelectPayload(payloadId)
    setActiveTab('sandbox')
  }

  return (
    <div className="min-h-screen bg-[#1a2332] text-[#a4b1cd] flex flex-col">
      {/* Simple Clean Header */}
      <header className="sticky top-0 z-30 bg-[#111824]/95 backdrop-blur border-b border-[#2d3b52]">
        <div className="max-w-6xl mx-auto px-4 sm:px-6 py-3.5 flex flex-col md:flex-row md:items-center md:justify-between gap-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-xl bg-[#2ee7b6]/10 border border-[#2ee7b6]/40">
              <Shield className="w-6 h-6 text-[#2ee7b6]" />
            </div>
            <div>
              <h1 className="text-base sm:text-lg font-bold text-[#e2e8f0]">
                AI Security &amp; Privacy Lab
              </h1>
              <p className="text-xs text-[#a4b1cd]">
                See how attackers trick an AI — and how safety guards stop them
              </p>
            </div>
          </div>

          {/* Simple Mode Switcher */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="inline-flex rounded-lg bg-[#1a2332] border border-[#2d3b52] p-0.5">
              <button
                type="button"
                onClick={() => setConnectionMode('offline')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition ${
                  connectionMode === 'offline'
                    ? 'bg-[#2ee7b6] text-[#0f172a] font-semibold'
                    : 'text-[#a4b1cd] hover:text-[#e2e8f0]'
                }`}
              >
                Demo Mode
              </button>
              <button
                type="button"
                onClick={() => setConnectionMode('live')}
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition ${
                  connectionMode === 'live'
                    ? 'bg-[#38bdf8] text-[#0f172a] font-semibold'
                    : 'text-[#a4b1cd] hover:text-[#e2e8f0]'
                }`}
              >
                Live API / Colab
              </button>
            </div>

            {connectionMode === 'live' && (
              <div className="flex items-center gap-1.5">
                <input
                  type="url"
                  value={tunnelUrl}
                  onChange={(e) => setTunnelUrl(e.target.value)}
                  placeholder="Paste Colab URL or localhost"
                  className="w-52 bg-[#1a2332] border border-[#2d3b52] rounded-lg px-2.5 py-1.5 text-xs text-[#e2e8f0] focus:outline-none focus:border-[#38bdf8]"
                />
                <button
                  type="button"
                  onClick={() => checkLiveConnection()}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg bg-[#1a2332] border border-[#2d3b52] hover:border-[#38bdf8] text-xs text-[#e2e8f0]"
                >
                  <Plug className="w-3.5 h-3.5 text-[#38bdf8]" />
                  Connect
                </button>
              </div>
            )}

            <span
              className={`px-2.5 py-1.5 rounded-lg border text-xs font-medium ${
                statusPill.kind === 'error'
                  ? 'bg-[#f43f5e]/15 text-[#f43f5e] border-[#f43f5e]/40'
                  : statusPill.kind === 'connected'
                    ? 'bg-[#38bdf8]/15 text-[#38bdf8] border-[#38bdf8]/40'
                    : 'bg-[#2ee7b6]/15 text-[#2ee7b6] border-[#2ee7b6]/40'
              }`}
            >
              {statusPill.label}
            </span>
          </div>
        </div>

        {/* Clean 3-Tab Navigation */}
        <div className="max-w-6xl mx-auto px-4 sm:px-6 flex gap-2 overflow-x-auto border-t border-[#2d3b52]/60">
          {TABS.map((tab) => {
            const Icon = tab.icon
            const active = activeTab === tab.id
            return (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`inline-flex items-center gap-2 px-4 py-2.5 text-xs sm:text-sm font-medium border-b-2 transition whitespace-nowrap ${
                  active
                    ? 'border-[#2ee7b6] text-[#2ee7b6]'
                    : 'border-transparent text-[#a4b1cd] hover:text-[#e2e8f0]'
                }`}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            )
          })}
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 max-w-6xl w-full mx-auto px-4 sm:px-6 py-6">
        {activeTab === 'sandbox' && (
          <SandboxView
            payloads={payloads}
            scenarios={scenarios}
            selectedPayloadId={selectedPayloadId}
            onSelectPayload={handleSelectPayload}
            prompt={prompt}
            onPromptChange={setPrompt}
            agenticMode={agenticMode}
            onAgenticModeChange={setAgenticMode}
            scenarioId={scenarioId}
            onScenarioIdChange={setScenarioId}
            piiPolicy={piiPolicy}
            onPiiPolicyChange={setPiiPolicy}
            onEvaluate={handleRunEvaluation}
            result={evalResult}
            isRunning={isRunning}
            error={evalError}
          />
        )}

        {activeTab === 'telemetry' && (
          <TelemetryView
            benchmarks={benchmarks}
            connectionMode={connectionMode}
            onRefreshLiveBenchmarks={handleRefreshLiveBenchmarks}
            isRefreshing={isRefreshingBenchmarks}
            onInspectPayload={handleInspectFromOtherTab}
          />
        )}

        {activeTab === 'grc' && (
          <GrcMatrixView onInspectPayload={handleInspectFromOtherTab} />
        )}
      </main>
    </div>
  )
}
