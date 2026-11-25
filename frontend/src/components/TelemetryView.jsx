import React, { useMemo, useState } from 'react'
import { Activity, RefreshCw, ShieldAlert, ShieldCheck, Timer, Zap } from 'lucide-react'

function KpiCard({ title, value, subtitle, accent = 'text-[#e2e8f0]', icon: Icon }) {
  return (
    <div className="bg-[#111824] border border-[#2d3b52] rounded-xl p-4 flex items-start justify-between">
      <div>
        <div className="text-xs font-mono uppercase tracking-wider text-[#a4b1cd]">{title}</div>
        <div className={`text-2xl font-mono font-bold mt-1 ${accent}`}>{value}</div>
        {subtitle && <div className="text-xs text-[#a4b1cd] mt-1">{subtitle}</div>}
      </div>
      {Icon && (
        <div className="p-2 rounded-lg bg-[#1a2332] border border-[#2d3b52]">
          <Icon className={`w-5 h-5 ${accent}`} />
        </div>
      )}
    </div>
  )
}

export default function TelemetryView({
  benchmarks,
  connectionMode,
  onRefreshLiveBenchmarks,
  isRefreshing,
  onInspectPayload,
}) {
  const [ledgerFilter, setLedgerFilter] = useState('ALL')

  const verdictCounts = useMemo(() => {
    const counts = { BLOCK: 0, FLAG_AND_MASK: 0, ALLOW: 0 }
    for (const r of benchmarks.records || []) {
      counts[r.pre_filter_verdict] = (counts[r.pre_filter_verdict] || 0) + 1
    }
    return counts
  }, [benchmarks.records])

  const filteredRecords = useMemo(() => {
    const rows = benchmarks.records || []
    if (ledgerFilter === 'ALL') return rows
    if (ledgerFilter === 'BREACHED_RAW') return rows.filter((r) => r.unguarded_attack_success)
    if (ledgerFilter === 'BENIGN') return rows.filter((r) => r.is_benign)
    return rows.filter((r) => r.category === ledgerFilter)
  }, [benchmarks.records, ledgerFilter])

  const maxOverhead = Math.max(
    0.2,
    ...(benchmarks.by_category || []).map((c) => c.mean_overhead_ms || 0)
  )

  return (
    <div className="space-y-5">
      {/* Header Row */}
      <div className="flex flex-wrap items-center justify-between gap-3 bg-[#111824] border border-[#2d3b52] rounded-xl px-4 py-3">
        <div className="text-xs font-mono text-[#a4b1cd] flex flex-wrap items-center gap-3">
          <span>
            Dataset: <strong className="text-[#e2e8f0]">{benchmarks.total_payloads} probes</strong> (
            {benchmarks.adversarial_count} adversarial / {benchmarks.benign_count} benign)
          </span>
          <span>
            Mode: <strong className="text-[#38bdf8] uppercase">{benchmarks.mode}</strong>
          </span>
          <span>
            Classifier: <strong className="text-[#e2e8f0]">{benchmarks.classifier_backend}</strong>
          </span>
        </div>

        {connectionMode === 'live' && (
          <button
            type="button"
            onClick={onRefreshLiveBenchmarks}
            disabled={isRefreshing}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#1a2332] border border-[#2ee7b6]/40 text-xs font-mono text-[#2ee7b6] hover:bg-[#2ee7b6]/10 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            {isRefreshing ? 'Running Live Benchmark...' : 'Run Live Colab Benchmark'}
          </button>
        )}
      </div>

      {/* KPI Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Unguarded ASR"
          value={`${benchmarks.unguarded_asr_pct}%`}
          subtitle={`${benchmarks.adversarial_count} OWASP attack probes`}
          accent="text-[#f43f5e]"
          icon={ShieldAlert}
        />
        <KpiCard
          title="Guardrailed ASR"
          value={`${benchmarks.guardrailed_asr_pct}%`}
          subtitle={`-${benchmarks.asr_reduction_pct}% absolute risk reduction`}
          accent="text-[#2ee7b6]"
          icon={ShieldCheck}
        />
        <KpiCard
          title="Benign FPR"
          value={`${benchmarks.guardrailed_fpr_pct}%`}
          subtitle={`0 false blocks across ${benchmarks.benign_count} clean controls`}
          accent="text-[#38bdf8]"
          icon={Activity}
        />
        <KpiCard
          title="Guardrail Overhead"
          value={`${benchmarks.mean_guardrail_overhead_ms} ms`}
          subtitle={`P95 overhead: ${benchmarks.p95_guardrail_overhead_ms} ms`}
          accent="text-[#f59e0b]"
          icon={Timer}
        />
      </div>

      {/* Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-5">
        {/* ASR Comparison Bar Chart */}
        <section className="lg:col-span-7 bg-[#111824] border border-[#2d3b52] rounded-xl p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-sm font-semibold text-[#e2e8f0]">
                Attack Success Rate (ASR %) by OWASP Category
              </h3>
              <p className="text-xs text-[#a4b1cd]">
                Lower is safer — compares raw DeepSeek-R1 against Dual-Guardrailed Pipeline
              </p>
            </div>
            <div className="flex items-center gap-4 text-xs font-mono">
              <span className="flex items-center gap-1.5 text-[#f43f5e]">
                <span className="w-2.5 h-2.5 rounded-sm bg-[#f43f5e]" /> Unguarded
              </span>
              <span className="flex items-center gap-1.5 text-[#2ee7b6]">
                <span className="w-2.5 h-2.5 rounded-sm bg-[#2ee7b6]" /> Guardrailed
              </span>
            </div>
          </div>

          <div className="space-y-4 pt-2">
            {(benchmarks.by_category || []).map((cat) => (
              <div key={cat.category} className="space-y-1.5">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-[#e2e8f0]">
                    {cat.label} <span className="text-[#a4b1cd]">({cat.count} probes)</span>
                  </span>
                  <span>
                    <span className="text-[#f43f5e]">{cat.unguarded_asr_pct}%</span>
                    <span className="text-[#64748b] mx-1.5">→</span>
                    <span className="text-[#2ee7b6]">{cat.guardrailed_asr_pct}%</span>
                  </span>
                </div>
                <div className="space-y-1">
                  <div className="h-3 bg-[#1a2332] rounded overflow-hidden border border-[#2d3b52]">
                    <div
                      className="h-full bg-[#f43f5e] transition-all duration-500"
                      style={{ width: `${cat.unguarded_asr_pct}%` }}
                    />
                  </div>
                  <div className="h-3 bg-[#1a2332] rounded overflow-hidden border border-[#2d3b52]">
                    <div
                      className="h-full bg-[#2ee7b6] transition-all duration-500"
                      style={{ width: `${Math.max(cat.guardrailed_asr_pct, 1)}%` }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        </section>

        {/* Latency Overhead & Verdict Breakdown */}
        <section className="lg:col-span-5 bg-[#111824] border border-[#2d3b52] rounded-xl p-5 space-y-5">
          <div>
            <h3 className="text-sm font-semibold text-[#e2e8f0] flex items-center gap-2">
              <Zap className="w-4 h-4 text-[#38bdf8]" />
              Guardrail Latency Overhead by Category
            </h3>
            <p className="text-xs text-[#a4b1cd] mt-0.5">
              Pre-Filter + PII Tokenizer + Post-Sanitizer processing cost (ms)
            </p>
            <div className="space-y-3 mt-4">
              {(benchmarks.by_category || []).map((cat) => (
                <div key={cat.category} className="space-y-1">
                  <div className="flex justify-between text-xs font-mono">
                    <span className="text-[#a4b1cd]">{cat.label}</span>
                    <span className="text-[#38bdf8] font-semibold">{cat.mean_overhead_ms} ms</span>
                  </div>
                  <div className="h-2.5 bg-[#1a2332] rounded overflow-hidden border border-[#2d3b52]">
                    <div
                      className="h-full bg-[#38bdf8]"
                      style={{
                        width: `${Math.min(100, (cat.mean_overhead_ms / maxOverhead) * 100)}%`,
                      }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="border-t border-[#2d3b52] pt-4">
            <h4 className="text-xs font-mono uppercase tracking-wider text-[#a4b1cd] mb-3">
              Pre-Filter Verdict Distribution
            </h4>
            <div className="grid grid-cols-3 gap-2">
              <div className="bg-[#1a2332] border border-[#f43f5e]/30 rounded-lg p-3 text-center">
                <div className="text-lg font-mono font-bold text-[#f43f5e]">{verdictCounts.BLOCK}</div>
                <div className="text-[11px] font-mono text-[#a4b1cd]">BLOCK</div>
              </div>
              <div className="bg-[#1a2332] border border-[#f59e0b]/30 rounded-lg p-3 text-center">
                <div className="text-lg font-mono font-bold text-[#f59e0b]">
                  {verdictCounts.FLAG_AND_MASK}
                </div>
                <div className="text-[11px] font-mono text-[#a4b1cd]">FLAG &amp; MASK</div>
              </div>
              <div className="bg-[#1a2332] border border-[#2ee7b6]/30 rounded-lg p-3 text-center">
                <div className="text-lg font-mono font-bold text-[#2ee7b6]">{verdictCounts.ALLOW}</div>
                <div className="text-[11px] font-mono text-[#a4b1cd]">ALLOW</div>
              </div>
            </div>
          </div>
        </section>
      </div>

      {/* Per-Payload Ledger */}
      <section className="bg-[#111824] border border-[#2d3b52] rounded-xl overflow-hidden">
        <div className="px-4 py-3 border-b border-[#2d3b52] flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-[#e2e8f0]">
            Per-Payload Evaluation Ledger (Click row to inspect in Sandbox)
          </h3>
          <select
            value={ledgerFilter}
            onChange={(e) => setLedgerFilter(e.target.value)}
            className="bg-[#1a2332] border border-[#2d3b52] text-xs font-mono text-[#e2e8f0] rounded-lg px-2.5 py-1.5"
          >
            <option value="ALL">All Payloads ({benchmarks.total_payloads})</option>
            <option value="BREACHED_RAW">Raw Exploits Succeeded</option>
            <option value="BENIGN">Benign Control Suite</option>
            <option value="LLM01_System_Extraction">LLM01 Sys Extraction</option>
            <option value="LLM01_CoT_Hijack">LLM01 CoT Hijack</option>
            <option value="LLM01_Direct_Jailbreak">LLM01 Direct Jailbreak</option>
            <option value="LLM06_PII_Leakage">LLM06 PII Leakage</option>
            <option value="LLM08_Agentic_Injection">LLM08 Agentic Injection</option>
          </select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#2d3b52] bg-[#161f2e] font-mono text-[11px] text-[#a4b1cd] uppercase">
                <th className="py-2.5 px-3">ID</th>
                <th className="py-2.5 px-3">Title</th>
                <th className="py-2.5 px-3">OWASP</th>
                <th className="py-2.5 px-3">Unguarded</th>
                <th className="py-2.5 px-3">Guardrailed</th>
                <th className="py-2.5 px-3">Pre-Filter</th>
                <th className="py-2.5 px-3 text-right">Risk</th>
                <th className="py-2.5 px-3 text-right">PII</th>
                <th className="py-2.5 px-3 text-right">Overhead</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2d3b52]/60">
              {filteredRecords.map((row) => (
                <tr
                  key={row.id}
                  onClick={() => onInspectPayload(row.id)}
                  className="hover:bg-[#1a2332] cursor-pointer transition"
                >
                  <td className="py-2 px-3 font-mono text-[#38bdf8] whitespace-nowrap">{row.id}</td>
                  <td className="py-2 px-3 text-[#e2e8f0]">{row.title}</td>
                  <td className="py-2 px-3 font-mono text-[#a4b1cd] whitespace-nowrap">{row.owasp_id}</td>
                  <td className="py-2 px-3 font-mono">
                    {row.is_benign ? (
                      <span className="text-[#a4b1cd]">CLEAN</span>
                    ) : row.unguarded_attack_success ? (
                      <span className="text-[#f43f5e]">BREACH</span>
                    ) : (
                      <span className="text-[#2ee7b6]">HELD</span>
                    )}
                  </td>
                  <td className="py-2 px-3 font-mono">
                    {row.is_benign ? (
                      row.guardrailed_false_positive ? (
                        <span className="text-[#f43f5e]">FALSE POS</span>
                      ) : (
                        <span className="text-[#2ee7b6]">PASSED</span>
                      )
                    ) : row.guardrailed_attack_success ? (
                      <span className="text-[#f43f5e]">BYPASSED</span>
                    ) : (
                      <span className="text-[#2ee7b6]">DEFENDED</span>
                    )}
                  </td>
                  <td className="py-2 px-3 font-mono text-[#a4b1cd]">{row.pre_filter_verdict}</td>
                  <td className="py-2 px-3 font-mono text-right text-[#e2e8f0]">
                    {(row.pre_filter_risk_score * 100).toFixed(0)}%
                  </td>
                  <td className="py-2 px-3 font-mono text-right text-[#2ee7b6]">
                    {row.pii_entities_masked}
                  </td>
                  <td className="py-2 px-3 font-mono text-right text-[#38bdf8]">
                    {row.guardrail_overhead_ms} ms
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
