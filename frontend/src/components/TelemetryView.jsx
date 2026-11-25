import React from 'react'
import { CheckCircle2, RefreshCw, ShieldAlert, ShieldCheck, Timer } from 'lucide-react'

const FRIENDLY_CATEGORIES = {
  LLM01_Prompt_Injection: 'LLM01: Prompt Injection',
  LLM02_Sensitive_Information_Disclosure: 'LLM02: Sensitive Info Disclosure',
  LLM03_Supply_Chain: 'LLM03: Supply Chain',
  LLM04_Data_and_Model_Poisoning: 'LLM04: Data & Model Poisoning',
  LLM05_Improper_Output_Handling: 'LLM05: Improper Output Handling',
  LLM06_Excessive_Agency: 'LLM06: Excessive Agency',
  LLM07_System_Prompt_Leakage: 'LLM07: System Prompt Leakage',
  LLM08_Vector_and_Embedding_Weaknesses: 'LLM08: Vector & Embedding Weaknesses',
  LLM09_Misinformation: 'LLM09: Misinformation',
  LLM10_Unbounded_Consumption: 'LLM10: Unbounded Consumption',
}

export default function TelemetryView({
  benchmarks,
  connectionMode,
  onRefreshLiveBenchmarks,
  isRefreshing,
  onInspectPayload,
}) {
  return (
    <div className="space-y-6">
      <div className="bg-[#111824] border border-[#2d3b52] rounded-xl p-5 flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-semibold text-[#e2e8f0]">
            OWASP Top 10 Scoreboard ({benchmarks.total_payloads} Tests)
          </h2>
          <p className="text-xs text-[#a4b1cd] mt-0.5">
            Covers all 10 official OWASP LLM categories ({benchmarks.adversarial_count} attacks + {benchmarks.benign_count} normal questions).
          </p>
        </div>

        {connectionMode === 'live' && (
          <button
            type="button"
            onClick={onRefreshLiveBenchmarks}
            disabled={isRefreshing}
            className="inline-flex items-center gap-2 px-3.5 py-2 rounded-lg bg-[#1a2332] border border-[#2ee7b6]/40 text-xs font-medium text-[#2ee7b6] hover:bg-[#2ee7b6]/10 disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
            {isRefreshing ? 'Running Live Benchmark...' : 'Re-run on Live AI'}
          </button>
        )}
      </div>

      {/* 3 Simple Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-[#111824] border border-[#2d3b52] rounded-xl p-5 flex items-start justify-between">
          <div>
            <div className="text-xs text-[#a4b1cd]">Without Safety Guard</div>
            <div className="text-3xl font-mono font-bold text-[#f43f5e] mt-1">
              {benchmarks.unguarded_asr_pct}%
            </div>
            <div className="text-xs text-[#a4b1cd] mt-1">of attacks tricked the raw AI</div>
          </div>
          <ShieldAlert className="w-7 h-7 text-[#f43f5e]" />
        </div>

        <div className="bg-[#111824] border border-[#2d3b52] rounded-xl p-5 flex items-start justify-between">
          <div>
            <div className="text-xs text-[#a4b1cd]">With Our Safety Guard</div>
            <div className="text-3xl font-mono font-bold text-[#2ee7b6] mt-1">
              {benchmarks.guardrailed_asr_pct}%
            </div>
            <div className="text-xs text-[#a4b1cd] mt-1">of attacks succeeded after filtering</div>
          </div>
          <ShieldCheck className="w-7 h-7 text-[#2ee7b6]" />
        </div>

        <div className="bg-[#111824] border border-[#2d3b52] rounded-xl p-5 flex items-start justify-between">
          <div>
            <div className="text-xs text-[#a4b1cd]">Speed &amp; Normal Questions</div>
            <div className="text-3xl font-mono font-bold text-[#38bdf8] mt-1">
              +{benchmarks.mean_guardrail_overhead_ms} ms
            </div>
            <div className="text-xs text-[#a4b1cd] mt-1">
              extra delay · {benchmarks.guardrailed_fpr_pct}% false alarms
            </div>
          </div>
          <Timer className="w-7 h-7 text-[#38bdf8]" />
        </div>
      </div>

      {/* 10-Category Comparison Bars */}
      <section className="bg-[#111824] border border-[#2d3b52] rounded-xl p-5 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-[#e2e8f0]">
              Attack Success Rate Across All 10 OWASP Categories (Lower = Safer)
            </h3>
            <p className="text-xs text-[#a4b1cd]">Red = No Guard; Green = With Safety Guard.</p>
          </div>
          <div className="flex items-center gap-4 text-xs">
            <span className="flex items-center gap-1.5 text-[#f43f5e]">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#f43f5e]" /> No Guard
            </span>
            <span className="flex items-center gap-1.5 text-[#2ee7b6]">
              <span className="w-2.5 h-2.5 rounded-sm bg-[#2ee7b6]" /> With Guard
            </span>
          </div>
        </div>

        <div className="space-y-3.5 pt-1">
          {(benchmarks.by_category || []).map((cat) => (
            <div key={cat.category} className="space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-[#e2e8f0] font-medium">
                  {FRIENDLY_CATEGORIES[cat.category] || cat.label}
                </span>
                <span className="font-mono">
                  <span className="text-[#f43f5e]">{cat.unguarded_asr_pct}%</span>
                  <span className="text-[#64748b] mx-1.5">→</span>
                  <span className="text-[#2ee7b6]">{cat.guardrailed_asr_pct}%</span>
                </span>
              </div>
              <div className="space-y-1">
                <div className="h-2.5 bg-[#1a2332] rounded overflow-hidden">
                  <div className="h-full bg-[#f43f5e]" style={{ width: `${cat.unguarded_asr_pct}%` }} />
                </div>
                <div className="h-2.5 bg-[#1a2332] rounded overflow-hidden">
                  <div
                    className="h-full bg-[#2ee7b6]"
                    style={{ width: `${Math.max(cat.guardrailed_asr_pct, 1)}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Clean Test List */}
      <section className="bg-[#111824] border border-[#2d3b52] rounded-xl overflow-hidden">
        <div className="px-5 py-3.5 border-b border-[#2d3b52]">
          <h3 className="text-sm font-semibold text-[#e2e8f0]">
            All {benchmarks.total_payloads} Test Cases (Click any row to try it)
          </h3>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-[#2d3b52] bg-[#161f2e] text-[#a4b1cd]">
                <th className="py-2.5 px-4 font-medium">Test Name</th>
                <th className="py-2.5 px-4 font-medium">OWASP Category</th>
                <th className="py-2.5 px-4 font-medium">Without Guard</th>
                <th className="py-2.5 px-4 font-medium">With Guard</th>
                <th className="py-2.5 px-4 font-medium text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#2d3b52]/60">
              {(benchmarks.records || []).map((row) => (
                <tr
                  key={row.id}
                  onClick={() => onInspectPayload(row.id)}
                  className="hover:bg-[#1a2332] cursor-pointer transition"
                >
                  <td className="py-2.5 px-4 text-[#e2e8f0] font-medium">{row.title}</td>
                  <td className="py-2.5 px-4 text-[#a4b1cd]">
                    {row.is_benign ? 'Normal Question' : FRIENDLY_CATEGORIES[row.category] || row.owasp_id}
                  </td>
                  <td className="py-2.5 px-4 font-medium">
                    {row.is_benign ? (
                      <span className="text-[#a4b1cd]">Safe</span>
                    ) : row.unguarded_attack_success ? (
                      <span className="text-[#f43f5e]">Hacked</span>
                    ) : (
                      <span className="text-[#2ee7b6]">Safe</span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 font-medium">
                    {row.guardrailed_attack_success || row.guardrailed_false_positive ? (
                      <span className="text-[#f43f5e]">Failed</span>
                    ) : (
                      <span className="inline-flex items-center gap-1 text-[#2ee7b6]">
                        <CheckCircle2 className="w-3.5 h-3.5" /> Safe
                      </span>
                    )}
                  </td>
                  <td className="py-2.5 px-4 text-right text-[#38bdf8] font-medium">Open →</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
