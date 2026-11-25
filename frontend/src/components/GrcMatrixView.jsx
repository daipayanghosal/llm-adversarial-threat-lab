import React, { useMemo, useState } from 'react'
import { Download, FileCheck2, Filter, Search } from 'lucide-react'
import { GRC_MAPPINGS } from '../data/grcMatrix'

export default function GrcMatrixView({ onInspectPayload }) {
  const [query, setQuery] = useState('')
  const [owaspFilter, setOwaspFilter] = useState('ALL')
  const [nistFilter, setNistFilter] = useState('ALL')
  const [euFilter, setEuFilter] = useState('ALL')

  const filteredRows = useMemo(() => {
    return GRC_MAPPINGS.filter((item) => {
      if (owaspFilter !== 'ALL' && !item.owaspId.includes(owaspFilter)) return false
      if (nistFilter !== 'ALL' && item.nistFunction !== nistFilter) return false
      if (euFilter !== 'ALL' && !item.euRiskTier.includes(euFilter)) return false
      if (query.trim()) {
        const q = query.toLowerCase()
        const hay = `${item.threatVector} ${item.owaspTitle} ${item.nistSubcategory} ${item.euArticleRef} ${item.controlSummary}`.toLowerCase()
        return hay.includes(q)
      }
      return true
    })
  }, [query, owaspFilter, nistFilter, euFilter])

  const handleExportJson = () => {
    const blob = new Blob([JSON.stringify(filteredRows, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'llm-adversarial-threat-lab-grc-matrix.json'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-5">
      {/* Filter Bar */}
      <section className="bg-[#111824] border border-[#2d3b52] rounded-xl p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h2 className="text-sm font-semibold text-[#e2e8f0] flex items-center gap-2">
              <FileCheck2 className="w-4 h-4 text-[#2ee7b6]" />
              GRC &amp; Regulatory Compliance Explorer
            </h2>
            <p className="text-xs text-[#a4b1cd] mt-0.5">
              Maps tested DeepSeek-R1 attack vectors and controls across OWASP LLM Top 10, NIST AI RMF, and EU AI Act risk tiers.
            </p>
          </div>

          <button
            type="button"
            onClick={handleExportJson}
            className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#1a2332] border border-[#2d3b52] hover:border-[#2ee7b6] text-xs font-mono text-[#e2e8f0]"
          >
            <Download className="w-3.5 h-3.5 text-[#2ee7b6]" />
            Export GRC JSON
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-4 gap-3 pt-1">
          <div className="relative">
            <Search className="w-4 h-4 text-[#a4b1cd] absolute left-3 top-2.5" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search threat, article, control..."
              className="w-full bg-[#1a2332] border border-[#2d3b52] rounded-lg pl-9 pr-3 py-2 text-xs text-[#e2e8f0] placeholder-[#64748b] focus:outline-none focus:border-[#2ee7b6]"
            />
          </div>

          <select
            value={owaspFilter}
            onChange={(e) => setOwaspFilter(e.target.value)}
            className="bg-[#1a2332] border border-[#2d3b52] rounded-lg px-3 py-2 text-xs font-mono text-[#e2e8f0]"
          >
            <option value="ALL">OWASP: All Categories</option>
            <option value="LLM01">LLM01 Prompt Injection</option>
            <option value="LLM06">LLM06 Sensitive Info Disclosure</option>
            <option value="LLM07">LLM07 System Prompt Leakage</option>
            <option value="LLM08">LLM08 Excessive Agency</option>
            <option value="CONTROL">Benign Control Baseline</option>
          </select>

          <select
            value={nistFilter}
            onChange={(e) => setNistFilter(e.target.value)}
            className="bg-[#1a2332] border border-[#2d3b52] rounded-lg px-3 py-2 text-xs font-mono text-[#e2e8f0]"
          >
            <option value="ALL">NIST AI RMF: All Functions</option>
            <option value="GOVERN">GOVERN</option>
            <option value="MAP">MAP</option>
            <option value="MEASURE">MEASURE</option>
            <option value="MANAGE">MANAGE</option>
          </select>

          <select
            value={euFilter}
            onChange={(e) => setEuFilter(e.target.value)}
            className="bg-[#1a2332] border border-[#2d3b52] rounded-lg px-3 py-2 text-xs font-mono text-[#e2e8f0]"
          >
            <option value="ALL">EU AI Act: All Risk Tiers</option>
            <option value="High-Risk">High-Risk (Annex III / Art. 9-15)</option>
            <option value="Limited Risk">Limited Risk (Art. 50)</option>
            <option value="Minimal Risk">Minimal Risk</option>
          </select>
        </div>
      </section>

      {/* Matrix Cards */}
      <div className="space-y-3">
        {filteredRows.length === 0 ? (
          <div className="bg-[#111824] border border-[#2d3b52] rounded-xl p-8 text-center text-sm text-[#a4b1cd]">
            <Filter className="w-5 h-5 mx-auto mb-2 opacity-60" />
            No compliance mappings match the current filters.
          </div>
        ) : (
          filteredRows.map((row) => (
            <article
              key={row.id}
              className="bg-[#111824] border border-[#2d3b52] rounded-xl p-4 sm:p-5 space-y-3 hover:border-[#3d4f6d] transition"
            >
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div>
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-mono text-xs text-[#38bdf8] bg-[#38bdf8]/10 px-2 py-0.5 rounded border border-[#38bdf8]/30">
                      {row.id}
                    </span>
                    <span className="font-mono text-xs text-[#f59e0b] bg-[#f59e0b]/10 px-2 py-0.5 rounded border border-[#f59e0b]/30">
                      OWASP {row.owaspId}
                    </span>
                    <span className="font-mono text-xs text-[#e2e8f0] bg-[#1a2332] px-2 py-0.5 rounded border border-[#2d3b52]">
                      NIST: {row.nistFunction} ({row.nistSubcategory})
                    </span>
                    <span className="font-mono text-xs text-[#a4b1cd] bg-[#1a2332] px-2 py-0.5 rounded border border-[#2d3b52]">
                      EU AI Act: {row.euRiskTier}
                    </span>
                  </div>
                  <h3 className="text-base font-semibold text-[#e2e8f0] mt-2">{row.threatVector}</h3>
                </div>

                <div className="flex items-center gap-2 font-mono text-xs">
                  <span className="px-2.5 py-1 rounded bg-[#2ee7b6]/15 text-[#2ee7b6] border border-[#2ee7b6]/40">
                    {row.status} (Residual: {row.residualRisk})
                  </span>
                </div>
              </div>

              <p className="text-xs sm:text-sm text-[#a4b1cd] leading-relaxed">{row.controlSummary}</p>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 pt-1 text-xs font-mono">
                <div className="bg-[#1a2332] border border-[#2d3b52] rounded-lg px-3 py-2">
                  <span className="text-[#a4b1cd]">Control Module: </span>
                  <span className="text-[#e2e8f0]">{row.controlOwner}</span>
                </div>
                <div className="bg-[#1a2332] border border-[#2d3b52] rounded-lg px-3 py-2">
                  <span className="text-[#a4b1cd]">Regulatory Citation: </span>
                  <span className="text-[#e2e8f0]">{row.euArticleRef}</span>
                </div>
              </div>

              <div className="flex flex-wrap items-center gap-1.5 pt-1">
                <span className="text-[11px] font-mono text-[#a4b1cd] mr-1">Linked Payloads:</span>
                {row.payloadIds.map((pid) => (
                  <button
                    key={pid}
                    type="button"
                    onClick={() => onInspectPayload(pid)}
                    className="px-2 py-0.5 rounded text-[11px] font-mono bg-[#1a2332] border border-[#2d3b52] text-[#38bdf8] hover:border-[#2ee7b6] hover:text-[#2ee7b6] transition"
                  >
                    {pid}
                  </button>
                ))}
              </div>
            </article>
          ))
        )}
      </div>
    </div>
  )
}
