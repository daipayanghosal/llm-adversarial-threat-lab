import React, { useMemo, useState } from 'react'
import { ArrowRight, BookOpen, Search } from 'lucide-react'
import { GRC_MAPPINGS } from '../data/grcMatrix'

export default function GrcMatrixView({ onInspectPayload }) {
  const [query, setQuery] = useState('')
  const [frameworkFilter, setFrameworkFilter] = useState('ALL')

  const filteredRows = useMemo(() => {
    return GRC_MAPPINGS.filter((item) => {
      if (frameworkFilter === 'OWASP_1_5' && !['LLM01', 'LLM02', 'LLM03', 'LLM04', 'LLM05'].includes(item.owaspId)) return false
      if (frameworkFilter === 'OWASP_6_10' && !['LLM06', 'LLM07', 'LLM08', 'LLM09', 'LLM10'].includes(item.owaspId)) return false
      if (frameworkFilter === 'HIGH_RISK' && !item.euRiskTier.includes('High-Risk')) return false
      if (query.trim()) {
        const q = query.toLowerCase()
        return `${item.threatVector} ${item.controlSummary} ${item.owaspId} ${item.nistSubcategory} ${item.euArticleRef}`
          .toLowerCase()
          .includes(q)
      }
      return true
    })
  }, [query, frameworkFilter])

  return (
    <div className="space-y-5">
      <section className="bg-[#111824] border border-[#2d3b52] rounded-xl p-5 space-y-4">
        <div>
          <h2 className="text-base font-semibold text-[#e2e8f0] flex items-center gap-2">
            <BookOpen className="w-4 h-4 text-[#2ee7b6]" />
            Textbook OWASP Top 10 for LLMs (2025) &amp; AI Laws
          </h2>
          <p className="text-xs text-[#a4b1cd] mt-1">
            All 10 official <strong>OWASP LLM Top 10</strong> risks mapped to the <strong>NIST AI RMF</strong> guidelines and the <strong>EU AI Act</strong>.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div className="relative">
            <Search className="w-4 h-4 text-[#a4b1cd] absolute left-3 top-2.5" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search topic (e.g. XSS, supply chain, vector, Aadhaar, loop)..."
              className="w-full bg-[#1a2332] border border-[#2d3b52] rounded-lg pl-9 pr-3 py-2 text-xs text-[#e2e8f0] placeholder-[#64748b] focus:outline-none focus:border-[#2ee7b6]"
            />
          </div>

          <select
            value={frameworkFilter}
            onChange={(e) => setFrameworkFilter(e.target.value)}
            className="bg-[#1a2332] border border-[#2d3b52] rounded-lg px-3 py-2 text-xs text-[#e2e8f0]"
          >
            <option value="ALL">Show All 10 OWASP LLM Categories</option>
            <option value="OWASP_1_5">OWASP LLM01 – LLM05</option>
            <option value="OWASP_6_10">OWASP LLM06 – LLM10</option>
            <option value="HIGH_RISK">EU AI Act High-Risk Categories</option>
          </select>
        </div>
      </section>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {filteredRows.map((row) => (
          <article
            key={row.id}
            className="bg-[#111824] border border-[#2d3b52] rounded-xl p-5 flex flex-col justify-between space-y-4"
          >
            <div className="space-y-2.5">
              <div className="flex flex-wrap gap-1.5 text-[11px] font-mono">
                <span className="px-2 py-0.5 rounded bg-[#f59e0b]/10 text-[#f59e0b] border border-[#f59e0b]/30">
                  OWASP {row.owaspId}
                </span>
                <span className="px-2 py-0.5 rounded bg-[#38bdf8]/10 text-[#38bdf8] border border-[#38bdf8]/30">
                  NIST {row.nistFunction}
                </span>
                <span className="px-2 py-0.5 rounded bg-[#2ee7b6]/10 text-[#2ee7b6] border border-[#2ee7b6]/30">
                  {row.euRiskTier}
                </span>
              </div>

              <h3 className="text-sm font-semibold text-[#e2e8f0]">{row.threatVector}</h3>
              <p className="text-xs text-[#a4b1cd] leading-relaxed">{row.controlSummary}</p>
            </div>

            <div className="pt-2 border-t border-[#2d3b52] flex flex-wrap items-center justify-between gap-2">
              <span className="text-[11px] font-mono text-[#a4b1cd] truncate max-w-[230px]">
                {row.controlOwner}
              </span>
              {row.payloadIds[0] && (
                <button
                  type="button"
                  onClick={() => onInspectPayload(row.payloadIds[0])}
                  className="inline-flex items-center gap-1 text-xs font-medium text-[#2ee7b6] hover:underline"
                >
                  Try {row.payloadIds[0]} <ArrowRight className="w-3.5 h-3.5" />
                </button>
              )}
            </div>
          </article>
        ))}
      </div>
    </div>
  )
}
