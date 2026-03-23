'use client'

import { useState } from 'react'
import { ChevronDown, ChevronRight, Copy, Check } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { SeverityBadge } from '@/components/ui/severity-badge'
import type { Finding } from '@/lib/types'
import { cn } from '@/lib/utils'

interface FindingCardProps {
  finding: Finding
  index: number
}

function CodeBlock({ code, label }: { code: string; label: string }) {
  const [copied, setCopied] = useState(false)

  async function copy() {
    await navigator.clipboard.writeText(code)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div className="rounded border border-[#334155] overflow-hidden">
      <div className="flex items-center justify-between px-3 py-1.5 bg-[#0F172A] border-b border-[#334155]">
        <span className="text-[10px] text-[#64748B] uppercase tracking-wider">{label}</span>
        <button
          onClick={copy}
          className="flex items-center gap-1 text-[10px] text-[#64748B] hover:text-white transition-colors"
          aria-label="Copy to clipboard"
        >
          {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="p-3 text-[11px] text-[#B0B8C1] overflow-x-auto font-mono leading-relaxed bg-[#000E1A]">
        <code>{code}</code>
      </pre>
    </div>
  )
}

export function FindingCard({ finding, index }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="rounded border border-[#334155] bg-[#0B1120] overflow-hidden">
      {/* Header row — always visible */}
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-[#0F172A] transition-colors"
        onClick={() => setExpanded((e) => !e)}
        aria-expanded={expanded}
      >
        <span className="text-xs text-[#475569] font-mono w-5 shrink-0">#{index + 1}</span>
        <SeverityBadge severity={finding.severity} size="sm" />
        <span className="flex-1 min-w-0">
          <span className="block text-sm font-medium text-white truncate">{finding.vulnerability_type}</span>
          <span className="block text-[11px] text-[#64748B] truncate">{finding.description}</span>
        </span>
        <div className="flex items-center gap-3 shrink-0">
          {finding.line_number !== 'N/A' && (
            <span className="text-[10px] text-[#475569] font-mono">L{finding.line_number}</span>
          )}
          {finding.verdict_status && (
            <span
              className={cn(
                'text-[10px] px-2 py-0.5 rounded border font-semibold uppercase tracking-wide',
                finding.verdict_status === 'CONFIRMED'
                  ? 'border-red-700 text-red-400 bg-red-900/20'
                  : finding.verdict_status === 'FALSE_POSITIVE'
                  ? 'border-green-700 text-green-400 bg-green-900/20'
                  : 'border-[#334155] text-[#64748B]'
              )}
            >
              {finding.verdict_status}
            </span>
          )}
          {expanded ? (
            <ChevronDown className="w-4 h-4 text-[#64748B]" />
          ) : (
            <ChevronRight className="w-4 h-4 text-[#64748B]" />
          )}
        </div>
      </button>

      {/* Expanded detail */}
      <AnimatePresence initial={false}>
      {expanded && (
        <motion.div
          key="expanded"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
        >
        <div className="border-t border-[#1E293B] px-4 py-4 space-y-4">
          {/* Meta row */}
          <div className="flex flex-wrap gap-x-6 gap-y-1.5 text-xs">
            <span><span className="text-[#475569]">Detector: </span><span className="text-[#94A3B8] font-mono">{finding.detector_name}</span></span>
            {finding.cwe_id && <span><span className="text-[#475569]">CWE: </span><span className="text-[#94A3B8]">{finding.cwe_id}</span></span>}
            {finding.confidence !== undefined && (
              <span><span className="text-[#475569]">Confidence: </span><span className="text-[#94A3B8]">{(finding.confidence * 100).toFixed(0)}%</span></span>
            )}
          </div>

          {/* Code snippet */}
          {finding.code_snippet && (
            <CodeBlock code={finding.code_snippet} label="Code Snippet" />
          )}

          {/* Risk analysis */}
          {finding.risk_explanation && (
            <div>
              <p className="section-label mb-2">AI Risk Analysis</p>
              <p className="text-xs text-[#94A3B8] leading-relaxed">{finding.risk_explanation}</p>
            </div>
          )}

          {/* Suggested fix */}
          {finding.suggested_fix && (
            <div>
              <p className="section-label mb-2">Suggested Fix</p>
              <CodeBlock code={finding.suggested_fix} label="Fix" />
            </div>
          )}

          {/* Verdict reason */}
          {finding.verdict_reason && (
            <div>
              <p className="section-label mb-1">Verdict Reasoning</p>
              <p className="text-xs text-[#94A3B8] leading-relaxed">{finding.verdict_reason}</p>
            </div>
          )}

          {/* Reachability */}
          {finding.reachability_status && (
            <div>
              <p className="section-label mb-1">Reachability</p>
              <p className="text-xs text-[#94A3B8]">{finding.reachability_status}</p>
              {finding.reachability_reasoning && (
                <p className="text-xs text-[#64748B] mt-1 leading-relaxed">{finding.reachability_reasoning}</p>
              )}
            </div>
          )}
        </div>
        </motion.div>
      )}
      </AnimatePresence>
    </div>
  )
}
