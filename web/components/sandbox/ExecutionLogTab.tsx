'use client'

import { useState } from 'react'
import { ChevronDown, ChevronRight, CheckCircle2, XCircle, AlertTriangle, ArrowRightLeft } from 'lucide-react'
import { SandboxConsole, type LogLine } from './SandboxConsole'
import { SeverityBadge } from '@/components/ui/severity-badge'
import type { SandboxResults, FixDiff } from '@/lib/types'
import { cn } from '@/lib/utils'

/* ─── Side-by-side diff ─────────────────────────────────────────────────── */
function DiffView({ before, after }: { before: string; after: string }) {
  const beforeLines = before.split('\n')
  const afterLines  = after.split('\n')
  const maxLen      = Math.max(beforeLines.length, afterLines.length)

  return (
    <div className="grid grid-cols-2 gap-1 text-[10px] font-mono rounded border border-[#334155] overflow-hidden">
      {/* Before header */}
      <div className="px-3 py-1.5 bg-red-900/20 border-b border-[#334155] text-red-400 font-semibold uppercase tracking-wider">Before</div>
      <div className="px-3 py-1.5 bg-emerald-900/20 border-b border-[#334155] text-emerald-400 font-semibold uppercase tracking-wider">After</div>
      {/* Lines */}
      <div className="bg-[#000E1A] p-3 overflow-x-auto max-h-64">
        {beforeLines.slice(0, maxLen).map((line, i) => (
          <div key={i} className={cn('whitespace-pre leading-relaxed', line !== afterLines[i] ? 'text-red-300 bg-red-900/20' : 'text-[#64748B]')}>
            <span className="select-none text-[#334155] mr-3">{String(i + 1).padStart(3)}</span>
            {line}
          </div>
        ))}
      </div>
      <div className="bg-[#000E1A] p-3 overflow-x-auto max-h-64">
        {Array.from({ length: maxLen }, (_, i) => afterLines[i] ?? '').map((line, i) => (
          <div key={i} className={cn('whitespace-pre leading-relaxed', line !== beforeLines[i] ? 'text-emerald-300 bg-emerald-900/20' : 'text-[#64748B]')}>
            <span className="select-none text-[#334155] mr-3">{String(i + 1).padStart(3)}</span>
            {line}
          </div>
        ))}
      </div>
    </div>
  )
}

/* ─── Fix tier badge ─────────────────────────────────────────────────────── */
function FixTierBadge({ fix }: { fix: FixDiff }) {
  if (!fix.is_functional) {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-red-700 bg-red-900/20 text-red-400 text-[10px] font-semibold uppercase">
        <XCircle className="w-3 h-3" /> Rejected
      </span>
    )
  }
  return (
    <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded border border-emerald-700 bg-emerald-900/20 text-emerald-400 text-[10px] font-semibold uppercase">
      <CheckCircle2 className="w-3 h-3" /> Applied
    </span>
  )
}

/* ─── Per-file expander ──────────────────────────────────────────────────── */
function FileResultExpander({
  filename,
  result,
}: {
  filename: string
  result: SandboxResults['files'][string]
}) {
  const [open, setOpen] = useState(false)
  const [showDiff, setShowDiff] = useState(false)

  const reduced = result.findings_before.length - result.findings_after.length

  return (
    <div className="rounded border border-[#334155] bg-[#0B1120] overflow-hidden">
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-[#0F172A] transition-colors"
        onClick={() => setOpen((o) => !o)}
      >
        <span className="font-mono text-xs text-white truncate flex-1">{filename}</span>
        <div className="flex items-center gap-2 shrink-0 text-[11px]">
          <span className="text-[#64748B]">{result.findings_before.length} → {result.findings_after.length}</span>
          {reduced > 0 && (
            <span className="text-emerald-400 font-semibold">−{reduced} fixed</span>
          )}
          {result.fixes.some((f) => !f.is_functional) && (
            <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
          )}
        </div>
        {open ? <ChevronDown className="w-4 h-4 text-[#64748B]" /> : <ChevronRight className="w-4 h-4 text-[#64748B]" />}
      </button>

      {open && (
        <div className="border-t border-[#1E293B] px-4 py-4 space-y-5">
          {/* Findings comparison */}
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="section-label mb-2">Before ({result.findings_before.length})</p>
              <div className="space-y-1.5">
                {result.findings_before.length === 0 ? (
                  <p className="text-xs text-[#475569]">None</p>
                ) : (
                  result.findings_before.map((f, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <SeverityBadge severity={f.severity} size="sm" />
                      <span className="text-[#94A3B8] truncate">{f.vulnerability_type}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
            <div>
              <p className="section-label mb-2">After ({result.findings_after.length})</p>
              <div className="space-y-1.5">
                {result.findings_after.length === 0 ? (
                  <p className="text-xs text-emerald-400">All clear ✓</p>
                ) : (
                  result.findings_after.map((f, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      <SeverityBadge severity={f.severity} size="sm" />
                      <span className="text-[#94A3B8] truncate">{f.vulnerability_type}</span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>

          {/* Fix list */}
          {result.fixes.length > 0 && (
            <div>
              <p className="section-label mb-2">Applied Fixes ({result.fixes.length})</p>
              <div className="space-y-2">
                {result.fixes.map((fix, i) => (
                  <div key={i} className="flex items-start gap-3 p-2 rounded bg-[#0F172A] border border-[#1E293B]">
                    <FixTierBadge fix={fix} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs text-[#94A3B8]">{fix.description}</p>
                      <p className="text-[10px] text-[#475569] font-mono mt-0.5">L{fix.line_number} · {fix.vulnerability_type}</p>
                      {fix.rejection_reason && (
                        <p className="text-[10px] text-red-400 mt-1">{fix.rejection_reason}</p>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Diff toggle */}
          {result.original_code && result.fixed_code && (
            <div>
              <button
                onClick={() => setShowDiff((d) => !d)}
                className="flex items-center gap-2 text-xs text-indigo-400 hover:text-indigo-300 transition-colors mb-2"
              >
                <ArrowRightLeft className="w-3.5 h-3.5" />
                {showDiff ? 'Hide diff' : 'Show side-by-side diff'}
              </button>
              {showDiff && <DiffView before={result.original_code} after={result.fixed_code} />}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

/* ─── ExecutionLogTab ────────────────────────────────────────────────────── */
interface ExecutionLogTabProps {
  logLines: LogLine[]
  results: SandboxResults | null
}

export function ExecutionLogTab({ logLines, results }: ExecutionLogTabProps) {
  return (
    <div className="space-y-5">
      <SandboxConsole lines={logLines} height="260px" title="Pipeline Console" />

      {results && Object.keys(results.files).length > 0 && (
        <div className="space-y-3">
          <p className="section-label">Per-file Results</p>
          {Object.entries(results.files).map(([filename, result]) => (
            <FileResultExpander key={filename} filename={filename} result={result} />
          ))}
        </div>
      )}
    </div>
  )
}
