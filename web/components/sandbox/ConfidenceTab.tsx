'use client'

import { ShieldCheck, ShieldOff, HelpCircle, Eye, AlertTriangle } from 'lucide-react'
import type { SandboxResults, ReachabilityResult } from '@/lib/types'
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip'

type ReachabilityStatus = ReachabilityResult['status']

const STATUS_CONFIG: Record<ReachabilityStatus, {
  icon: React.ComponentType<{ className?: string }>
  label: string
  color: string
  border: string
  bg: string
  description: string
  tooltip: string
}> = {
  'Confirmed Reachable': {
    icon: ShieldOff,
    label: 'Confirmed Reachable',
    color: '#DC2626',
    border: '#7F1D1D',
    bg: 'rgba(220,38,38,0.07)',
    description: 'Attack path is verified reachable — immediate remediation required.',
    tooltip: 'Tainted data reaches a sensitive sink with no sanitiser detected by static analysis',
  },
  'Reachability Eliminated': {
    icon: ShieldCheck,
    label: 'Reachability Eliminated',
    color: '#10B981',
    border: '#065F46',
    bg: 'rgba(16,185,129,0.07)',
    description: 'Fix was verified to break the attack path. Vulnerability neutralised.',
    tooltip: 'The attack path was broken by automated remediation or an existing sanitiser',
  },
  'Unverifiable': {
    icon: HelpCircle,
    label: 'Unverifiable',
    color: '#CA8A04',
    border: '#78350F',
    bg: 'rgba(202,138,4,0.07)',
    description: 'Dynamic conditions prevent static verification. Manual review advised.',
    tooltip: 'A path exists but sanitisation cannot be proven statically — manual review advised',
  },
  'Requires Manual Review': {
    icon: Eye,
    label: 'Requires Manual Review',
    color: '#3B82F6',
    border: '#1E3A5F',
    bg: 'rgba(59,130,246,0.07)',
    description: 'Complexity or side-effects require a human to assess the risk.',
    tooltip: 'Reachability depends on runtime context that static analysis cannot evaluate',
  },
}

function ReachabilityCard({ result }: { result: ReachabilityResult }) {
  const cfg = STATUS_CONFIG[result.status]
  const Icon = cfg.icon

  return (
    <div
      className="rounded border p-4 space-y-3"
      style={{ backgroundColor: cfg.bg, borderColor: cfg.border }}
    >
      <div className="flex items-center gap-2.5">
        <div className="flex items-center justify-center w-7 h-7 rounded-full"
          style={{ backgroundColor: `${cfg.color}22`, border: `1px solid ${cfg.border}` }}>
          <span style={{ color: cfg.color }}><Icon className="w-3.5 h-3.5" /></span>
        </div>
        <Tooltip>
          <TooltipTrigger
            render={<span />}
            className="text-xs font-semibold cursor-help underline decoration-dotted underline-offset-2"
            style={{ color: cfg.color }}
          >
            {cfg.label}
          </TooltipTrigger>
          <TooltipContent side="top">{cfg.tooltip}</TooltipContent>
        </Tooltip>
      </div>

      <p className="text-[11px] text-[#94A3B8]">{cfg.description}</p>

      {/* Attack path summary */}
      <div className="text-[11px] text-[#64748B] space-y-0.5">
        <div><span className="text-[#475569]">Source: </span><span className="font-mono text-[#94A3B8]">{result.path.source.name}</span> <span className="text-[#334155]">L{result.path.source.line}</span></div>
        <div><span className="text-[#475569]">Sink: </span><span className="font-mono text-[#94A3B8]">{result.path.sink.name}</span> <span className="text-[#334155]">L{result.path.sink.line}</span></div>
        <div><span className="text-[#475569]">Type: </span><span className="text-[#94A3B8]">{result.path.vulnerability_type}</span></div>
      </div>

      {/* Reasoning */}
      {result.reasoning && (
        <p className="text-[11px] text-[#64748B] italic leading-relaxed border-l-2 pl-3" style={{ borderColor: cfg.border }}>
          {result.reasoning}
        </p>
      )}
    </div>
  )
}

function StatusSummaryRow({ status, count, total }: { status: ReachabilityStatus; count: number; total: number }) {
  const cfg = STATUS_CONFIG[status]
  const Icon = cfg.icon
  const pct = total > 0 ? Math.round((count / total) * 100) : 0

  return (
    <div className="flex items-center gap-3">
      <span style={{ color: cfg.color }}><Icon className="w-3.5 h-3.5 shrink-0" /></span>
      <div className="flex-1">
        <div className="flex justify-between mb-1">
          <Tooltip>
            <TooltipTrigger
              render={<span />}
              className="text-xs text-[#94A3B8] cursor-help"
            >
              {cfg.label}
            </TooltipTrigger>
            <TooltipContent side="top">{cfg.tooltip}</TooltipContent>
          </Tooltip>
          <span className="text-xs font-mono text-white">{count}</span>
        </div>
        <div className="h-1.5 rounded-full bg-[#1E293B] overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{ width: `${pct}%`, backgroundColor: cfg.color }}
          />
        </div>
      </div>
      <span className="text-[10px] text-[#475569] w-8 text-right">{pct}%</span>
    </div>
  )
}

interface ConfidenceTabProps {
  results: SandboxResults | null
}

export function ConfidenceTab({ results }: ConfidenceTabProps) {
  if (!results) {
    return <div className="py-16 text-center text-sm text-[#475569]">Run the sandbox to see confidence classification</div>
  }

  // Collect all reachability results across files (before + after)
  const allResults: ReachabilityResult[] = []
  for (const fr of Object.values(results.files)) {
    allResults.push(...fr.reachability_before, ...fr.reachability_after)
  }

  const STATUS_ORDER: ReachabilityStatus[] = [
    'Confirmed Reachable',
    'Reachability Eliminated',
    'Unverifiable',
    'Requires Manual Review',
  ]

  const counts = STATUS_ORDER.reduce<Record<ReachabilityStatus, number>>((acc, s) => {
    acc[s] = allResults.filter((r) => r.status === s).length
    return acc
  }, {} as Record<ReachabilityStatus, number>)

  const total = allResults.length

  if (total === 0) {
    return (
      <div className="py-16 flex flex-col items-center gap-4 text-center">
        <AlertTriangle className="w-8 h-8 text-[#475569]" />
        <p className="text-sm text-[#64748B]">No reachability data — ensure the Python backend provides reachability analysis</p>
      </div>
    )
  }

  const grouped = STATUS_ORDER.reduce<Record<ReachabilityStatus, ReachabilityResult[]>>((acc, s) => {
    acc[s] = allResults.filter((r) => r.status === s)
    return acc
  }, {} as Record<ReachabilityStatus, ReachabilityResult[]>)

  return (
    <div className="space-y-6">
      {/* Summary bar */}
      <div className="rounded border border-[#334155] bg-[#0B1120] p-5 space-y-4">
        <p className="section-label">Trust-Gradient Classification ({total} paths)</p>
        {STATUS_ORDER.map((s) => (
          <StatusSummaryRow key={s} status={s} count={counts[s]} total={total} />
        ))}
      </div>

      {/* Per-status result groups */}
      {STATUS_ORDER.map((s) => {
        const items = grouped[s]
        if (!items.length) return null
        const cfg = STATUS_CONFIG[s]
        return (
          <div key={s}>
            <p className="section-label mb-3" style={{ color: cfg.color }}>{cfg.label} ({items.length})</p>
            <div className="grid grid-cols-2 gap-3">
              {items.map((r, i) => <ReachabilityCard key={i} result={r} />)}
            </div>
          </div>
        )
      })}
    </div>
  )
}
