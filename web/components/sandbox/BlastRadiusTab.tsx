'use client'

import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Cell, PieChart, Pie,
} from 'recharts'
import type { SandboxResults, Severity } from '@/lib/types'
import { cn } from '@/lib/utils'

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#DC2626',
  HIGH:     '#EA580C',
  MEDIUM:   '#CA8A04',
  LOW:      '#2563EB',
}

interface CustomBarTooltipProps {
  active?: boolean
  payload?: Array<{ value?: number; payload?: Record<string, unknown> }>
  label?: string
}

function CustomBarTooltip({ active, payload, label }: CustomBarTooltipProps) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-[#0F172A] border border-[#334155] rounded p-2.5 text-xs shadow-xl">
      <p className="text-[#94A3B8] mb-1">{label}</p>
      <p className="text-white font-mono font-semibold">{payload[0]?.value ?? 0}</p>
    </div>
  )
}

function aggregateSeverity(results: SandboxResults, phase: 'before' | 'after') {
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }
  for (const fr of Object.values(results.files)) {
    const findings = phase === 'before' ? fr.findings_before : fr.findings_after
    for (const f of findings) {
      counts[f.severity] = (counts[f.severity] ?? 0) + 1
    }
  }
  return counts
}

function aggregateVulnTypes(results: SandboxResults, phase: 'before' | 'after') {
  const counts: Record<string, number> = {}
  for (const fr of Object.values(results.files)) {
    const findings = phase === 'before' ? fr.findings_before : fr.findings_after
    for (const f of findings) {
      counts[f.vulnerability_type] = (counts[f.vulnerability_type] ?? 0) + 1
    }
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([type, count]) => ({ type, count }))
}

const BAR_COLORS = ['#4338CA','#6366F1','#818CF8','#A5B4FC','#C7D2FE','#E0E7FF','#7C3AED','#8B5CF6','#A78BFA','#C4B5FD']

interface BlastRadiusTabProps {
  results: SandboxResults | null
}

export function BlastRadiusTab({ results }: BlastRadiusTabProps) {
  if (!results) {
    return <div className="py-16 text-center text-sm text-[#475569]">Run the sandbox to see blast radius</div>
  }

  const beforeSev = aggregateSeverity(results, 'before')
  const afterSev  = aggregateSeverity(results, 'after')

  const beforeTotal = Object.values(beforeSev).reduce((a, b) => a + b, 0)
  const afterTotal  = Object.values(afterSev).reduce((a, b) => a + b, 0)
  const reduced     = beforeTotal - afterTotal

  const beforeVuln = aggregateVulnTypes(results, 'before')
  const afterVuln  = aggregateVulnTypes(results, 'after')

  const severityData = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map((sev) => ({
    sev,
    before: beforeSev[sev],
    after:  afterSev[sev],
    color:  SEVERITY_COLORS[sev],
  }))

  const donutData = (['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[])
    .map((sev) => ({ name: sev, value: beforeSev[sev], color: SEVERITY_COLORS[sev] }))
    .filter((d) => d.value > 0)

  return (
    <div className="space-y-6">
      {/* Summary cards */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: 'Total Before',    value: beforeTotal,            color: '#DC2626' },
          { label: 'Total After',     value: afterTotal,             color: afterTotal > 0 ? '#EA580C' : '#10B981' },
          { label: 'Findings Fixed',  value: results.total_functional_fixes, color: '#10B981' },
          { label: 'Fixes Rejected',  value: results.total_rejected_fixes,   color: '#CA8A04' },
        ].map(({ label, value, color }) => (
          <div key={label} className="rounded border border-[#334155] bg-[#0B1120] p-4">
            <p className="section-label mb-2">{label}</p>
            <p className="metric-value" style={{ color }}>{value}</p>
          </div>
        ))}
      </div>

      {/* Progress bar showing reduction */}
      {beforeTotal > 0 && (
        <div className="rounded border border-[#334155] bg-[#0B1120] p-4">
          <div className="flex items-center justify-between mb-2">
            <p className="section-label">Vulnerability Reduction</p>
            <span className={cn('text-sm font-semibold font-mono', reduced > 0 ? 'text-emerald-400' : 'text-[#64748B]')}>
              {reduced > 0 ? `−${reduced}` : '0'} ({beforeTotal > 0 ? Math.round((reduced / beforeTotal) * 100) : 0}%)
            </span>
          </div>
          <div className="h-3 rounded-full bg-[#1E293B] overflow-hidden">
            <div
              className="h-full rounded-full bg-emerald-500 transition-all duration-700"
              style={{ width: `${beforeTotal > 0 ? Math.round(((beforeTotal - afterTotal) / beforeTotal) * 100) : 0}%` }}
            />
          </div>
          <div className="flex justify-between mt-1 text-[10px] text-[#475569]">
            <span>{afterTotal} remaining</span>
            <span>{beforeTotal} initial</span>
          </div>
        </div>
      )}

      <div className="grid grid-cols-3 gap-5">
        {/* Severity comparison bar chart */}
        <div className="col-span-2 rounded border border-[#334155] bg-[#0B1120] p-4">
          <p className="section-label mb-4">Severity Before vs After</p>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={severityData} barCategoryGap="30%" barGap={2}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
              <XAxis dataKey="sev" tick={{ fill: '#64748B', fontSize: 10 }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fill: '#64748B', fontSize: 10 }} axisLine={false} tickLine={false} />
              <Tooltip content={<CustomBarTooltip />} cursor={{ fill: '#1E293B' }} />
              <Bar dataKey="before" name="Before" radius={[2, 2, 0, 0]} opacity={0.9}>
                {severityData.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Bar>
              <Bar dataKey="after" name="After" radius={[2, 2, 0, 0]} opacity={0.45}>
                {severityData.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
          <div className="flex gap-4 mt-2">
            <div className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-[#6366F1]" /><span className="text-[10px] text-[#64748B]">Before</span></div>
            <div className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-[#6366F1] opacity-45" /><span className="text-[10px] text-[#64748B]">After</span></div>
          </div>
        </div>

        {/* Donut summary */}
        <div className="rounded border border-[#334155] bg-[#0B1120] p-4 flex flex-col items-center">
          <p className="section-label mb-3 self-start">Before (by severity)</p>
          <PieChart width={140} height={140}>
            <Pie data={donutData} cx={70} cy={70} innerRadius={44} outerRadius={64} paddingAngle={3} dataKey="value" strokeWidth={0}>
              {donutData.map((d, i) => <Cell key={i} fill={d.color} />)}
            </Pie>
          </PieChart>
          <div className="space-y-1.5 w-full mt-2">
            {donutData.map(({ name, value, color }) => (
              <div key={name} className="flex items-center justify-between text-[11px]">
                <div className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full" style={{ backgroundColor: color }} />
                  <span className="text-[#94A3B8]">{name}</span>
                </div>
                <span className="font-mono text-white">{value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Vuln type before/after */}
      <div className="grid grid-cols-2 gap-5">
        {[{ label: 'Types — Before', data: beforeVuln }, { label: 'Types — After', data: afterVuln }].map(({ label, data }) => (
          <div key={label} className="rounded border border-[#334155] bg-[#0B1120] p-4">
            <p className="section-label mb-3">{label}</p>
            {data.length === 0 ? (
              <p className="text-xs text-emerald-400 py-4">All clear ✓</p>
            ) : (
              <ResponsiveContainer width="100%" height={180}>
                <BarChart data={data} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" horizontal={false} />
                  <XAxis type="number" tick={{ fill: '#64748B', fontSize: 9 }} axisLine={false} tickLine={false} />
                  <YAxis type="category" dataKey="type" width={100} tick={{ fill: '#94A3B8', fontSize: 9 }} axisLine={false} tickLine={false} tickFormatter={(v: string) => v.length > 14 ? v.slice(0, 14) + '…' : v} />
                  <Tooltip content={<CustomBarTooltip />} cursor={{ fill: '#1E293B' }} />
                  <Bar dataKey="count" radius={[0, 2, 2, 0]}>
                    {data.map((_, i) => <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />)}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
