'use client'

import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import type { Severity } from '@/lib/types'

interface SeverityPieChartProps {
  counts: Partial<Record<Severity, number>>
}

const SLICE_CONFIG: { severity: Severity; color: string }[] = [
  { severity: 'CRITICAL', color: '#DC2626' },
  { severity: 'HIGH',     color: '#EA580C' },
  { severity: 'MEDIUM',   color: '#CA8A04' },
  { severity: 'LOW',      color: '#2563EB' },
]

interface CustomTooltipProps {
  active?: boolean
  payload?: Array<{ name?: string; value?: number }>
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.length) return null
  const item = payload[0]
  return (
    <div className="bg-[#0F172A] border border-[#334155] rounded p-3 text-xs shadow-xl">
      <p className="text-[#94A3B8] mb-1">{item.name}</p>
      <p className="text-white font-mono font-semibold">{item.value}</p>
    </div>
  )
}

export function SeverityPieChart({ counts }: SeverityPieChartProps) {
  const data = SLICE_CONFIG
    .map(({ severity, color }) => ({
      name: severity,
      value: counts[severity] ?? 0,
      color,
    }))
    .filter((d) => d.value > 0)

  const total = data.reduce((s, d) => s + d.value, 0)

  return (
    <div className="rounded border border-[#334155] bg-[#0B1120] p-4">
      <p className="section-label mb-4">Severity Distribution</p>
      <div className="flex items-center gap-4">
        <ResponsiveContainer width={160} height={160}>
          <PieChart>
            <Pie
              data={data}
              cx="50%"
              cy="50%"
              innerRadius={48}
              outerRadius={70}
              paddingAngle={3}
              dataKey="value"
              strokeWidth={0}
            >
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>

        {/* Legend + total */}
        <div className="flex-1 space-y-2">
          <p className="text-2xl font-bold font-mono text-white">{total}</p>
          <p className="text-[10px] text-[#64748B] uppercase tracking-wide mb-2">Total</p>
          {data.map(({ name, value, color }) => (
            <div key={name} className="flex items-center justify-between">
              <div className="flex items-center gap-1.5">
                <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: color }} />
                <span className="text-[10px] text-[#94A3B8]">{name}</span>
              </div>
              <span className="text-[11px] font-mono font-semibold text-white">{value}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
