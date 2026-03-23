'use client'

import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

interface TrendPoint {
  date: string
  total: number
  critical: number
  high: number
}

interface FindingsTrendChartProps {
  data: TrendPoint[]
}

interface TooltipEntry {
  dataKey?: string | number
  value?: number
  color?: string
}

interface CustomTooltipProps {
  active?: boolean
  payload?: TooltipEntry[]
  label?: string
}

function CustomTooltip({ active, payload, label }: CustomTooltipProps) {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-[#0F172A] border border-[#334155] rounded p-3 text-xs space-y-1 shadow-xl">
      <p className="text-[#94A3B8] mb-1.5 font-medium">{label}</p>
      {payload.map((p, i) => (
        <div key={i} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: p.color }} />
          <span className="text-[#B0B8C1] capitalize">{p.dataKey}:</span>
          <span className="text-white font-mono font-semibold">{p.value}</span>
        </div>
      ))}
    </div>
  )
}

export function FindingsTrendChart({ data }: FindingsTrendChartProps) {
  return (
    <div className="rounded border border-[#334155] bg-[#0B1120] p-4">
      <p className="section-label mb-4">Findings Trend</p>
      <ResponsiveContainer width="100%" height={200}>
        <LineChart data={data} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" />
          <XAxis
            dataKey="date"
            tick={{ fill: '#64748B', fontSize: 10 }}
            axisLine={{ stroke: '#334155' }}
            tickLine={false}
          />
          <YAxis
            tick={{ fill: '#64748B', fontSize: 10 }}
            axisLine={false}
            tickLine={false}
          />
          <Tooltip content={<CustomTooltip />} />
          <Line type="monotone" dataKey="total"    stroke="#6366F1" strokeWidth={2} dot={false} />
          <Line type="monotone" dataKey="critical" stroke="#DC2626" strokeWidth={1.5} dot={false} strokeDasharray="4 2" />
          <Line type="monotone" dataKey="high"     stroke="#EA580C" strokeWidth={1.5} dot={false} strokeDasharray="4 2" />
        </LineChart>
      </ResponsiveContainer>
      <div className="flex items-center gap-4 mt-3">
        {[
          { color: '#6366F1', label: 'Total' },
          { color: '#DC2626', label: 'Critical' },
          { color: '#EA580C', label: 'High' },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1.5">
            <span className="w-3 h-0.5 inline-block" style={{ backgroundColor: color }} />
            <span className="text-[10px] text-[#64748B]">{label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
