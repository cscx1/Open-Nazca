'use client'

import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'

interface VulnTypePoint {
  type: string
  count: number
}

interface VulnTypesChartProps {
  data: VulnTypePoint[]
}

const BAR_COLORS = ['#4338CA', '#6366F1', '#818CF8', '#A5B4FC', '#C7D2FE', '#E0E7FF']

interface CustomTooltipProps {
  active?: boolean
  payload?: Array<{ value?: number; payload?: VulnTypePoint }>
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.length) return null
  const item = payload[0]
  return (
    <div className="bg-[#0F172A] border border-[#334155] rounded p-3 text-xs shadow-xl">
      <p className="text-[#94A3B8] mb-1">{item.payload?.type}</p>
      <p className="text-white font-mono font-semibold">{item.value} findings</p>
    </div>
  )
}

export function VulnTypesChart({ data }: VulnTypesChartProps) {
  const sorted = [...data].sort((a, b) => b.count - a.count).slice(0, 8)

  return (
    <div className="rounded border border-[#334155] bg-[#0B1120] p-4">
      <p className="section-label mb-4">Vulnerability Types</p>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={sorted} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" horizontal={false} />
          <XAxis
            type="number"
            tick={{ fill: '#64748B', fontSize: 10 }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            type="category"
            dataKey="type"
            width={110}
            tick={{ fill: '#94A3B8', fontSize: 9 }}
            axisLine={false}
            tickLine={false}
            tickFormatter={(v: string) => v.length > 16 ? v.slice(0, 16) + '…' : v}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: '#1E293B' }} />
          <Bar dataKey="count" radius={[0, 2, 2, 0]}>
            {sorted.map((_, i) => (
              <Cell key={i} fill={BAR_COLORS[i % BAR_COLORS.length]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
