'use client'

import type { LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface MetricCardProps {
  title: string
  value: string | number
  subtext?: string
  icon: LucideIcon
  color?: string
  className?: string
}

export function MetricCard({ title, value, subtext, icon: Icon, color = '#6366F1', className }: MetricCardProps) {
  return (
    <div
      className={cn(
        'group relative rounded p-4 border border-[#334155] bg-[#0B1120] transition-all duration-200',
        'hover:border-indigo-500 hover:shadow-[0_0_20px_rgba(99,102,241,0.2)]',
        className
      )}
    >
      {/* Header pill */}
      <div className="flex items-center gap-2 mb-3">
        <div
          className="flex items-center justify-center w-6 h-6 rounded"
          style={{ backgroundColor: `${color}22`, border: `1px solid ${color}55` }}
        >
          <Icon className="w-3.5 h-3.5" style={{ color }} />
        </div>
        <span className="section-label">{title}</span>
      </div>

      {/* Value */}
      <p className="metric-value" style={{ color }}>
        {value}
      </p>

      {/* Subtext */}
      {subtext && (
        <p className="mt-2 text-[11px] text-[#64748B]">{subtext}</p>
      )}
    </div>
  )
}
