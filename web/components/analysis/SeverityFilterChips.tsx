'use client'

import { motion } from 'framer-motion'
import type { Severity } from '@/lib/types'
import { cn } from '@/lib/utils'

const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const chipStyle: Record<Severity, { text: string; activeBg: string; activeBorder: string }> = {
  CRITICAL: { text: 'text-red-300',    activeBg: 'bg-red-500/20',    activeBorder: 'border-red-500' },
  HIGH:     { text: 'text-orange-300', activeBg: 'bg-orange-500/20', activeBorder: 'border-orange-500' },
  MEDIUM:   { text: 'text-yellow-300', activeBg: 'bg-yellow-500/20', activeBorder: 'border-yellow-500' },
  LOW:      { text: 'text-blue-300',   activeBg: 'bg-blue-500/20',   activeBorder: 'border-blue-500' },
}

interface SeverityFilterChipsProps {
  active: Severity[]
  onChange: (v: Severity[]) => void
  counts?: Partial<Record<Severity, number>>
}

export function SeverityFilterChips({ active, onChange, counts }: SeverityFilterChipsProps) {
  function toggle(s: Severity) {
    if (active.includes(s)) {
      onChange(active.filter((x) => x !== s))
    } else {
      onChange([...active, s])
    }
  }

  const allActive = active.length === SEVERITIES.length || active.length === 0

  return (
    <div className="flex flex-wrap items-center gap-2">
      <button
        onClick={() => onChange(SEVERITIES)}
        className={cn(
          'relative px-2.5 py-1 text-[11px] rounded border transition-colors overflow-hidden',
          allActive
            ? 'border-indigo-500 text-indigo-300'
            : 'border-[#334155] text-[#64748B] hover:border-[#475569]'
        )}
      >
        {allActive && (
          <motion.span
            layoutId="chip-active-bg"
            className="absolute inset-0 bg-indigo-500/20 rounded"
            transition={{ type: 'spring', stiffness: 400, damping: 30 }}
          />
        )}
        <span className="relative">All</span>
      </button>
      {SEVERITIES.map((s) => {
        const isActive = active.includes(s)
        const styles = chipStyle[s]
        const count = counts?.[s]
        return (
          <button
            key={s}
            onClick={() => toggle(s)}
            className={cn(
              'relative px-2.5 py-1 text-[11px] rounded border font-semibold tracking-wide transition-colors overflow-hidden',
              isActive
                ? `${styles.activeBorder} ${styles.text}`
                : 'border-[#334155] text-[#64748B] hover:border-[#475569]'
            )}
          >
            {isActive && (
              <motion.span
                layoutId={`chip-active-bg-${s}`}
                className={cn('absolute inset-0 rounded', styles.activeBg)}
                transition={{ type: 'spring', stiffness: 400, damping: 30 }}
              />
            )}
            <span className="relative">
              {s}
              {count !== undefined && (
                <span className="ml-1.5 opacity-70 font-normal font-mono">{count}</span>
              )}
            </span>
          </button>
        )
      })}
    </div>
  )
}
