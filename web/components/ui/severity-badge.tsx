'use client'

import type { Severity } from '@/lib/types'

const severityConfig: Record<
  Severity,
  { bg: string; text: string; border: string; glow: string; label: string }
> = {
  CRITICAL: { bg: '#DC2626', text: 'white',  border: '#EF4444', glow: 'rgba(220,38,38,0.4)', label: 'Critical' },
  HIGH:     { bg: '#EA580C', text: 'white',  border: '#F97316', glow: 'none',                 label: 'High'     },
  MEDIUM:   { bg: '#CA8A04', text: 'black',  border: '#EAB308', glow: 'none',                 label: 'Medium'   },
  LOW:      { bg: '#2563EB', text: 'white',  border: '#3B82F6', glow: 'none',                 label: 'Low'      },
}

interface SeverityBadgeProps {
  severity: Severity
  size?: 'sm' | 'md'
}

export function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
  const cfg = severityConfig[severity]
  const padding = size === 'sm' ? '1px 6px' : '2px 10px'
  const fontSize = size === 'sm' ? '10px' : '11px'

  return (
    <span
      style={{
        backgroundColor: cfg.bg,
        color: cfg.text,
        border: `1px solid ${cfg.border}`,
        boxShadow: cfg.glow !== 'none' ? `0 0 8px ${cfg.glow}` : undefined,
        padding,
        fontSize,
        fontWeight: 700,
        letterSpacing: '0.06em',
        borderRadius: '3px',
        textTransform: 'uppercase',
        fontFamily: 'var(--font-geist-mono, monospace)',
        whiteSpace: 'nowrap',
        display: 'inline-block',
      }}
    >
      {cfg.label}
    </span>
  )
}

export { severityConfig }
