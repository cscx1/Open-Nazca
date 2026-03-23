'use client'

import { useState } from 'react'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { Skeleton } from '@/components/ui/skeleton'
import { FindingCard } from './FindingCard'
import type { Finding, Severity } from '@/lib/types'
import { cn } from '@/lib/utils'
import { ArrowUpDown } from 'lucide-react'

export function FindingsTableSkeleton({ rows = 5 }: { rows?: number }) {
  return (
    <div className="rounded border border-[#334155] overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="bg-[#0F172A] border-b border-[#334155] hover:bg-[#0F172A]">
            {['#', 'Type', 'Severity', 'Verdict', 'Line', 'Description', 'Detector'].map((h) => (
              <TableHead key={h}>
                <Skeleton className="h-2.5 w-12 rounded" />
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: rows }).map((_, i) => (
            <TableRow key={i} className="border-b border-[#1E293B]">
              <TableCell><Skeleton className="h-3 w-4 rounded" /></TableCell>
              <TableCell><Skeleton className="h-3 w-32 rounded" /></TableCell>
              <TableCell><Skeleton className="h-5 w-16 rounded" /></TableCell>
              <TableCell><Skeleton className="h-3 w-16 rounded" /></TableCell>
              <TableCell><Skeleton className="h-3 w-8 rounded" /></TableCell>
              <TableCell><Skeleton className="h-3 w-40 rounded" /></TableCell>
              <TableCell><Skeleton className="h-3 w-24 rounded" /></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

type SortField = 'severity' | 'vulnerability_type' | 'line_number'
type SortDir = 'asc' | 'desc'

const SEVERITY_ORDER: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }

interface FindingsTableProps {
  findings: Finding[]
}

export function FindingsTable({ findings }: FindingsTableProps) {
  const [sortField, setSortField] = useState<SortField>('severity')
  const [sortDir, setSortDir] = useState<SortDir>('asc')
  const [expandedIdx, setExpandedIdx] = useState<number | null>(null)

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDir('asc')
    }
  }

  const sorted = [...findings].sort((a, b) => {
    let cmp = 0
    if (sortField === 'severity') {
      cmp = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]
    } else if (sortField === 'vulnerability_type') {
      cmp = a.vulnerability_type.localeCompare(b.vulnerability_type)
    } else {
      const aLine = a.line_number === 'N/A' ? Infinity : a.line_number
      const bLine = b.line_number === 'N/A' ? Infinity : b.line_number
      cmp = (aLine as number) - (bLine as number)
    }
    return sortDir === 'asc' ? cmp : -cmp
  })

  function SortButton({ field, label }: { field: SortField; label: string }) {
    const active = sortField === field
    return (
      <button
        onClick={() => handleSort(field)}
        className={cn('flex items-center gap-1 text-[10px] uppercase tracking-wider font-semibold transition-colors', active ? 'text-indigo-400' : 'text-[#64748B] hover:text-[#94A3B8]')}
      >
        {label}
        <ArrowUpDown className="w-3 h-3" />
      </button>
    )
  }

  return (
    <div className="rounded border border-[#334155] overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="bg-[#0F172A] border-b border-[#334155] hover:bg-[#0F172A]">
            <TableHead className="w-8 text-center text-[#475569] text-[10px]">#</TableHead>
            <TableHead><SortButton field="vulnerability_type" label="Type" /></TableHead>
            <TableHead><SortButton field="severity" label="Severity" /></TableHead>
            <TableHead className="text-[10px] uppercase tracking-wider text-[#64748B]">Verdict</TableHead>
            <TableHead><SortButton field="line_number" label="Line" /></TableHead>
            <TableHead className="text-[10px] uppercase tracking-wider text-[#64748B]">Description</TableHead>
            <TableHead className="text-[10px] uppercase tracking-wider text-[#64748B]">Detector</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {sorted.map((finding, i) => (
            <>
              <TableRow
                key={`row-${i}`}
                className={cn(
                  'border-b border-[#1E293B] cursor-pointer transition-colors',
                  expandedIdx === i ? 'bg-[#0F172A]' : 'hover:bg-[#0F172A]'
                )}
                onClick={() => setExpandedIdx(expandedIdx === i ? null : i)}
              >
                <TableCell className="text-center text-[11px] text-[#475569] font-mono">{i + 1}</TableCell>
                <TableCell className="text-xs text-[#B0B8C1] font-medium max-w-[160px] truncate">{finding.vulnerability_type}</TableCell>
                <TableCell><SeverityBadge severity={finding.severity} size="sm" /></TableCell>
                <TableCell>
                  {finding.verdict_status ? (
                    <span className={cn('text-[10px] font-semibold uppercase', finding.verdict_status === 'CONFIRMED' ? 'text-red-400' : finding.verdict_status === 'FALSE_POSITIVE' ? 'text-green-400' : 'text-[#64748B]')}>
                      {finding.verdict_status}
                    </span>
                  ) : (
                    <span className="text-[#475569]">—</span>
                  )}
                </TableCell>
                <TableCell className="text-[11px] text-[#64748B] font-mono">
                  {finding.line_number === 'N/A' ? '—' : `L${finding.line_number}`}
                </TableCell>
                <TableCell className="text-xs text-[#94A3B8] max-w-[240px] truncate">{finding.description}</TableCell>
                <TableCell className="text-[10px] text-[#64748B] font-mono">{finding.detector_name}</TableCell>
              </TableRow>
              {expandedIdx === i && (
                <TableRow key={`expanded-${i}`} className="bg-[#0F172A] border-b border-[#1E293B] hover:bg-[#0F172A]">
                  <TableCell colSpan={7} className="p-0">
                    <div className="px-4 py-3">
                      <FindingCard finding={finding} index={i} />
                    </div>
                  </TableCell>
                </TableRow>
              )}
            </>
          ))}
        </TableBody>
      </Table>
      {sorted.length === 0 && (
        <div className="py-10 text-center text-sm text-[#475569]">No findings match the current filter</div>
      )}
    </div>
  )
}
