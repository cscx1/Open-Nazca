'use client'

import { useState } from 'react'
import { Trash2, Clock, ChevronUp, ChevronDown } from 'lucide-react'
import {
  Table, TableBody, TableCell, TableHead, TableHeader, TableRow,
} from '@/components/ui/table'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { EmptyState } from '@/components/ui/empty-state'
import { Skeleton } from '@/components/ui/skeleton'
import { useScanHistory } from '@/hooks/useScanHistory'
import type { ScanHistoryEntry, Severity } from '@/lib/types'
import { cn } from '@/lib/utils'

export function HistoryTableSkeleton({ rows = 4 }: { rows?: number }) {
  return (
    <div className="rounded border border-[#334155] overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="bg-[#0F172A] border-b border-[#334155] hover:bg-[#0F172A]">
            {['#', 'File', 'Date', 'Total', 'Critical', 'Severity Split', 'Duration'].map((h) => (
              <TableHead key={h}><Skeleton className="h-2.5 w-12 rounded" /></TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: rows }).map((_, i) => (
            <TableRow key={i} className="border-b border-[#1E293B]">
              <TableCell><Skeleton className="h-3 w-4 rounded" /></TableCell>
              <TableCell>
                <Skeleton className="h-3 w-36 rounded mb-1" />
                <Skeleton className="h-2.5 w-24 rounded" />
              </TableCell>
              <TableCell>
                <Skeleton className="h-3 w-20 rounded mb-1" />
                <Skeleton className="h-2.5 w-12 rounded" />
              </TableCell>
              <TableCell><Skeleton className="h-5 w-8 rounded" /></TableCell>
              <TableCell><Skeleton className="h-5 w-8 rounded" /></TableCell>
              <TableCell><Skeleton className="h-5 w-24 rounded" /></TableCell>
              <TableCell><Skeleton className="h-3 w-10 rounded" /></TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  )
}

type SortField = 'filename' | 'timestamp' | 'total' | 'critical'
type SortDir = 'asc' | 'desc'

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

function HistorySortButton({
  field,
  label,
  active,
  sortDir,
  onSort,
}: {
  field: SortField
  label: string
  active: boolean
  sortDir: SortDir
  onSort: (field: SortField) => void
}) {
  const Icon = sortDir === 'asc' ? ChevronUp : ChevronDown
  return (
    <button
      type="button"
      onClick={() => onSort(field)}
      className={cn(
        'flex items-center gap-1 text-[10px] uppercase tracking-wider font-semibold transition-colors',
        active ? 'text-indigo-400' : 'text-[#64748B] hover:text-[#94A3B8]'
      )}
    >
      {label}
      {active && <Icon className="w-3 h-3" />}
    </button>
  )
}

interface HistoryTableProps {
  onRowClick: (entry: ScanHistoryEntry) => void
}

export function HistoryTable({ onRowClick }: HistoryTableProps) {
  const { history, clearHistory } = useScanHistory()
  const [sortField, setSortField] = useState<SortField>('timestamp')
  const [sortDir, setSortDir] = useState<SortDir>('desc')

  function handleSort(field: SortField) {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDir(field === 'timestamp' ? 'desc' : 'asc')
    }
  }

  const sorted = [...history].sort((a, b) => {
    let cmp = 0
    if (sortField === 'filename')  cmp = a.filename.localeCompare(b.filename)
    if (sortField === 'timestamp') cmp = new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    if (sortField === 'total')     cmp = a.results.total_findings - b.results.total_findings
    if (sortField === 'critical')  cmp = (a.results.severity_counts?.CRITICAL ?? 0) - (b.results.severity_counts?.CRITICAL ?? 0)
    return sortDir === 'asc' ? cmp : -cmp
  })

  if (history.length === 0) {
    return (
      <EmptyState
        icon={Clock}
        title="No scan history"
        description="Completed scans will appear here. Run a scan from the Analysis Lab to get started."
        ctaLabel="Go to Analysis Lab"
        ctaHref="/analysis"
      />
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-[#64748B]">{history.length} scan(s) stored locally</span>
        <button
          onClick={clearHistory}
          className="flex items-center gap-1.5 text-[11px] text-[#475569] hover:text-red-400 transition-colors"
        >
          <Trash2 className="w-3 h-3" />
          Clear all
        </button>
      </div>

      <div className="rounded border border-[#334155] overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="bg-[#0F172A] border-b border-[#334155] hover:bg-[#0F172A]">
              <TableHead className="w-8 text-[#475569] text-[10px]">#</TableHead>
              <TableHead>
                <HistorySortButton
                  field="filename"
                  label="File"
                  active={sortField === 'filename'}
                  sortDir={sortDir}
                  onSort={handleSort}
                />
              </TableHead>
              <TableHead>
                <HistorySortButton
                  field="timestamp"
                  label="Date"
                  active={sortField === 'timestamp'}
                  sortDir={sortDir}
                  onSort={handleSort}
                />
              </TableHead>
              <TableHead>
                <HistorySortButton
                  field="total"
                  label="Total"
                  active={sortField === 'total'}
                  sortDir={sortDir}
                  onSort={handleSort}
                />
              </TableHead>
              <TableHead>
                <HistorySortButton
                  field="critical"
                  label="Critical"
                  active={sortField === 'critical'}
                  sortDir={sortDir}
                  onSort={handleSort}
                />
              </TableHead>
              <TableHead className="text-[10px] uppercase tracking-wider text-[#64748B]">Severity Split</TableHead>
              <TableHead className="text-[10px] uppercase tracking-wider text-[#64748B]">Duration</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {sorted.map((entry, i) => {
              const sc = entry.results.severity_counts ?? {}
              const durationSec = (entry.results.scan_duration_ms / 1000).toFixed(1)

              return (
                <TableRow
                  key={`${entry.filename}-${entry.timestamp}`}
                  className="border-b border-[#1E293B] cursor-pointer hover:bg-[#0F172A] transition-colors"
                  onClick={() => onRowClick(entry)}
                >
                  <TableCell className="text-center text-[11px] text-[#475569] font-mono">{i + 1}</TableCell>

                  <TableCell>
                    <p className="text-xs text-white font-medium truncate max-w-[180px]">{entry.filename}</p>
                    <p className="text-[10px] text-[#475569] font-mono mt-0.5">{entry.results.scan_id.slice(0, 12)}…</p>
                  </TableCell>

                  <TableCell>
                    <p className="text-xs text-[#94A3B8]">
                      {new Date(entry.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}
                    </p>
                    <p className="text-[10px] text-[#475569]">
                      {new Date(entry.timestamp).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}
                    </p>
                  </TableCell>

                  <TableCell>
                    <span className="text-sm font-mono font-semibold text-white">
                      {entry.results.total_findings}
                    </span>
                  </TableCell>

                  <TableCell>
                    <span className={cn(
                      'text-sm font-mono font-semibold',
                      (sc.CRITICAL ?? 0) > 0 ? 'text-red-400' : 'text-[#475569]'
                    )}>
                      {sc.CRITICAL ?? 0}
                    </span>
                  </TableCell>

                  <TableCell>
                    <div className="flex items-center gap-1.5">
                      {SEVERITY_ORDER.map((sev) => {
                        const count = sc[sev] ?? 0
                        if (count === 0) return null
                        return <SeverityBadge key={sev} severity={sev} size="sm" />
                      })}
                      {SEVERITY_ORDER.every((s) => !sc[s]) && (
                        <span className="text-[11px] text-emerald-400">Clean ✓</span>
                      )}
                    </div>
                  </TableCell>

                  <TableCell>
                    <span className="text-[11px] text-[#64748B] font-mono">{durationSec}s</span>
                  </TableCell>
                </TableRow>
              )
            })}
          </TableBody>
        </Table>
      </div>
    </div>
  )
}
