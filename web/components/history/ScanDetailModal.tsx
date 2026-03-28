'use client'

import { useState } from 'react'
import { X, Clock, FileCode2, ShieldOff, AlertOctagon, Timer } from 'lucide-react'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription,
} from '@/components/ui/dialog'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { FindingsTable } from '@/components/analysis/FindingsTable'
import { SeverityFilterChips } from '@/components/analysis/SeverityFilterChips'
import { DownloadReports } from '@/components/analysis/DownloadReports'
import { Separator } from '@/components/ui/separator'
import type { ScanHistoryEntry, Severity, ReportFormat } from '@/lib/types'

interface ScanDetailModalProps {
  entry: ScanHistoryEntry | null
  open: boolean
  onClose: () => void
}

export function ScanDetailModal({ entry, open, onClose }: ScanDetailModalProps) {
  const [activeFilters, setActiveFilters] = useState<Severity[]>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])

  if (!entry) return null

  const { results, filename, timestamp } = entry
  const sc = results.severity_counts ?? {}

  const filteredFindings = results.findings.filter((f) => activeFilters.includes(f.severity))
  const availableFormats = results.report_paths
    ? (Object.keys(results.report_paths) as ReportFormat[])
    : []

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-5xl max-h-[90vh] overflow-y-auto bg-[#0F172A] border border-[#334155] p-0">
        {/* Header */}
        <DialogHeader className="px-6 py-5 border-b border-[#334155] sticky top-0 bg-[#0F172A] z-10">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <DialogTitle className="text-base font-semibold text-white flex items-center gap-2">
                <FileCode2 className="w-4 h-4 text-indigo-400 shrink-0" />
                <span className="truncate">{filename}</span>
              </DialogTitle>
              <DialogDescription className="flex items-center gap-3 mt-1.5 text-[11px] text-[#64748B]">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {new Date(timestamp).toLocaleString('en-US', {
                    month: 'short', day: 'numeric', year: 'numeric',
                    hour: '2-digit', minute: '2-digit',
                  })}
                </span>
                <span className="font-mono">{results.scan_id}</span>
              </DialogDescription>
            </div>
            <button
              onClick={onClose}
              className="shrink-0 flex items-center justify-center w-7 h-7 rounded border border-[#334155] text-[#64748B] hover:text-white hover:border-[#475569] transition-colors"
              aria-label="Close"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </DialogHeader>

        <div className="px-6 py-5 space-y-6">
          {/* Metric strip */}
          <div className="grid grid-cols-4 gap-3">
            {[
              { label: 'Total Findings', value: results.total_findings,    icon: ShieldOff,    color: '#6366F1' },
              { label: 'Critical',       value: sc.CRITICAL ?? 0,          icon: AlertOctagon, color: '#DC2626' },
              { label: 'High',           value: sc.HIGH ?? 0,              icon: AlertOctagon, color: '#EA580C' },
              { label: 'Duration',       value: `${(results.scan_duration_ms / 1000).toFixed(1)}s`, icon: Timer, color: '#10B981' },
            ].map(({ label, value, icon: Icon, color }) => (
              <div key={label} className="rounded border border-[#334155] bg-[#0B1120] px-4 py-3">
                <div className="flex items-center gap-2 mb-2">
                  <span style={{ color }}><Icon className="w-3.5 h-3.5" /></span>
                  <span className="section-label">{label}</span>
                </div>
                <p className="metric-value" style={{ color, fontSize: '1.25rem' }}>{value}</p>
              </div>
            ))}
          </div>

          {/* Severity breakdown */}
          <div className="flex flex-wrap gap-2">
            {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as Severity[]).map((sev) => {
              const count = sc[sev] ?? 0
              if (!count) return null
              return (
                <div key={sev} className="flex items-center gap-2 px-3 py-1.5 rounded border border-[#334155] bg-[#0B1120]">
                  <SeverityBadge severity={sev} size="sm" />
                  <span className="text-sm font-mono font-semibold text-white">{count}</span>
                </div>
              )
            })}
          </div>

          {/* Download reports */}
          {availableFormats.length > 0 && (
            <div className="space-y-2">
              <p className="section-label">Download Reports</p>
              <DownloadReports scanId={results.scan_id} availableFormats={availableFormats} />
            </div>
          )}

          <Separator className="bg-[#1E293B]" />

          {/* Findings */}
          {results.total_findings > 0 ? (
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="section-label">
                  Findings
                  <span className="ml-2 font-mono normal-case text-white">{filteredFindings.length}</span>
                  <span className="text-[#475569]"> / {results.total_findings}</span>
                </p>
              </div>
              <SeverityFilterChips
                active={activeFilters}
                onChange={setActiveFilters}
                counts={sc}
              />
              <FindingsTable findings={filteredFindings} />
            </div>
          ) : (
            <p className="py-8 text-center text-sm text-emerald-400">No vulnerabilities found in this scan ✓</p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  )
}
