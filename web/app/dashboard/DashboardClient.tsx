'use client'

import { useMemo } from 'react'
import { LayoutDashboard, AlertTriangle, AlertOctagon, FileCode2, ShieldCheck } from 'lucide-react'
import { AppShell } from '@/components/layout/AppShell'
import { PageTransition } from '@/components/layout/PageTransition'
import { MetricsGrid, type MetricDef } from '@/components/dashboard/MetricsGrid'
import { FindingsTrendChart } from '@/components/dashboard/FindingsTrendChart'
import { VulnTypesChart } from '@/components/dashboard/VulnTypesChart'
import { SeverityPieChart } from '@/components/dashboard/SeverityPieChart'
import { EmptyState } from '@/components/ui/empty-state'
import { useScanHistory } from '@/hooks/useScanHistory'
import type { ScanHistoryEntry } from '@/lib/types'

function computeSecurityRating(criticals: number, highs: number, total: number): string {
  if (total === 0) return 'N/A'
  if (criticals > 0) return 'F'
  if (highs > 5) return 'D'
  if (highs > 0) return 'C'
  if (total > 10) return 'B'
  return 'A'
}

function buildTrendData(history: ScanHistoryEntry[]) {
  return [...history].reverse().slice(-12).map((entry) => ({
    date: new Date(entry.timestamp).toLocaleDateString('en-US', { month: 'short', day: 'numeric' }),
    total:    entry.results.total_findings,
    critical: entry.results.severity_counts?.CRITICAL ?? 0,
    high:     entry.results.severity_counts?.HIGH ?? 0,
  }))
}

function buildVulnTypeData(history: ScanHistoryEntry[]) {
  const counts: Record<string, number> = {}
  for (const entry of history) {
    for (const finding of entry.results.findings) {
      counts[finding.vulnerability_type] = (counts[finding.vulnerability_type] ?? 0) + 1
    }
  }
  return Object.entries(counts)
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count)
}

export function DashboardClient() {
  const { history } = useScanHistory()

  const aggregate = useMemo(() => {
    const totalFindings = history.reduce((s, e) => s + e.results.total_findings, 0)
    const criticals = history.reduce((s, e) => s + (e.results.severity_counts?.CRITICAL ?? 0), 0)
    const highs     = history.reduce((s, e) => s + (e.results.severity_counts?.HIGH ?? 0), 0)
    const filesScanned = history.length
    const rating = computeSecurityRating(criticals, highs, totalFindings)

    const allSeverityCounts = {
      CRITICAL: criticals,
      HIGH:     highs,
      MEDIUM:   history.reduce((s, e) => s + (e.results.severity_counts?.MEDIUM ?? 0), 0),
      LOW:      history.reduce((s, e) => s + (e.results.severity_counts?.LOW ?? 0), 0),
    }

    return { totalFindings, criticals, highs, filesScanned, rating, allSeverityCounts }
  }, [history])

  const metrics: MetricDef[] = [
    { title: 'Total Findings',  value: aggregate.totalFindings, icon: AlertTriangle,  color: '#6366F1', subtext: 'across all scans' },
    { title: 'Critical Issues', value: aggregate.criticals,     icon: AlertOctagon,   color: '#DC2626', subtext: 'require immediate action' },
    { title: 'High Severity',   value: aggregate.highs,         icon: AlertTriangle,  color: '#EA580C', subtext: 'high priority fixes' },
    { title: 'Files Scanned',   value: aggregate.filesScanned,  icon: FileCode2,      color: '#10B981', subtext: 'total scans run' },
    { title: 'Security Rating', value: aggregate.rating,        icon: ShieldCheck,    color: '#4338CA', subtext: 'overall posture' },
  ]

  const trendData    = useMemo(() => buildTrendData(history),    [history])
  const vulnTypeData = useMemo(() => buildVulnTypeData(history), [history])

  return (
    <AppShell>
      <PageTransition>
      <div className="px-6 py-8 min-h-full">
        {/* Page header */}
        <div className="mb-6">
          <div className="flex items-center gap-3 mb-1">
            <LayoutDashboard className="w-5 h-5 text-indigo-400" />
            <h1 className="text-xl font-semibold text-white">Security Dashboard</h1>
          </div>
          <p className="text-sm text-[#94A3B8] ml-8">Aggregated metrics across all scans</p>
        </div>

        {history.length === 0 ? (
          <EmptyState
            icon={ShieldCheck}
            title="No scans yet"
            description="Run your first security scan to see metrics, trends, and vulnerability breakdowns here."
            ctaLabel="Go to Analysis Lab"
            ctaHref="/analysis"
          />
        ) : (
          <div className="space-y-6">
            {/* Metrics row */}
            <MetricsGrid metrics={metrics} />

            {/* Charts section */}
            <div>
              <p className="section-label mb-3">Security Insights</p>
              <div className="grid grid-cols-3 gap-4">
                <FindingsTrendChart data={trendData} />
                <VulnTypesChart data={vulnTypeData} />
                <SeverityPieChart counts={aggregate.allSeverityCounts} />
              </div>
            </div>
          </div>
        )}
      </div>
      </PageTransition>
    </AppShell>
  )
}
