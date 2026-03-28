'use client'

import { useEffect, useMemo, useRef, useState } from 'react'
import { FlaskConical, ShieldOff, Scan, Timer, AlertOctagon } from 'lucide-react'
import { toast } from 'sonner'
import { motion } from 'framer-motion'
import { AppShell } from '@/components/layout/AppShell'
import { PageTransition } from '@/components/layout/PageTransition'
import { MetricsGrid, type MetricDef } from '@/components/dashboard/MetricsGrid'
import { FileUploadZone } from '@/components/analysis/FileUploadZone'
import { LanguageBadges } from '@/components/analysis/LanguageBadges'
import { ScanProgress } from '@/components/analysis/ScanProgress'
import { SeverityFilterChips } from '@/components/analysis/SeverityFilterChips'
import { FindingsTable } from '@/components/analysis/FindingsTable'
import { FindingCard } from '@/components/analysis/FindingCard'
import { DownloadReports } from '@/components/analysis/DownloadReports'
import { EmptyState } from '@/components/ui/empty-state'
import { Button } from '@/components/ui/button'
import { useScanJob } from '@/hooks/useScanJob'
import { useAddScanEntry } from '@/hooks/useScanHistory'
import { useConfigStore } from '@/store/configStore'
import type { Severity, ReportFormat } from '@/lib/types'

export function AnalysisClient() {
  const [file, setFile] = useState<File | null>(null)
  const [activeFilters, setActiveFilters] = useState<Severity[]>(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'])
  const [viewMode, setViewMode] = useState<'table' | 'cards'>('table')

  const { state, startScan, reset } = useScanJob()
  const addEntry = useAddScanEntry()
  const config = useConfigStore()
  const lastRecordedScanIdRef = useRef<string | null>(null)
  const lastErrorToastRef = useRef<string | null>(null)

  const isScanning = state.phase === 'uploading' || state.phase === 'streaming'

  async function handleLaunch() {
    if (!file) return
    await startScan(file, {
      useLLM: config.useLLM,
      llmProvider: config.llmProvider,
      useSnowflake: config.useSnowflake,
      reportFormats: config.reportFormats,
    })
  }

  const results = state.results

  useEffect(() => {
    if (state.phase === 'idle') {
      lastErrorToastRef.current = null
      lastRecordedScanIdRef.current = null
      return
    }
    if (state.phase === 'complete' && results && file) {
      const sid = results.scan_id
      if (sid && lastRecordedScanIdRef.current === sid) return
      if (sid) lastRecordedScanIdRef.current = sid
      addEntry.mutate({ filename: file.name, results })
      toast.success('Scan complete', { description: `${results.total_findings} finding(s) found` })
      return
    }
    if (state.phase === 'error' && state.error) {
      if (lastErrorToastRef.current === state.error) return
      lastErrorToastRef.current = state.error
      toast.error('Scan failed', { description: state.error })
    }
  }, [state.phase, state.error, results, file, addEntry])

  const filteredFindings = useMemo(
    () => (results?.findings ?? []).filter((f) => activeFilters.includes(f.severity)),
    [results, activeFilters]
  )

  const metrics: MetricDef[] = results
    ? [
        {
          title: 'Total Findings',
          value: results.total_findings,
          icon: ShieldOff,
          color: '#6366F1',
          subtext: 'vulnerabilities detected',
        },
        {
          title: 'Critical Issues',
          value: results.severity_counts?.CRITICAL ?? 0,
          icon: AlertOctagon,
          color: '#DC2626',
          subtext: 'require immediate action',
        },
        {
          title: 'Scan Duration',
          value: `${(results.scan_duration_ms / 1000).toFixed(1)}s`,
          icon: Timer,
          color: '#10B981',
          subtext: `scan ID: ${results.scan_id.slice(0, 8)}`,
        },
      ]
    : []

  const availableFormats = results?.report_paths
    ? (Object.keys(results.report_paths) as ReportFormat[])
    : []

  return (
    <AppShell>
      <PageTransition>
      <div className="px-6 py-8 min-h-full space-y-6">
        {/* Page header */}
        <div>
          <div className="flex items-center gap-3 mb-1">
            <FlaskConical className="w-5 h-5 text-indigo-400" />
            <h1 className="text-xl font-semibold text-white">Security Analysis Lab</h1>
          </div>
          <p className="text-sm text-[#94A3B8] ml-8">Upload a code file for AI-powered vulnerability scanning</p>
        </div>

        {/* Upload zone */}
        <div className="space-y-3">
          <FileUploadZone
            onFileSelected={(f) => { setFile(f); if (!f) reset() }}
            selectedFile={file}
            disabled={isScanning}
          />
          <LanguageBadges />
        </div>

        {/* Launch button */}
        {file && state.phase === 'idle' && (
          <div className="flex justify-center">
            <Button
              onClick={handleLaunch}
              className="bg-indigo-600 hover:bg-indigo-500 text-white uppercase text-xs tracking-wider font-semibold h-11 px-10 w-full max-w-md"
            >
              <Scan className="w-4 h-4 mr-2" />
              Launch Security Scan
            </Button>
          </div>
        )}

        {/* Live progress */}
        {isScanning && (
          <ScanProgress
            pct={state.pct}
            message={state.message}
            phase={state.phase === 'uploading' ? 'Uploading' : 'Scanning'}
          />
        )}

        {/* Error state */}
        {state.phase === 'error' && (
          <div className="flex flex-col items-center gap-4 py-8">
            <p className="text-sm text-red-400">Scan failed. Check that the Python backend is running.</p>
            <Button
              variant="outline"
              onClick={reset}
              className="border-[#334155] text-[#94A3B8] hover:border-[#475569] h-9"
            >
              Try Again
            </Button>
          </div>
        )}

        {/* Results */}
        {state.phase === 'complete' && results && (
          <div className="space-y-5">
            {/* Metrics — stagger in first */}
            <MetricsGrid metrics={metrics} />

            {/* Download reports */}
            {availableFormats.length > 0 && (
              <div className="space-y-2">
                <p className="section-label">Download Reports</p>
                <DownloadReports scanId={results.scan_id} availableFormats={availableFormats} />
              </div>
            )}

            {/* Findings section — fades in 150ms after metrics */}
            {results.total_findings > 0 ? (
              <motion.div
                className="space-y-3"
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ delay: 0.15, duration: 0.3 }}
              >
                <div className="flex items-center justify-between">
                  <p className="section-label">
                    Findings
                    <span className="ml-2 font-mono normal-case text-white">{filteredFindings.length}</span>
                    <span className="text-[#475569]"> / {results.total_findings}</span>
                  </p>
                  <div className="flex items-center gap-2">
                    {/* View mode toggle */}
                    <div className="flex rounded border border-[#334155] overflow-hidden text-[11px]">
                      {(['table', 'cards'] as const).map((mode) => (
                        <button
                          key={mode}
                          onClick={() => setViewMode(mode)}
                          className={`px-3 py-1 capitalize transition-colors ${viewMode === mode ? 'bg-indigo-600 text-white' : 'text-[#64748B] hover:text-[#94A3B8]'}`}
                        >
                          {mode}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Filter chips */}
                <SeverityFilterChips
                  active={activeFilters}
                  onChange={setActiveFilters}
                  counts={results.severity_counts}
                />

                {/* Findings view */}
                {viewMode === 'table' ? (
                  <FindingsTable findings={filteredFindings} />
                ) : (
                  <div className="space-y-2">
                    {filteredFindings.map((f, i) => (
                      <FindingCard key={i} finding={f} index={i} />
                    ))}
                  </div>
                )}
              </motion.div>
            ) : (
              <EmptyState
                icon={ShieldOff}
                title="No vulnerabilities found"
                description="The scanner found no issues in this file. Consider scanning more files."
                ctaLabel="Scan Another File"
                onCtaClick={reset}
              />
            )}

            {/* Re-scan button */}
            <div className="pt-2">
              <Button
                variant="outline"
                onClick={reset}
                className="border-[#334155] text-[#94A3B8] hover:border-[#475569] h-9 text-xs"
              >
                Scan Another File
              </Button>
            </div>
          </div>
        )}

        {/* Initial empty state (no file selected yet) */}
        {!file && state.phase === 'idle' && (
          <EmptyState
            icon={FlaskConical}
            title="Ready to scan"
            description="Upload a code file above to start the AI-powered security analysis."
          />
        )}
      </div>
      </PageTransition>
    </AppShell>
  )
}
