'use client'

import { useState } from 'react'
import { Shield, Play, CheckCircle2, AlertCircle, Loader2, ChevronRight } from 'lucide-react'
import { toast } from 'sonner'
import { AppShell } from '@/components/layout/AppShell'
import { PageTransition } from '@/components/layout/PageTransition'
import { MultiFileUploadZone } from '@/components/analysis/MultiFileUploadZone'
import { SandboxConsole } from '@/components/sandbox/SandboxConsole'
import { ExecutionLogTab } from '@/components/sandbox/ExecutionLogTab'
import { AttackGraphTab } from '@/components/sandbox/AttackGraphTab'
import { BlastRadiusTab } from '@/components/sandbox/BlastRadiusTab'
import { ConfidenceTab } from '@/components/sandbox/ConfidenceTab'
import { MapAnalysisTab } from '@/components/sandbox/MapAnalysisTab'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Button } from '@/components/ui/button'
import { EmptyState } from '@/components/ui/empty-state'
import { useSandboxJob } from '@/hooks/useSandboxJob'
import { useConfigStore } from '@/store/configStore'
import { cn } from '@/lib/utils'

/* ─── Pipeline stepper ──────────────────────────────────────────────────── */
const PIPELINE_LABELS = ['Setup', 'Detection', 'Analysis', 'Remediation', 'Re-verify']

function PipelineStepper({ step, running }: { step: number; running: boolean }) {
  return (
    <div className="flex items-center gap-1">
      {PIPELINE_LABELS.map((label, i) => {
        const done    = i < step
        const active  = i === step && running
        const pending = i > step

        return (
          <div key={label} className="flex items-center gap-1">
            <div
              className={cn(
                'flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium transition-all',
                done    && 'bg-emerald-900/30 border border-emerald-700 text-emerald-400',
                active  && 'bg-indigo-900/40 border border-indigo-500 text-indigo-300',
                pending && 'bg-[#0F172A] border border-[#1E293B] text-[#334155]'
              )}
            >
              {done ? (
                <CheckCircle2 className="w-3 h-3" />
              ) : active ? (
                <Loader2 className="w-3 h-3 animate-spin" />
              ) : (
                <span className="w-3 h-3 rounded-full border border-current inline-flex items-center justify-center text-[8px]">{i + 1}</span>
              )}
              {label}
            </div>
            {i < PIPELINE_LABELS.length - 1 && (
              <ChevronRight className={cn('w-3 h-3 shrink-0', done ? 'text-emerald-700' : 'text-[#1E293B]')} />
            )}
          </div>
        )
      })}
    </div>
  )
}

/* ─── Main client ────────────────────────────────────────────────────────── */
export function SandboxClient() {
  const [files, setFiles] = useState<File[]>([])
  const { state, startSandbox, reset } = useSandboxJob()
  const config = useConfigStore()

  const isRunning = state.phase === 'uploading' || state.phase === 'streaming'
  const isDone    = state.phase === 'complete'
  const isError   = state.phase === 'error'

  async function handleLaunch() {
    if (!files.length) return
    try {
      await startSandbox(files, {
        useLLM: config.useLLM,
        llmProvider: config.llmProvider,
        useSnowflake: config.useSnowflake,
        reportFormats: config.reportFormats,
      })
    } catch {
      // errors handled inside hook
    }
  }

  // Toast on completion / error
  if (isDone && !state.error) {
    const totalBefore = Object.values(state.results?.files ?? {}).reduce((s, f) => s + f.findings_before.length, 0)
    const totalAfter  = Object.values(state.results?.files ?? {}).reduce((s, f) => s + f.findings_after.length, 0)
    if (state.results && !state.results.log_lines?.includes('__toasted__')) {
      // Deduplicate toasts — only fire once per result set
      if (state.results.total_fixes >= 0) {
        toast.success('Sandbox complete', {
          description: `${totalBefore - totalAfter} finding(s) remediated across ${Object.keys(state.results.files).length} file(s)`,
        })
      }
    }
  }
  if (isError && state.error) {
    toast.error('Sandbox failed', { description: state.error })
  }

  return (
    <AppShell>
      <PageTransition>
      <div className="px-6 py-8 min-h-full space-y-6">
        {/* Header */}
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Shield className="w-5 h-5 text-indigo-400" />
            <h1 className="text-xl font-semibold text-white">Sandbox Verification Lab</h1>
          </div>
          <p className="text-sm text-[#94A3B8] ml-8">Multi-file deep analysis — AST/taint tracking, automated remediation, and re-verification</p>
        </div>

        {/* File upload */}
        {!isDone && (
          <MultiFileUploadZone
            onFilesChanged={setFiles}
            selectedFiles={files}
            disabled={isRunning}
          />
        )}

        {/* Launch button */}
        {files.length > 0 && state.phase === 'idle' && (
          <div className="flex justify-center">
            <Button
              onClick={handleLaunch}
              className="bg-indigo-600 hover:bg-indigo-500 text-white uppercase text-xs tracking-wider font-semibold h-11 px-10 w-full max-w-md"
            >
              <Play className="w-4 h-4 mr-2" />
              Launch Sandbox Verification
            </Button>
          </div>
        )}

        {/* Pipeline stepper (shown while running or done) */}
        {(isRunning || isDone) && (
          <PipelineStepper step={state.pipelineStep} running={isRunning} />
        )}

        {/* Live console (while running) */}
        {isRunning && (
          <SandboxConsole lines={state.logLines} height="280px" />
        )}

        {/* Error state */}
        {isError && (
          <div className="space-y-3">
            <SandboxConsole lines={state.logLines} height="200px" />
            <div className="flex items-center gap-3 p-4 rounded border border-red-800 bg-red-900/10">
              <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />
              <p className="text-sm text-red-400 flex-1">{state.error}</p>
              <Button variant="outline" onClick={reset} className="border-[#334155] text-[#94A3B8] h-8 text-xs">
                Reset
              </Button>
            </div>
          </div>
        )}

        {/* Results — 5 tabs */}
        {isDone && state.results && (
          <div className="space-y-4">
            <Tabs defaultValue="log">
              <TabsList className="bg-[#0F172A] border border-[#334155] p-1 h-auto gap-0.5">
                {[
                  { value: 'log',        label: 'Execution Log' },
                  { value: 'attack',     label: 'Attack-Path Graph' },
                  { value: 'blast',      label: 'Blast Radius' },
                  { value: 'confidence', label: 'Confidence' },
                  { value: 'map',        label: 'Map Analysis' },
                ].map(({ value, label }) => (
                  <TabsTrigger
                    key={value}
                    value={value}
                    className="text-xs px-3 py-1.5 data-[state=active]:bg-indigo-600 data-[state=active]:text-white text-[#64748B] hover:text-[#94A3B8] rounded-[3px] transition-colors"
                  >
                    {label}
                  </TabsTrigger>
                ))}
              </TabsList>

              <TabsContent value="log" className="mt-4">
                <ExecutionLogTab logLines={state.logLines} results={state.results} />
              </TabsContent>
              <TabsContent value="attack" className="mt-4">
                <AttackGraphTab results={state.results} />
              </TabsContent>
              <TabsContent value="blast" className="mt-4">
                <BlastRadiusTab results={state.results} />
              </TabsContent>
              <TabsContent value="confidence" className="mt-4">
                <ConfidenceTab results={state.results} />
              </TabsContent>
              <TabsContent value="map" className="mt-4">
                <MapAnalysisTab results={state.results} />
              </TabsContent>
            </Tabs>

            <Button
              variant="outline"
              onClick={reset}
              className="border-[#334155] text-[#94A3B8] hover:border-[#475569] h-9 text-xs"
            >
              Scan New Files
            </Button>
          </div>
        )}

        {/* Initial empty state */}
        {files.length === 0 && state.phase === 'idle' && (
          <EmptyState
            icon={Shield}
            title="Upload files to begin"
            description="Add one or more code files above. The sandbox will run a 5-phase pipeline: setup, detection, AST/taint analysis, remediation, and re-verification."
          />
        )}
      </div>
      </PageTransition>
    </AppShell>
  )
}
