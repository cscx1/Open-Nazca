'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import type { SandboxResults } from '@/lib/types'
import { type LogLine, parseLogLevel } from '@/components/sandbox/SandboxConsole'

export type SandboxPhase = 'idle' | 'uploading' | 'streaming' | 'complete' | 'error'

export interface SandboxState {
  phase: SandboxPhase
  jobId: string | null
  logLines: LogLine[]
  pipelineStep: number        // 0-4 for the 5 phases
  results: SandboxResults | null
  error: string | null
}

type SandboxEvent =
  | { type: 'log';      message: string; level?: string }
  | { type: 'step';     step: number; label: string }
  | { type: 'complete'; results: SandboxResults }
  | { type: 'error';    message: string }

const PIPELINE_STEPS = ['Setup', 'Detection', 'Analysis', 'Remediation', 'Re-verify']

const INITIAL_STATE: SandboxState = {
  phase: 'idle',
  jobId: null,
  logLines: [],
  pipelineStep: 0,
  results: null,
  error: null,
}

function nowTs(): string {
  return new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function useSandboxJob() {
  const [state, setState] = useState<SandboxState>(INITIAL_STATE)
  const esRef = useRef<EventSource | null>(null)

  function patch(updates: Partial<SandboxState>) {
    setState((prev) => ({ ...prev, ...updates }))
  }

  function appendLog(text: string, levelHint?: string) {
    const level = levelHint
      ? (levelHint as LogLine['level'])
      : parseLogLevel(text)
    const line: LogLine = { ts: nowTs(), level, text }
    setState((prev) => ({ ...prev, logLines: [...prev.logLines, line] }))
  }

  const closeStream = useCallback(() => {
    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }
  }, [])

  useEffect(() => () => closeStream(), [closeStream])

  const startSandbox = useCallback(
    async (files: File[], config: object): Promise<void> => {
      closeStream()
      setState({
        ...INITIAL_STATE,
        phase: 'uploading',
        logLines: [{ ts: nowTs(), level: 'info', text: `Uploading ${files.length} file(s)…` }],
      })

      try {
        const form = new FormData()
        files.forEach((f) => form.append('files', f))
        form.append('config', JSON.stringify(config))

        const res = await fetch('/api/sandbox', { method: 'POST', body: form })
        if (!res.ok) {
          const body = await res.json() as { error?: string }
          throw new Error(body.error ?? `Upload failed (${res.status})`)
        }

        const { jobId } = (await res.json()) as { jobId: string }
        patch({ phase: 'streaming', jobId })
        appendLog('=== Sandbox pipeline started ===', 'phase')
        appendLog(`Job ID: ${jobId}`, 'dim')

        const es = new EventSource(`/api/sandbox/${encodeURIComponent(jobId)}/stream`)
        esRef.current = es

        es.onmessage = (ev) => {
          try {
            const event = JSON.parse(ev.data as string) as SandboxEvent
            if (event.type === 'log') {
              appendLog(event.message, event.level)
            } else if (event.type === 'step') {
              patch({ pipelineStep: event.step })
              appendLog(`=== ${PIPELINE_STEPS[event.step] ?? event.label} ===`, 'phase')
            } else if (event.type === 'complete') {
              closeStream()
              appendLog('=== Pipeline complete ===', 'ok')
              setState((prev) => ({
                ...prev,
                phase: 'complete',
                results: event.results,
                pipelineStep: PIPELINE_STEPS.length - 1,
              }))
            } else if (event.type === 'error') {
              closeStream()
              appendLog(`✗ ${event.message}`, 'fail')
              patch({ phase: 'error', error: event.message })
            }
          } catch {
            // ignore malformed frames
          }
        }

        es.onerror = () => {
          closeStream()
          setState((prev) => {
            if (prev.phase === 'complete') return prev
            return { ...prev, phase: 'error', error: 'Lost connection to sandbox stream' }
          })
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error'
        appendLog(`✗ ${message}`, 'fail')
        patch({ phase: 'error', error: message })
      }
    },
    [closeStream]
  )

  const reset = useCallback(() => {
    closeStream()
    setState(INITIAL_STATE)
  }, [closeStream])

  return { state, startSandbox, reset, PIPELINE_STEPS }
}
