'use client'

import { useCallback, useEffect, useRef, useState } from 'react'
import type { ScanEvent, ScanResults } from '@/lib/types'

export type ScanPhase = 'idle' | 'uploading' | 'streaming' | 'complete' | 'error'

export interface ScanState {
  phase: ScanPhase
  jobId: string | null
  pct: number
  message: string
  results: ScanResults | null
  error: string | null
}

const INITIAL_STATE: ScanState = {
  phase: 'idle',
  jobId: null,
  pct: 0,
  message: '',
  results: null,
  error: null,
}

/**
 * Manages a single scan job lifecycle:
 *   1. POST /api/scans → get jobId
 *   2. Open SSE stream at /api/scans/[jobId]/stream
 *   3. Parse ScanEvents and surface progress + results
 */
export function useScanJob() {
  const [state, setState] = useState<ScanState>(INITIAL_STATE)
  const esRef = useRef<EventSource | null>(null)

  function patch(updates: Partial<ScanState>) {
    setState((prev) => ({ ...prev, ...updates }))
  }

  const closeStream = useCallback(() => {
    if (esRef.current) {
      esRef.current.close()
      esRef.current = null
    }
  }, [])

  useEffect(() => () => closeStream(), [closeStream])

  const startScan = useCallback(
    async (file: File, config: object): Promise<void> => {
      closeStream()
      setState({ ...INITIAL_STATE, phase: 'uploading', message: 'Uploading file…' })

      try {
        const form = new FormData()
        form.append('file', file)
        form.append('config', JSON.stringify(config))

        const res = await fetch('/api/scans', { method: 'POST', body: form })
        if (!res.ok) {
          const body = await res.json() as { error?: string }
          throw new Error(body.error ?? `Upload failed (${res.status})`)
        }

        const { jobId } = (await res.json()) as { jobId: string }
        patch({ phase: 'streaming', jobId, message: 'Starting scan…', pct: 0 })

        // Open SSE stream
        const es = new EventSource(`/api/scans/${encodeURIComponent(jobId)}/stream`)
        esRef.current = es

        es.onmessage = (ev) => {
          try {
            const event = JSON.parse(ev.data as string) as ScanEvent
            if (event.type === 'progress') {
              patch({ pct: event.pct, message: event.message })
            } else if (event.type === 'complete') {
              closeStream()
              setState((prev) => ({
                ...prev,
                phase: 'complete',
                pct: 100,
                message: 'Scan complete',
                results: event.results,
              }))
            } else if (event.type === 'error') {
              closeStream()
              patch({ phase: 'error', error: event.message })
            }
          } catch {
            // ignore malformed frames
          }
        }

        es.onerror = () => {
          closeStream()
          // If we already have results, ignore the stream close error
          setState((prev) => {
            if (prev.phase === 'complete') return prev
            return { ...prev, phase: 'error', error: 'Lost connection to scan stream' }
          })
        }
      } catch (err) {
        const message = err instanceof Error ? err.message : 'Unknown error'
        patch({ phase: 'error', error: message })
      }
    },
    [closeStream]
  )

  const reset = useCallback(() => {
    closeStream()
    setState(INITIAL_STATE)
  }, [closeStream])

  return { state, startScan, reset }
}
