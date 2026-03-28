'use client'

import { useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import type { ScanHistoryEntry, ScanResults } from '@/lib/types'

const STORAGE_KEY = 'nazca-scan-history'
const QUERY_KEY = ['scan-history']

function loadHistory(): ScanHistoryEntry[] {
  if (typeof window === 'undefined') return []
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    return raw ? (JSON.parse(raw) as ScanHistoryEntry[]) : []
  } catch {
    return []
  }
}

function saveHistory(entries: ScanHistoryEntry[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(entries))
}

/** Prepend entry; drop any existing row with the same scan_id (idempotent). */
function prependDeduped(entry: ScanHistoryEntry, maxEntries: number): ScanHistoryEntry[] {
  const sid = entry.results.scan_id
  const prev = loadHistory()
  const rest = sid ? prev.filter((e) => e.results.scan_id !== sid) : prev
  return [entry, ...rest].slice(0, maxEntries)
}

export function useScanHistory() {
  const qc = useQueryClient()

  const { data: history = [] } = useQuery<ScanHistoryEntry[]>({
    queryKey: QUERY_KEY,
    queryFn: loadHistory,
    staleTime: Infinity,
  })

  const addEntry = useCallback(
    (filename: string, results: ScanResults) => {
      const entry: ScanHistoryEntry = {
        filename,
        timestamp: new Date().toISOString(),
        results,
      }
      const updated = prependDeduped(entry, 50)
      saveHistory(updated)
      qc.setQueryData<ScanHistoryEntry[]>(QUERY_KEY, updated)
    },
    [qc]
  )

  const clearHistory = useCallback(() => {
    saveHistory([])
    qc.setQueryData<ScanHistoryEntry[]>(QUERY_KEY, [])
  }, [qc])

  return { history, addEntry, clearHistory }
}

export { QUERY_KEY as SCAN_HISTORY_QUERY_KEY }

// Mutation version for imperative usage
export function useAddScanEntry() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: async ({ filename, results }: { filename: string; results: ScanResults }) => {
      const entry: ScanHistoryEntry = {
        filename,
        timestamp: new Date().toISOString(),
        results,
      }
      const updated = prependDeduped(entry, 50)
      saveHistory(updated)
      return updated
    },
    onSuccess: (updated) => {
      qc.setQueryData<ScanHistoryEntry[]>(QUERY_KEY, updated)
    },
  })
}
