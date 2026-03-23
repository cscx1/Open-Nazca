'use client'

import { useState } from 'react'
import { Clock } from 'lucide-react'
import { AppShell } from '@/components/layout/AppShell'
import { PageTransition } from '@/components/layout/PageTransition'
import { HistoryTable } from '@/components/history/HistoryTable'
import { ScanDetailModal } from '@/components/history/ScanDetailModal'
import type { ScanHistoryEntry } from '@/lib/types'

export function HistoryClient() {
  const [selected, setSelected] = useState<ScanHistoryEntry | null>(null)

  return (
    <AppShell>
      <PageTransition>
      <div className="px-6 py-8 min-h-full space-y-6">
        {/* Header */}
        <div>
          <div className="flex items-center gap-3 mb-1">
            <Clock className="w-5 h-5 text-indigo-400" />
            <h1 className="text-xl font-semibold text-white">Scan History</h1>
          </div>
          <p className="text-sm text-[#94A3B8] ml-8">
            Review past scans, download reports, and revisit findings — persisted locally across sessions
          </p>
        </div>

        <HistoryTable onRowClick={(entry) => setSelected(entry)} />

        <ScanDetailModal
          entry={selected}
          open={!!selected}
          onClose={() => setSelected(null)}
        />
      </div>
      </PageTransition>
    </AppShell>
  )
}
