'use client'

import { Progress } from '@/components/ui/progress'
import { Loader2 } from 'lucide-react'

interface ScanProgressProps {
  pct: number
  message: string
  phase?: string
}

export function ScanProgress({ pct, message, phase }: ScanProgressProps) {
  return (
    <div className="p-4 rounded border border-indigo-500/30 bg-indigo-500/5 space-y-3">
      <div className="flex items-center gap-2">
        <Loader2 className="w-4 h-4 text-indigo-400 animate-spin shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between mb-0.5">
            {phase && (
              <span className="text-[10px] uppercase tracking-wider text-indigo-400 font-semibold">{phase}</span>
            )}
            <span className="text-[11px] font-mono text-white ml-auto">{pct}%</span>
          </div>
          <p className="text-xs text-[#94A3B8] truncate">{message}</p>
        </div>
      </div>
      <Progress
        value={pct}
        className="h-1.5 bg-[#1E293B] [&>div]:bg-indigo-500 [&>div]:transition-all"
      />
    </div>
  )
}
