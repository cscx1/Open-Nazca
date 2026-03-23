'use client'

import { Download, FileJson, FileCode2, FileText } from 'lucide-react'
import type { ReportFormat } from '@/lib/types'
import { getReportUrl } from '@/lib/api'
import { cn } from '@/lib/utils'

const FORMAT_META: Record<ReportFormat, { label: string; icon: React.ComponentType<{ className?: string }>; color: string }> = {
  json:     { label: 'JSON',     icon: FileJson,  color: '#10B981' },
  html:     { label: 'HTML',     icon: FileCode2, color: '#3B82F6' },
  markdown: { label: 'Markdown', icon: FileText,  color: '#A855F7' },
}

interface DownloadReportsProps {
  scanId: string
  availableFormats: ReportFormat[]
  className?: string
}

export function DownloadReports({ scanId, availableFormats, className }: DownloadReportsProps) {
  if (!availableFormats.length) return null

  return (
    <div className={cn('flex flex-wrap gap-2', className)}>
      {availableFormats.map((fmt) => {
        const meta = FORMAT_META[fmt]
        const Icon = meta.icon
        return (
          <a
            key={fmt}
            href={getReportUrl(scanId, fmt)}
            download
            className="flex items-center gap-2 px-3 py-2 rounded border border-[#334155] bg-[#1E293B] text-[#B0B8C1] hover:border-[#475569] hover:text-white transition-colors text-xs font-medium"
          >
            <span style={{ color: meta.color }}>
              <Icon className="w-3.5 h-3.5" />
            </span>
            Download {meta.label}
            <Download className="w-3 h-3 text-[#475569]" />
          </a>
        )
      })}
    </div>
  )
}
