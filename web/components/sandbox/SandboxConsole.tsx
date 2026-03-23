'use client'

import { useEffect, useRef } from 'react'
import { Terminal } from 'lucide-react'
import { cn } from '@/lib/utils'

export type LogLevel = 'phase' | 'ok' | 'fail' | 'warn' | 'info' | 'dim'

export interface LogLine {
  ts: string
  level: LogLevel
  text: string
}

const LEVEL_STYLES: Record<LogLevel, string> = {
  phase: 'text-indigo-400 font-bold',
  ok:    'text-emerald-400',
  fail:  'text-red-400',
  warn:  'text-amber-400',
  info:  'text-sky-400',
  dim:   'text-[#475569]',
}

const LEVEL_PREFIX: Record<LogLevel, string> = {
  phase: '●',
  ok:    '✓',
  fail:  '✗',
  warn:  '⚠',
  info:  '→',
  dim:   ' ',
}

export function parseLogLevel(raw: string): LogLevel {
  const lower = raw.toLowerCase()
  if (lower.includes('[phase]') || lower.startsWith('===') || lower.startsWith('---')) return 'phase'
  if (lower.includes('[ok]') || lower.includes('success') || lower.includes('fixed')) return 'ok'
  if (lower.includes('[fail]') || lower.includes('error') || lower.includes('failed')) return 'fail'
  if (lower.includes('[warn]') || lower.includes('warning')) return 'warn'
  if (lower.includes('[info]')) return 'info'
  return 'dim'
}

interface SandboxConsoleProps {
  lines: LogLine[]
  height?: string
  title?: string
}

export function SandboxConsole({ lines, height = '320px', title = 'Console Output' }: SandboxConsoleProps) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines.length])

  return (
    <div className="rounded border border-[#334155] overflow-hidden">
      {/* Header bar */}
      <div className="flex items-center gap-2 px-3 py-2 bg-[#0F172A] border-b border-[#334155]">
        <Terminal className="w-3.5 h-3.5 text-indigo-400" />
        <span className="text-[11px] text-[#64748B] uppercase tracking-wider">{title}</span>
        <span className="ml-auto text-[10px] font-mono text-[#475569]">{lines.length} lines</span>
      </div>

      {/* Log body */}
      <div
        className="overflow-y-auto font-mono text-[11px] leading-relaxed bg-[#020B14] p-3 space-y-px"
        style={{ height }}
      >
        {lines.length === 0 ? (
          <p className="text-[#334155]">Waiting for output…</p>
        ) : (
          lines.map((line, i) => (
            <div key={i} className="flex gap-2">
              <span className="text-[#334155] shrink-0 select-none w-16">{line.ts}</span>
              <span className={cn('shrink-0 w-3', LEVEL_STYLES[line.level])}>{LEVEL_PREFIX[line.level]}</span>
              <span className={cn('flex-1 whitespace-pre-wrap break-all', LEVEL_STYLES[line.level])}>
                {line.text}
              </span>
            </div>
          ))
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
