'use client'

import { useConfigStore } from '@/store/configStore'
import { Switch } from '@/components/ui/switch'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import type { LLMProvider, ReportFormat } from '@/lib/types'

const LLM_PROVIDERS: { value: LLMProvider; label: string }[] = [
  { value: 'snowflake_cortex', label: 'Snowflake Cortex' },
  { value: 'openai', label: 'OpenAI' },
  { value: 'anthropic', label: 'Anthropic' },
]

const REPORT_FORMATS: { value: ReportFormat; label: string }[] = [
  { value: 'json', label: 'JSON' },
  { value: 'html', label: 'HTML' },
  { value: 'markdown', label: 'Markdown' },
]

export function SidebarConfig() {
  const { useLLM, llmProvider, useSnowflake, reportFormats, setUseLLM, setLLMProvider, setUseSnowflake, setReportFormats } =
    useConfigStore()

  function toggleFormat(fmt: ReportFormat) {
    if (reportFormats.includes(fmt)) {
      setReportFormats(reportFormats.filter((f) => f !== fmt))
    } else {
      setReportFormats([...reportFormats, fmt])
    }
  }

  return (
    <div className="px-3 py-4 space-y-4">
      <p className="section-label px-1">Configuration</p>

      {/* AI Analysis toggle */}
      <div className="space-y-2">
        <div className="flex items-center justify-between">
          <span className="text-xs text-[#94A3B8]">AI Analysis</span>
          <Switch
            checked={useLLM}
            onCheckedChange={setUseLLM}
            className="data-[state=checked]:bg-indigo-600"
          />
        </div>

        {useLLM && (
          <Select value={llmProvider} onValueChange={(v) => setLLMProvider(v as LLMProvider)}>
            <SelectTrigger className="h-8 text-xs bg-[#1E293B] border-[#334155] text-[#B0B8C1]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-[#0F172A] border-[#334155]">
              {LLM_PROVIDERS.map((p) => (
                <SelectItem key={p.value} value={p.value} className="text-xs text-[#B0B8C1] focus:bg-[#1E293B]">
                  {p.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>

      {/* Store in Snowflake toggle */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-[#94A3B8]">Store in Snowflake</span>
        <Switch
          checked={useSnowflake}
          onCheckedChange={setUseSnowflake}
          className="data-[state=checked]:bg-indigo-600"
        />
      </div>

      {/* Report formats */}
      <div className="space-y-2">
        <p className="text-xs text-[#94A3B8]">Report Formats</p>
        <div className="flex flex-wrap gap-1.5">
          {REPORT_FORMATS.map((fmt) => {
            const active = reportFormats.includes(fmt.value)
            return (
              <button
                key={fmt.value}
                onClick={() => toggleFormat(fmt.value)}
                className={`px-2 py-0.5 text-[11px] rounded border transition-colors ${
                  active
                    ? 'border-indigo-500 bg-indigo-500/20 text-indigo-300'
                    : 'border-[#334155] bg-transparent text-[#64748B] hover:border-[#475569]'
                }`}
              >
                {fmt.label}
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}
