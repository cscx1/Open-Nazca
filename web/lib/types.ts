export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
export type LLMProvider = 'snowflake_cortex' | 'openai' | 'anthropic'
export type ReportFormat = 'json' | 'html' | 'markdown'

export interface ScanConfig {
  useLLM: boolean
  llmProvider: LLMProvider
  useSnowflake: boolean
  reportFormats: ReportFormat[]
}

export interface AttackPath {
  source: { name: string; line: number; detail?: string }
  sink: { name: string; line: number; detail?: string }
  transforms: { name: string; line: number }[]
  severity: Severity
  vulnerability_type: string
}

export interface Finding {
  vulnerability_type: string
  severity: Severity
  verdict_status?: string
  verdict_reason?: string
  line_number: number | 'N/A'
  description: string
  detector_name: string
  code_snippet?: string
  risk_explanation?: string
  suggested_fix?: string
  reachability_status?: string
  reachability_reasoning?: string
  attack_path?: AttackPath
  sink_api?: string
  confidence?: number
  cwe_id?: string
}

export interface ScanResults {
  scan_id: string
  total_findings: number
  severity_counts: Record<Severity, number>
  scan_duration_ms: number
  findings: Finding[]
  report_paths?: Partial<Record<ReportFormat, string>>
}

export interface ScanHistoryEntry {
  filename: string
  timestamp: string
  results: ScanResults
}

export interface ReachabilityResult {
  status:
    | 'Confirmed Reachable'
    | 'Reachability Eliminated'
    | 'Unverifiable'
    | 'Requires Manual Review'
  reasoning: string
  path: AttackPath
}

export interface FixDiff {
  line_number: number
  vulnerability_type: string
  description: string
  is_functional: boolean
  rejection_reason?: string
}

export interface SandboxFileResult {
  findings_before: Finding[]
  findings_after: Finding[]
  fixes: FixDiff[]
  original_code: string
  fixed_code: string
  attack_paths_before: AttackPath[]
  attack_paths_after: AttackPath[]
  reachability_before: ReachabilityResult[]
  reachability_after: ReachabilityResult[]
}

export interface SandboxResults {
  files: Record<string, SandboxFileResult>
  totals_before: Record<string, number>
  totals_after: Record<string, number>
  total_fixes: number
  total_functional_fixes: number
  total_rejected_fixes: number
  log_lines: string[]
}

export type ScanJobStatus = 'queued' | 'running' | 'complete' | 'error'

export interface ScanJob {
  jobId: string
  status: ScanJobStatus
  results?: ScanResults
  error?: string
}

export type ScanEventType = 'progress' | 'complete' | 'error'

export type ScanEvent =
  | { type: 'progress'; message: string; pct: number }
  | { type: 'complete'; results: ScanResults }
  | { type: 'error'; message: string }

export interface KnowledgeBaseFile {
  filename: string
  uploaded_at?: string
}
