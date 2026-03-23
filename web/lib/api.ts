import type {
  ScanConfig,
  ScanJob,
  ScanResults,
  ReportFormat,
  KnowledgeBaseFile,
} from './types'

const BASE = '/api'

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.text()
    throw new Error(body || `HTTP ${res.status}`)
  }
  return res.json() as Promise<T>
}

/* ─── Scans ─────────────────────────────────────────────────────────────── */

export async function postScan(
  file: File,
  config: ScanConfig
): Promise<{ jobId: string; status: 'queued' }> {
  const form = new FormData()
  form.append('file', file)
  form.append('config', JSON.stringify(config))
  const res = await fetch(`${BASE}/scans`, { method: 'POST', body: form })
  return handleResponse(res)
}

export async function getScanJob(jobId: string): Promise<ScanJob> {
  const res = await fetch(`${BASE}/scans/${jobId}`)
  return handleResponse(res)
}

export async function getScanResults(jobId: string): Promise<ScanResults> {
  const job = await getScanJob(jobId)
  if (job.status !== 'complete' || !job.results) {
    throw new Error('Scan not complete')
  }
  return job.results
}

/* ─── Sandbox ────────────────────────────────────────────────────────────── */

export async function postSandbox(
  files: File[],
  config: ScanConfig
): Promise<{ jobId: string; status: 'queued' }> {
  const form = new FormData()
  files.forEach((f) => form.append('files', f))
  form.append('config', JSON.stringify(config))
  const res = await fetch(`${BASE}/sandbox`, { method: 'POST', body: form })
  return handleResponse(res)
}

/* ─── Reports ────────────────────────────────────────────────────────────── */

export function getReportUrl(scanId: string, format: ReportFormat): string {
  return `${BASE}/reports/${encodeURIComponent(scanId)}/${format}`
}

/* ─── Knowledge Base ─────────────────────────────────────────────────────── */

export async function getKnowledgeBaseFiles(): Promise<{ files: KnowledgeBaseFile[] }> {
  const res = await fetch(`${BASE}/knowledge-base`)
  return handleResponse(res)
}

export async function uploadKnowledgeBaseFile(
  file: File
): Promise<{ success: boolean; filename: string }> {
  const form = new FormData()
  form.append('file', file)
  form.append('filename', file.name)
  const res = await fetch(`${BASE}/knowledge-base`, { method: 'POST', body: form })
  return handleResponse(res)
}

export async function deleteKnowledgeBaseFile(
  filename: string
): Promise<{ success: boolean }> {
  const res = await fetch(`${BASE}/knowledge-base/${encodeURIComponent(filename)}`, {
    method: 'DELETE',
  })
  return handleResponse(res)
}
