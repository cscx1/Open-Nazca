import { NextRequest } from 'next/server'
import { BACKEND_URL, notFound, safeError, badRequest } from '@/lib/backend'

const ALLOWED_FORMATS = new Set(['json', 'html', 'markdown'])

const MIME: Record<string, string> = {
  json:     'application/json',
  html:     'text/html',
  markdown: 'text/markdown',
}

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ scanId: string; format: string }> }
) {
  const { scanId, format } = await params

  // Validate params before hitting backend
  if (!ALLOWED_FORMATS.has(format)) return badRequest(`Invalid format: ${format}`)
  if (!/^[\w-]+$/.test(scanId)) return badRequest('Invalid scan ID')

  try {
    const upstream = await fetch(
      `${BACKEND_URL}/api/reports/${encodeURIComponent(scanId)}/${encodeURIComponent(format)}`
    )
    if (upstream.status === 404) return notFound('Report not found')
    if (!upstream.ok) return safeError('Failed to fetch report')

    const body = await upstream.arrayBuffer()
    const ext = format === 'markdown' ? 'md' : format

    return new Response(body, {
      headers: {
        'Content-Type': MIME[format] ?? 'application/octet-stream',
        'Content-Disposition': `attachment; filename="report_${scanId}.${ext}"`,
      },
    })
  } catch (err) {
    console.error('[GET /api/reports]', err)
    return safeError('Failed to download report')
  }
}
