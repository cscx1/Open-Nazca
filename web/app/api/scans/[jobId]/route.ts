import { NextRequest } from 'next/server'
import { proxyToBackend, safeError } from '@/lib/backend'

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ jobId: string }> }
) {
  try {
    const { jobId } = await params
    const upstream = await proxyToBackend(`/api/scans/${encodeURIComponent(jobId)}`)
    const data = await upstream.json() as unknown
    return Response.json(data, { status: upstream.status })
  } catch (err) {
    console.error('[GET /api/scans/[jobId]]', err)
    return safeError('Failed to fetch scan status')
  }
}
