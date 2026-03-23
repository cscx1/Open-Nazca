import { NextRequest } from 'next/server'
import { proxyToBackend, safeError } from '@/lib/backend'

export async function DELETE(
  _req: NextRequest,
  { params }: { params: Promise<{ filename: string }> }
) {
  try {
    const { filename } = await params
    const upstream = await proxyToBackend(
      `/api/knowledge-base/${encodeURIComponent(filename)}`,
      { method: 'DELETE' }
    )
    const data = await upstream.json() as unknown
    return Response.json(data, { status: upstream.status })
  } catch (err) {
    console.error('[DELETE /api/knowledge-base/[filename]]', err)
    return safeError('Failed to delete document')
  }
}
