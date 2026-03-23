import { NextRequest } from 'next/server'
import { proxyToBackend, safeError } from '@/lib/backend'

export async function GET() {
  try {
    const upstream = await proxyToBackend('/api/knowledge-base')
    const data = await upstream.json() as unknown
    return Response.json(data, { status: upstream.status })
  } catch (err) {
    console.error('[GET /api/knowledge-base]', err)
    return safeError('Failed to fetch knowledge base files')
  }
}

export async function POST(req: NextRequest) {
  try {
    const form = await req.formData()
    const upstream = await proxyToBackend('/api/knowledge-base', {
      method: 'POST',
      body: form,
    })
    const data = await upstream.json() as unknown
    return Response.json(data, { status: upstream.status })
  } catch (err) {
    console.error('[POST /api/knowledge-base]', err)
    return safeError('Failed to upload document')
  }
}
