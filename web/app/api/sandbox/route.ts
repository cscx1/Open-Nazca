import { NextRequest } from 'next/server'
import { proxyToBackend, safeError, badRequest } from '@/lib/backend'

export async function POST(req: NextRequest) {
  try {
    const form = await req.formData()
    const files = form.getAll('files')
    if (!files.length) return badRequest('No files provided')

    const upstream = await proxyToBackend('/api/sandbox', {
      method: 'POST',
      body: form,
    })
    const data = await upstream.json() as unknown
    return Response.json(data, { status: upstream.status })
  } catch (err) {
    console.error('[POST /api/sandbox]', err)
    return safeError('Failed to submit sandbox job')
  }
}
