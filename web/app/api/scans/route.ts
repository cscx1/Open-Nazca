import { NextRequest } from 'next/server'
import { proxyToBackend, safeError, badRequest } from '@/lib/backend'

export async function POST(req: NextRequest) {
  try {
    const form = await req.formData()
    if (!form.get('file')) return badRequest('Missing file')

    const upstream = await proxyToBackend('/api/scans', {
      method: 'POST',
      body: form,
    })

    const data = await upstream.json() as unknown
    return Response.json(data, { status: upstream.status })
  } catch (err) {
    console.error('[POST /api/scans]', err)
    return safeError('Failed to submit scan job')
  }
}
