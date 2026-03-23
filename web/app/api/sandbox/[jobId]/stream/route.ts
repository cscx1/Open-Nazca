import { NextRequest } from 'next/server'
import { BACKEND_URL } from '@/lib/backend'

export async function GET(
  _req: NextRequest,
  { params }: { params: Promise<{ jobId: string }> }
) {
  const { jobId } = await params
  const encoder = new TextEncoder()

  const stream = new ReadableStream({
    async start(controller) {
      function send(data: string) {
        controller.enqueue(encoder.encode(`data: ${data}\n\n`))
      }

      try {
        const upstream = await fetch(
          `${BACKEND_URL}/api/sandbox/${encodeURIComponent(jobId)}/stream`,
          { headers: { Accept: 'text/event-stream' } }
        )

        if (!upstream.ok || !upstream.body) {
          send(JSON.stringify({ type: 'error', message: 'Stream unavailable' }))
          controller.close()
          return
        }

        const reader  = upstream.body.getReader()
        const decoder = new TextDecoder()

        while (true) {
          const { done, value } = await reader.read()
          if (done) break
          controller.enqueue(value)
          const text = decoder.decode(value, { stream: true })
          if (text.includes('"type":"complete"') || text.includes('"type":"error"')) break
        }
      } catch (err) {
        console.error('[Sandbox SSE error]', err)
        send(JSON.stringify({ type: 'error', message: 'Stream connection failed' }))
      } finally {
        controller.close()
      }
    },
  })

  return new Response(stream, {
    headers: {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive',
    },
  })
}
