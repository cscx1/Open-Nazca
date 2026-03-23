'use client'

import { useRef, useState } from 'react'
import { Upload, FileText, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { useUploadDocument } from '@/hooks/useKnowledgeBase'
import { cn } from '@/lib/utils'

const ACCEPTED = ['.pdf', '.md', '.txt']
const ACCEPT_STRING = ACCEPTED.join(',')

type UploadStatus = 'idle' | 'uploading' | 'done' | 'error'

interface FileUploadEntry {
  file: File
  status: UploadStatus
  pct: number
  error?: string
}

export function DocumentUploader() {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)
  const [queue, setQueue] = useState<FileUploadEntry[]>([])
  const upload = useUploadDocument()

  function updateEntry(name: string, patch: Partial<FileUploadEntry>) {
    setQueue((prev) =>
      prev.map((e) => (e.file.name === name ? { ...e, ...patch } : e))
    )
  }

  async function uploadFile(entry: FileUploadEntry) {
    updateEntry(entry.file.name, { status: 'uploading', pct: 10 })

    // Simulate incremental progress while awaiting the network call
    let pct = 10
    const ticker = setInterval(() => {
      pct = Math.min(pct + 15, 85)
      updateEntry(entry.file.name, { pct })
    }, 350)

    try {
      await upload.mutateAsync(entry.file)
      clearInterval(ticker)
      updateEntry(entry.file.name, { status: 'done', pct: 100 })
      toast.success(`Uploaded ${entry.file.name}`)
    } catch (err) {
      clearInterval(ticker)
      const msg = err instanceof Error ? err.message : 'Upload failed'
      updateEntry(entry.file.name, { status: 'error', pct: 0, error: msg })
      toast.error(`Failed to upload ${entry.file.name}`, { description: msg })
    }
  }

  function addFiles(incoming: FileList | null) {
    if (!incoming) return
    const newEntries: FileUploadEntry[] = Array.from(incoming)
      .filter((f) => !queue.some((e) => e.file.name === f.name))
      .map((f) => ({ file: f, status: 'idle', pct: 0 }))
    setQueue((prev) => [...prev, ...newEntries])
  }

  async function handleUploadAll() {
    const pending = queue.filter((e) => e.status === 'idle' || e.status === 'error')
    for (const entry of pending) {
      await uploadFile(entry)
    }
    // Remove completed entries after a short delay
    setTimeout(() => setQueue((prev) => prev.filter((e) => e.status !== 'done')), 2000)
  }

  const hasPending = queue.some((e) => e.status === 'idle' || e.status === 'error')
  const isUploading = queue.some((e) => e.status === 'uploading')

  return (
    <div className="space-y-4">
      {/* Drop zone */}
      <div
        role="button"
        tabIndex={0}
        aria-label="Upload documents"
        onClick={() => inputRef.current?.click()}
        onKeyDown={(e) => e.key === 'Enter' && inputRef.current?.click()}
        onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => { e.preventDefault(); setDragging(false); addFiles(e.dataTransfer.files) }}
        className={cn(
          'flex flex-col items-center justify-center gap-3 py-12 rounded border-2 border-dashed transition-colors cursor-pointer',
          dragging
            ? 'border-indigo-400 bg-indigo-500/10'
            : 'border-[#334155] hover:border-[#475569] bg-[#0B1120]'
        )}
      >
        <div className="flex items-center justify-center w-12 h-12 rounded-full bg-[#1E293B] border border-[#334155]">
          <Upload className="w-5 h-5 text-[#64748B]" />
        </div>
        <div className="text-center">
          <p className="text-sm font-medium text-white">
            {dragging ? 'Drop documents here' : 'Drop documents or click to browse'}
          </p>
          <p className="text-xs text-[#64748B] mt-1">Accepted: PDF, Markdown, Plain Text</p>
        </div>
      </div>

      {/* File queue */}
      {queue.length > 0 && (
        <div className="space-y-2">
          {queue.map((entry) => (
            <div
              key={entry.file.name}
              className="flex items-center gap-3 px-3 py-2.5 rounded border border-[#334155] bg-[#0B1120]"
            >
              <FileText className="w-4 h-4 text-indigo-400 shrink-0" />
              <div className="flex-1 min-w-0 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-[#B0B8C1] truncate">{entry.file.name}</span>
                  <StatusIcon status={entry.status} />
                </div>
                {entry.status === 'uploading' && (
                  <Progress
                    value={entry.pct}
                    className="h-1 bg-[#1E293B] [&>div]:bg-indigo-500 [&>div]:transition-all"
                  />
                )}
                {entry.status === 'error' && (
                  <p className="text-[10px] text-red-400">{entry.error}</p>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Upload button */}
      {hasPending && (
        <Button
          onClick={handleUploadAll}
          disabled={isUploading}
          className="w-full bg-indigo-600 hover:bg-indigo-500 text-white uppercase text-xs tracking-wider font-semibold h-10"
        >
          {isUploading ? (
            <><Loader2 className="w-3.5 h-3.5 mr-2 animate-spin" />Uploading…</>
          ) : (
            <><Upload className="w-3.5 h-3.5 mr-2" />Upload {queue.filter((e) => e.status === 'idle' || e.status === 'error').length} Document(s)</>
          )}
        </Button>
      )}

      <input
        ref={inputRef}
        type="file"
        multiple
        accept={ACCEPT_STRING}
        onChange={(e) => addFiles(e.target.files)}
        className="hidden"
      />
    </div>
  )
}

function StatusIcon({ status }: { status: UploadStatus }) {
  if (status === 'uploading') return <Loader2 className="w-3.5 h-3.5 text-indigo-400 animate-spin shrink-0" />
  if (status === 'done')      return <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
  if (status === 'error')     return <XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" />
  return <span className="w-3.5 h-3.5 rounded-full border border-[#475569] shrink-0 inline-block" />
}
