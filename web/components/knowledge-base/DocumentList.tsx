'use client'

import { useState } from 'react'
import { FileText, Trash2, Loader2, RefreshCw, Database } from 'lucide-react'
import { toast } from 'sonner'
import { Button } from '@/components/ui/button'
import { Skeleton } from '@/components/ui/skeleton'
import { useKnowledgeBase, useDeleteDocument } from '@/hooks/useKnowledgeBase'
import { EmptyState } from '@/components/ui/empty-state'
import { cn } from '@/lib/utils'

const FILE_EXT_COLORS: Record<string, string> = {
  pdf: '#DC2626',
  md:  '#3B82F6',
  txt: '#10B981',
}

function extColor(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() ?? ''
  return FILE_EXT_COLORS[ext] ?? '#6366F1'
}

function extLabel(filename: string): string {
  return (filename.split('.').pop()?.toUpperCase() ?? 'FILE')
}

export function DocumentList() {
  const { data, isLoading, isError, refetch, isFetching } = useKnowledgeBase()
  const deleteDoc = useDeleteDocument()
  const [deleting, setDeleting] = useState<string | null>(null)

  async function handleDelete(filename: string) {
    setDeleting(filename)
    try {
      await deleteDoc.mutateAsync(filename)
      toast.success(`Deleted ${filename}`)
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Delete failed'
      toast.error(`Failed to delete ${filename}`, { description: msg })
    } finally {
      setDeleting(null)
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 3 }).map((_, i) => (
          <div key={i} className="flex items-center gap-3 px-4 py-3 rounded border border-[#334155] bg-[#0B1120]">
            <Skeleton className="w-8 h-8 rounded shrink-0" />
            <div className="flex-1 space-y-1.5">
              <Skeleton className="h-3 w-40 rounded" />
              <Skeleton className="h-2.5 w-24 rounded" />
            </div>
          </div>
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <div className="flex items-center gap-3 py-6">
        <p className="text-sm text-[#64748B] flex-1">Could not reach backend — knowledge base unavailable.</p>
        <Button
          variant="outline"
          size="sm"
          onClick={() => void refetch()}
          className="border-[#334155] text-[#94A3B8] h-8 text-xs"
        >
          <RefreshCw className="w-3 h-3 mr-1.5" />
          Retry
        </Button>
      </div>
    )
  }

  const files = data?.files ?? []

  if (files.length === 0) {
    return (
      <EmptyState
        icon={Database}
        title="No documents stored"
        description="Upload PDF, Markdown, or plain-text policy documents to enrich AI analysis context."
      />
    )
  }

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between mb-1">
        <span className="text-xs text-[#64748B]">{files.length} document(s) in Snowflake</span>
        <button
          onClick={() => void refetch()}
          disabled={isFetching}
          className="flex items-center gap-1 text-[11px] text-[#64748B] hover:text-[#94A3B8] transition-colors disabled:opacity-50"
        >
          <RefreshCw className={cn('w-3 h-3', isFetching && 'animate-spin')} />
          Refresh
        </button>
      </div>

      {files.map((doc) => {
        const color = extColor(doc.filename)
        const isDeleting = deleting === doc.filename

        return (
          <div
            key={doc.filename}
            className="flex items-center gap-3 px-4 py-3 rounded border border-[#334155] bg-[#0B1120] hover:border-[#475569] transition-colors group"
          >
            {/* Icon */}
            <div
              className="flex items-center justify-center w-8 h-8 rounded shrink-0"
              style={{ backgroundColor: `${color}15`, border: `1px solid ${color}33` }}
            >
              <FileText className="w-4 h-4" style={{ color }} />
            </div>

            {/* Name + meta */}
            <div className="flex-1 min-w-0">
              <p className="text-sm text-[#B0B8C1] font-medium truncate">{doc.filename}</p>
              <div className="flex items-center gap-2 mt-0.5">
                <span
                  className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                  style={{ backgroundColor: `${color}20`, color }}
                >
                  {extLabel(doc.filename)}
                </span>
                {doc.uploaded_at && (
                  <span className="text-[10px] text-[#475569]">
                    {new Date(doc.uploaded_at).toLocaleDateString()}
                  </span>
                )}
              </div>
            </div>

            {/* Delete button */}
            <button
              onClick={() => handleDelete(doc.filename)}
              disabled={isDeleting}
              className="opacity-0 group-hover:opacity-100 flex items-center justify-center w-7 h-7 rounded border border-[#334155] text-[#64748B] hover:border-red-700 hover:text-red-400 hover:bg-red-900/10 transition-all disabled:opacity-50"
              aria-label={`Delete ${doc.filename}`}
            >
              {isDeleting
                ? <Loader2 className="w-3.5 h-3.5 animate-spin" />
                : <Trash2 className="w-3.5 h-3.5" />
              }
            </button>
          </div>
        )
      })}
    </div>
  )
}
