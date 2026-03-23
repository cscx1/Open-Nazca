'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { getKnowledgeBaseFiles, uploadKnowledgeBaseFile, deleteKnowledgeBaseFile } from '@/lib/api'
import type { KnowledgeBaseFile } from '@/lib/types'

const KB_KEY = ['knowledge-base']

export function useKnowledgeBase() {
  return useQuery<{ files: KnowledgeBaseFile[] }>({
    queryKey: KB_KEY,
    queryFn: getKnowledgeBaseFiles,
    retry: false,
    // Don't throw on backend offline — show empty state instead
    throwOnError: false,
  })
}

export function useUploadDocument() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: uploadKnowledgeBaseFile,
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: KB_KEY })
    },
  })
}

export function useDeleteDocument() {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: deleteKnowledgeBaseFile,
    onMutate: async (filename) => {
      await qc.cancelQueries({ queryKey: KB_KEY })
      const prev = qc.getQueryData<{ files: KnowledgeBaseFile[] }>(KB_KEY)
      qc.setQueryData<{ files: KnowledgeBaseFile[] }>(KB_KEY, (old) => ({
        files: old?.files.filter((f) => f.filename !== filename) ?? [],
      }))
      return { prev }
    },
    onError: (_err, _vars, ctx) => {
      if (ctx?.prev) qc.setQueryData(KB_KEY, ctx.prev)
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: KB_KEY })
    },
  })
}
