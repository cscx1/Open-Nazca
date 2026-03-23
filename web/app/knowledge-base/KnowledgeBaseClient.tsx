'use client'

import { BookOpen, Database } from 'lucide-react'
import { AppShell } from '@/components/layout/AppShell'
import { PageTransition } from '@/components/layout/PageTransition'
import { DocumentUploader } from '@/components/knowledge-base/DocumentUploader'
import { DocumentList } from '@/components/knowledge-base/DocumentList'
import { Separator } from '@/components/ui/separator'

export function KnowledgeBaseClient() {
  return (
    <AppShell>
      <PageTransition>
      <div className="px-6 py-8 min-h-full space-y-6">
        {/* Header */}
        <div>
          <div className="flex items-center gap-3 mb-1">
            <BookOpen className="w-5 h-5 text-indigo-400" />
            <h1 className="text-xl font-semibold text-white">Knowledge Base</h1>
          </div>
          <p className="text-sm text-[#94A3B8] ml-8">
            Upload policy documents to enrich AI analysis context — stored in Snowflake for semantic retrieval
          </p>
        </div>

        {/* Upload section */}
        <div className="space-y-3">
          <p className="section-label">Upload Documents</p>
          <p className="text-xs text-[#64748B]">
            Supported formats: PDF, Markdown (.md), Plain text (.txt) — security policies, coding standards, threat models
          </p>
          <DocumentUploader />
        </div>

        <Separator className="bg-[#1E293B]" />

        {/* Stored documents */}
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <Database className="w-4 h-4 text-indigo-400" />
            <p className="section-label">Stored Documents (Snowflake)</p>
          </div>
          <DocumentList />
        </div>
      </div>
      </PageTransition>
    </AppShell>
  )
}
