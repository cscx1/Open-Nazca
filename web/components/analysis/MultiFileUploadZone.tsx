'use client'

import { useRef, useState } from 'react'
import { Upload, FileCode2, X } from 'lucide-react'
import { cn } from '@/lib/utils'

const ALL_CODE_TYPES = [
  '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rs', '.rb', '.php', '.c', '.cpp',
]
const ACCEPT_STRING = ALL_CODE_TYPES.join(',')

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

interface MultiFileUploadZoneProps {
  onFilesChanged: (files: File[]) => void
  selectedFiles: File[]
  disabled?: boolean
}

export function MultiFileUploadZone({ onFilesChanged, selectedFiles, disabled }: MultiFileUploadZoneProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  function addFiles(incoming: FileList | null) {
    if (!incoming) return
    const newFiles = Array.from(incoming).filter(
      (f) => !selectedFiles.some((s) => s.name === f.name)
    )
    onFilesChanged([...selectedFiles, ...newFiles])
  }

  function removeFile(name: string) {
    onFilesChanged(selectedFiles.filter((f) => f.name !== name))
  }

  function handleDrop(e: React.DragEvent) {
    e.preventDefault()
    setDragging(false)
    if (!disabled) addFiles(e.dataTransfer.files)
  }

  return (
    <div className="space-y-3">
      <div
        role="button"
        tabIndex={0}
        aria-label="Upload files"
        onClick={() => !disabled && inputRef.current?.click()}
        onKeyDown={(e) => e.key === 'Enter' && !disabled && inputRef.current?.click()}
        onDragOver={(e) => { e.preventDefault(); if (!disabled) setDragging(true) }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={cn(
          'flex flex-col items-center justify-center gap-3 py-10 rounded border-2 border-dashed transition-colors cursor-pointer',
          dragging
            ? 'border-indigo-400 bg-indigo-500/10'
            : 'border-[#334155] hover:border-[#475569] bg-[#0B1120]',
          disabled && 'opacity-50 cursor-not-allowed'
        )}
      >
        <div className="flex items-center justify-center w-12 h-12 rounded-full bg-[#1E293B] border border-[#334155]">
          <Upload className="w-5 h-5 text-[#64748B]" />
        </div>
        <div className="text-center">
          <p className="text-sm font-medium text-white">
            {dragging ? 'Drop files here' : 'Drop files or click to browse'}
          </p>
          <p className="text-xs text-[#64748B] mt-1">Multiple files accepted: {ALL_CODE_TYPES.join(' ')}</p>
        </div>
      </div>

      {selectedFiles.length > 0 && (
        <div className="space-y-1.5">
          {selectedFiles.map((file) => (
            <div key={file.name} className="flex items-center gap-3 px-3 py-2 rounded border border-[#334155] bg-[#0B1120]">
              <FileCode2 className="w-4 h-4 text-indigo-400 shrink-0" />
              <span className="flex-1 text-xs text-[#B0B8C1] truncate">{file.name}</span>
              <span className="text-xs text-[#475569]">{formatBytes(file.size)}</span>
              <button
                onClick={() => removeFile(file.name)}
                className="text-[#475569] hover:text-white transition-colors"
                aria-label={`Remove ${file.name}`}
              >
                <X className="w-3.5 h-3.5" />
              </button>
            </div>
          ))}
        </div>
      )}

      <input
        ref={inputRef}
        type="file"
        multiple
        accept={ACCEPT_STRING}
        onChange={(e) => addFiles(e.target.files)}
        className="hidden"
        disabled={disabled}
      />
    </div>
  )
}
