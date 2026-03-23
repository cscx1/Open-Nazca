'use client'

import { useRef, useState } from 'react'
import { Upload, FileCode2, X } from 'lucide-react'
import { cn } from '@/lib/utils'

const ACCEPTED_TYPES = [
  '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.go', '.rs', '.rb', '.php',
]
const ACCEPT_STRING = ACCEPTED_TYPES.join(',')

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

interface FileUploadZoneProps {
  onFileSelected: (file: File | null) => void
  selectedFile: File | null
  disabled?: boolean
  multiple?: false
}

export function FileUploadZone({ onFileSelected, selectedFile, disabled }: FileUploadZoneProps) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  function handleDrop(e: React.DragEvent) {
    e.preventDefault()
    setDragging(false)
    if (disabled) return
    const file = e.dataTransfer.files[0]
    if (file) onFileSelected(file)
  }

  function handleChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0] ?? null
    onFileSelected(file)
    // reset so same file can be re-selected
    e.target.value = ''
  }

  return (
    <div>
      {selectedFile ? (
        <div className="flex items-center gap-3 p-4 rounded border border-indigo-500 bg-indigo-500/10">
          <FileCode2 className="w-5 h-5 text-indigo-400 shrink-0" />
          <div className="flex-1 min-w-0">
            <p className="text-sm font-medium text-white truncate">{selectedFile.name}</p>
            <p className="text-xs text-[#64748B]">{formatBytes(selectedFile.size)}</p>
          </div>
          <button
            onClick={() => onFileSelected(null)}
            className="text-[#64748B] hover:text-white transition-colors"
            aria-label="Remove file"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      ) : (
        <div
          role="button"
          tabIndex={0}
          aria-label="Upload file"
          onClick={() => !disabled && inputRef.current?.click()}
          onKeyDown={(e) => e.key === 'Enter' && !disabled && inputRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); if (!disabled) setDragging(true) }}
          onDragLeave={() => setDragging(false)}
          onDrop={handleDrop}
          className={cn(
            'flex flex-col items-center justify-center gap-3 py-14 rounded border-2 border-dashed transition-colors cursor-pointer',
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
              {dragging ? 'Drop file here' : 'Drop file or click to browse'}
            </p>
            <p className="text-xs text-[#64748B] mt-1">Accepted: {ACCEPTED_TYPES.join(' ')}</p>
          </div>
        </div>
      )}
      <input
        ref={inputRef}
        type="file"
        accept={ACCEPT_STRING}
        onChange={handleChange}
        className="hidden"
        disabled={disabled}
      />
    </div>
  )
}
