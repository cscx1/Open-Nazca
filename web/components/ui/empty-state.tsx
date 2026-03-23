'use client'

import type { LucideIcon } from 'lucide-react'
import Link from 'next/link'
import { Button } from './button'

interface EmptyStateProps {
  icon: LucideIcon
  title: string
  description: string
  ctaLabel?: string
  ctaHref?: string
  onCtaClick?: () => void
}

export function EmptyState({ icon: Icon, title, description, ctaLabel, ctaHref, onCtaClick }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center py-20 text-center">
      <div className="flex items-center justify-center w-16 h-16 rounded-full bg-[#1E293B] border border-[#334155] mb-5">
        <Icon className="w-7 h-7 text-[#475569]" />
      </div>
      <h3 className="text-base font-semibold text-white mb-2">{title}</h3>
      <p className="text-sm text-[#64748B] max-w-xs mb-6">{description}</p>
      {ctaLabel && (
        ctaHref ? (
          <Link href={ctaHref}>
            <Button className="bg-indigo-600 hover:bg-indigo-500 text-white uppercase text-xs tracking-wider font-semibold h-11 px-6">
              {ctaLabel}
            </Button>
          </Link>
        ) : (
          <Button
            onClick={onCtaClick}
            className="bg-indigo-600 hover:bg-indigo-500 text-white uppercase text-xs tracking-wider font-semibold h-11 px-6"
          >
            {ctaLabel}
          </Button>
        )
      )}
    </div>
  )
}
