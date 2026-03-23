'use client'

import type { LucideIcon } from 'lucide-react'
import { motion } from 'framer-motion'
import { MetricCard } from './MetricCard'
import { Skeleton } from '@/components/ui/skeleton'

export interface MetricDef {
  title: string
  value: string | number
  subtext?: string
  icon: LucideIcon
  color?: string
}

interface MetricsGridProps {
  metrics: MetricDef[]
}

const container = {
  hidden: {},
  show: { transition: { staggerChildren: 0.05 } },
}

const item = {
  hidden: { opacity: 0, y: 6 },
  show: { opacity: 1, y: 0, transition: { duration: 0.18, ease: [0.0, 0.0, 0.58, 1.0] as const } },
}

export function MetricsGridSkeleton({ count = 5 }: { count?: number }) {
  return (
    <div
      className="grid gap-3"
      style={{ gridTemplateColumns: `repeat(${count}, minmax(0, 1fr))` }}
    >
      {Array.from({ length: count }).map((_, i) => (
        <div key={i} className="rounded p-4 border border-[#334155] bg-[#0B1120] space-y-3">
          <div className="flex items-center gap-2">
            <Skeleton className="w-6 h-6 rounded" />
            <Skeleton className="w-24 h-2.5 rounded" />
          </div>
          <Skeleton className="w-16 h-7 rounded" />
          <Skeleton className="w-28 h-2 rounded" />
        </div>
      ))}
    </div>
  )
}

export function MetricsGrid({ metrics }: MetricsGridProps) {
  return (
    <motion.div
      variants={container}
      initial="hidden"
      animate="show"
      className="grid gap-3"
      style={{ gridTemplateColumns: `repeat(${metrics.length}, minmax(0, 1fr))` }}
    >
      {metrics.map((m) => (
        <motion.div key={m.title} variants={item}>
          <MetricCard {...m} />
        </motion.div>
      ))}
    </motion.div>
  )
}
