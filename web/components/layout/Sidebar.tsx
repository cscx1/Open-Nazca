'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import {
  LayoutDashboard,
  FlaskConical,
  Shield,
  BookOpen,
  Clock,
  ChevronLeft,
  ChevronRight,
  Zap,
} from 'lucide-react'
import { motion } from 'framer-motion'
import { cn } from '@/lib/utils'
import { SidebarConfig } from './SidebarConfig'
import { Separator } from '@/components/ui/separator'
import { Tooltip, TooltipTrigger, TooltipContent } from '@/components/ui/tooltip'

interface NavItem {
  href: string
  label: string
  icon: React.ComponentType<{ className?: string }>
}

const NAV_ITEMS: NavItem[] = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/analysis', label: 'Analysis Lab', icon: FlaskConical },
  { href: '/sandbox', label: 'Sandbox Lab', icon: Shield },
  { href: '/knowledge-base', label: 'Knowledge Base', icon: BookOpen },
  { href: '/history', label: 'Scan History', icon: Clock },
]

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

export function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const pathname = usePathname()

  return (
    <motion.aside
      animate={{ width: collapsed ? 64 : 240 }}
      transition={{ duration: 0.18, ease: 'easeInOut' }}
      className="relative flex flex-col h-screen bg-[#0F172A] border-r border-[#334155] shrink-0 overflow-hidden"
    >
      {/* Logo */}
      <div className={cn('flex items-center gap-2.5 px-4 py-5 border-b border-[#334155]', collapsed && 'justify-center px-0')}>
        <div className="flex items-center justify-center w-8 h-8 rounded bg-indigo-600 shrink-0">
          <Zap className="w-4 h-4 text-white" />
        </div>
        {!collapsed && (
          <div>
            <p className="text-sm font-bold text-white leading-tight whitespace-nowrap">Open Nazca</p>
            <p className="text-[10px] text-[#64748B] tracking-wide uppercase leading-tight whitespace-nowrap">Security Analytics</p>
          </div>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 space-y-0.5 px-2">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const active = pathname === href || pathname.startsWith(href + '/')
          const linkContent = (
            <Link
              key={href}
              href={href}
              className={cn(
                'flex items-center gap-3 px-2.5 py-2 rounded text-sm transition-colors group relative',
                collapsed ? 'justify-center px-0 py-2.5' : '',
                active
                  ? 'bg-indigo-600/15 text-white border-l-2 border-indigo-500 pl-2'
                  : 'text-[#94A3B8] hover:bg-[#1E293B] hover:text-white border-l-2 border-transparent pl-2'
              )}
            >
              <Icon className={cn('shrink-0 w-4 h-4', active ? 'text-indigo-400' : 'text-[#64748B] group-hover:text-[#94A3B8]')} />
              {!collapsed && (
                <span className="truncate whitespace-nowrap">{label}</span>
              )}
            </Link>
          )

          if (collapsed) {
            return (
              <Tooltip key={href}>
                <TooltipTrigger render={<span />} delay={300} className="block w-full">
                  {linkContent}
                </TooltipTrigger>
                <TooltipContent side="right">{label}</TooltipContent>
              </Tooltip>
            )
          }

          return linkContent
        })}
      </nav>

      {/* Config section — only shown when expanded */}
      {!collapsed && (
        <>
          <Separator className="bg-[#334155]" />
          <SidebarConfig />
        </>
      )}

      {/* Footer — only shown when expanded */}
      {!collapsed && (
        <div className="px-4 py-3 border-t border-[#334155] space-y-1">
          <p className="text-[10px] text-[#475569] uppercase tracking-wider whitespace-nowrap">HoyaHack 2026</p>
          <p className="text-[10px] text-[#475569] uppercase tracking-wider whitespace-nowrap">Powered by Snowflake Cortex</p>
        </div>
      )}

      {/* Collapse toggle — centered at bottom, always within sidebar bounds */}
      <button
        onClick={onToggle}
        className="absolute bottom-4 left-1/2 -translate-x-1/2 w-7 h-7 rounded-full bg-[var(--bg-overlay)] border border-[var(--border-default)] flex items-center justify-center text-[#94A3B8] hover:text-white hover:bg-[#334155] transition-colors z-10"
        aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronLeft className="w-3.5 h-3.5" />}
      </button>
    </motion.aside>
  )
}
