'use client'

import { useEffect } from 'react'
import { useRouter } from 'next/navigation'
import { LayoutDashboard, FlaskConical, Shield, BookOpen, Clock } from 'lucide-react'
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandShortcut,
} from '@/components/ui/command'
import { useConfigStore } from '@/store/configStore'

const NAV_ITEMS = [
  { label: 'Dashboard',     href: '/dashboard',      icon: LayoutDashboard, shortcut: '⌘1' },
  { label: 'Analysis Lab',  href: '/analysis',       icon: FlaskConical,    shortcut: '⌘2' },
  { label: 'Sandbox Lab',   href: '/sandbox',         icon: Shield,          shortcut: '⌘3' },
  { label: 'Knowledge Base', href: '/knowledge-base', icon: BookOpen,        shortcut: '⌘4' },
  { label: 'Scan History',  href: '/history',         icon: Clock,           shortcut: '⌘5' },
]

export function CommandPalette() {
  const { commandPaletteOpen, setCommandPaletteOpen } = useConfigStore()
  const router = useRouter()

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault()
        setCommandPaletteOpen(true)
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [setCommandPaletteOpen])

  function navigate(href: string) {
    setCommandPaletteOpen(false)
    router.push(href)
  }

  return (
    <CommandDialog
      open={commandPaletteOpen}
      onOpenChange={setCommandPaletteOpen}
      title="Command Palette"
      description="Navigate to a page"
    >
      <CommandInput placeholder="Type a page name…" />
      <CommandList>
        <CommandEmpty>No results found.</CommandEmpty>
        <CommandGroup heading="Navigation">
          {NAV_ITEMS.map(({ label, href, icon: Icon, shortcut }) => (
            <CommandItem
              key={href}
              onSelect={() => navigate(href)}
              className="gap-2 cursor-pointer"
            >
              <Icon className="w-4 h-4 text-indigo-400 shrink-0" />
              <span>{label}</span>
              <CommandShortcut>{shortcut}</CommandShortcut>
            </CommandItem>
          ))}
        </CommandGroup>
      </CommandList>
    </CommandDialog>
  )
}
