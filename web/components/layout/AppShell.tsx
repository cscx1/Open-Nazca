'use client'

import { Sidebar } from './Sidebar'
import { useConfigStore } from '@/store/configStore'

interface AppShellProps {
  children: React.ReactNode
}

export function AppShell({ children }: AppShellProps) {
  const { sidebarCollapsed, toggleSidebar } = useConfigStore()

  return (
    <div className="flex h-screen overflow-hidden bg-[#000E1A]">
      <Sidebar collapsed={sidebarCollapsed} onToggle={toggleSidebar} />
      <main className="flex-1 overflow-y-auto">
        {children}
      </main>
    </div>
  )
}
