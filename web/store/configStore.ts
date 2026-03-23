import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { LLMProvider, ReportFormat } from '@/lib/types'

interface ConfigState {
  useLLM: boolean
  llmProvider: LLMProvider
  useSnowflake: boolean
  reportFormats: ReportFormat[]
  sidebarCollapsed: boolean
  commandPaletteOpen: boolean
  setUseLLM: (v: boolean) => void
  setLLMProvider: (v: LLMProvider) => void
  setUseSnowflake: (v: boolean) => void
  setReportFormats: (v: ReportFormat[]) => void
  setSidebarCollapsed: (v: boolean) => void
  toggleSidebar: () => void
  setCommandPaletteOpen: (v: boolean) => void
}

export const useConfigStore = create<ConfigState>()(
  persist(
    (set) => ({
      useLLM: true,
      llmProvider: 'snowflake_cortex',
      useSnowflake: false,
      reportFormats: ['json', 'html', 'markdown'],
      sidebarCollapsed: false,
      commandPaletteOpen: false,
      setUseLLM: (v) => set({ useLLM: v }),
      setLLMProvider: (v) => set({ llmProvider: v }),
      setUseSnowflake: (v) => set({ useSnowflake: v }),
      setReportFormats: (v) => set({ reportFormats: v }),
      setSidebarCollapsed: (v) => set({ sidebarCollapsed: v }),
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setCommandPaletteOpen: (v) => set({ commandPaletteOpen: v }),
    }),
    { name: 'nazca-config' }
  )
)
