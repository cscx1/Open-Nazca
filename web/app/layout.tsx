import type { Metadata } from 'next'
import { Geist, Geist_Mono } from 'next/font/google'
import './globals.css'
import { Providers } from './providers'
import { Toaster } from '@/components/ui/sonner'
import { CommandPalette } from '@/components/layout/CommandPalette'

const geistSans = Geist({
  variable: '--font-geist-sans',
  subsets: ['latin'],
})

const geistMono = Geist_Mono({
  variable: '--font-geist-mono',
  subsets: ['latin'],
})

export const metadata: Metadata = {
  title: 'Open Nazca — Security Analytics',
  description: 'AI-powered code security scanning and vulnerability analysis',
}

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode
}>) {
  return (
    <html lang="en" className={`${geistSans.variable} ${geistMono.variable} h-full antialiased dark`}>
      <body className="h-full bg-[#000E1A]">
        <Providers>
          {children}
          <CommandPalette />
          <Toaster richColors position="bottom-right" theme="dark" />
        </Providers>
      </body>
    </html>
  )
}
