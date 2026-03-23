'use client'

import { useEffect, useRef, useState } from 'react'
import type { SandboxResults } from '@/lib/types'
import { cn } from '@/lib/utils'

/* ─── Graph data model ──────────────────────────────────────────────────── */
interface GraphNode {
  id: string
  label: string
  kind: 'file' | 'vuln'
  severity?: string
  x: number
  y: number
  count?: number
}

interface GraphEdge {
  from: string
  to: string
}

function buildGraph(results: SandboxResults): { nodes: GraphNode[]; edges: GraphEdge[] } {
  const nodes: GraphNode[] = []
  const edges: GraphEdge[] = []
  const entries = Object.entries(results.files)

  const totalFiles = entries.length
  const fileAngleStep = (2 * Math.PI) / Math.max(totalFiles, 1)
  const fileRadius = Math.min(180, 60 + totalFiles * 28)
  const cx = 360, cy = 240

  entries.forEach(([filename, fr], fi) => {
    const angle = fi * fileAngleStep - Math.PI / 2
    const fx = cx + Math.cos(angle) * fileRadius
    const fy = cy + Math.sin(angle) * fileRadius

    const shortName = filename.split('/').pop() ?? filename
    const fileId = `file:${fi}`
    nodes.push({ id: fileId, label: shortName, kind: 'file', x: fx, y: fy, count: fr.findings_before.length })

    // Unique vuln types for this file
    const vulnTypes = new Map<string, { sev: string; count: number }>()
    for (const f of fr.findings_before) {
      const existing = vulnTypes.get(f.vulnerability_type)
      vulnTypes.set(f.vulnerability_type, {
        sev: existing ? existing.sev : f.severity,
        count: (existing?.count ?? 0) + 1,
      })
    }

    let vi = 0
    for (const [type, { sev, count }] of vulnTypes) {
      const vulnAngle = angle + (vi - (vulnTypes.size - 1) / 2) * 0.45
      const vr = fileRadius + 90
      const vx = cx + Math.cos(vulnAngle) * vr
      const vy = cy + Math.sin(vulnAngle) * vr
      const vulnId = `vuln:${fi}:${vi}`
      nodes.push({ id: vulnId, label: type, kind: 'vuln', severity: sev, x: vx, y: vy, count })
      edges.push({ from: fileId, to: vulnId })
      vi++
    }
  })

  return { nodes, edges }
}

const SEV_COLORS: Record<string, string> = {
  CRITICAL: '#DC2626',
  HIGH:     '#EA580C',
  MEDIUM:   '#CA8A04',
  LOW:      '#2563EB',
}

interface MapAnalysisTabProps {
  results: SandboxResults | null
}

export function MapAnalysisTab({ results }: MapAnalysisTabProps) {
  const svgRef = useRef<SVGSVGElement>(null)
  const [tooltip, setTooltip] = useState<{ x: number; y: number; label: string; count?: number } | null>(null)

  if (!results || Object.keys(results.files).length === 0) {
    return <div className="py-16 text-center text-sm text-[#475569]">Run the sandbox to see the map analysis</div>
  }

  const { nodes, edges } = buildGraph(results)
  const W = 720, H = 480

  return (
    <div className="space-y-4">
      <div className="rounded border border-[#334155] bg-[#0B1120] p-4 overflow-hidden relative">
        <p className="section-label mb-3">File → Vulnerability DAG</p>
        <svg
          ref={svgRef}
          width="100%"
          viewBox={`0 0 ${W} ${H}`}
          className="overflow-visible"
        >
          {/* Edges */}
          {edges.map((edge, i) => {
            const from = nodes.find((n) => n.id === edge.from)
            const to   = nodes.find((n) => n.id === edge.to)
            if (!from || !to) return null
            return (
              <line
                key={i}
                x1={from.x} y1={from.y}
                x2={to.x}   y2={to.y}
                stroke="#334155"
                strokeWidth={1}
                opacity={0.5}
              />
            )
          })}

          {/* Nodes */}
          {nodes.map((node) => {
            const isFile = node.kind === 'file'
            const color  = isFile ? '#4338CA' : (SEV_COLORS[node.severity ?? 'LOW'] ?? '#6366F1')
            const r      = isFile ? 20 : 12

            return (
              <g
                key={node.id}
                transform={`translate(${node.x},${node.y})`}
                className="cursor-pointer"
                onMouseEnter={(e) => {
                  const rect = svgRef.current?.getBoundingClientRect()
                  if (rect) {
                    setTooltip({
                      x: e.clientX - rect.left,
                      y: e.clientY - rect.top - 10,
                      label: node.label,
                      count: node.count,
                    })
                  }
                }}
                onMouseLeave={() => setTooltip(null)}
              >
                <circle
                  r={r}
                  fill={color}
                  fillOpacity={isFile ? 0.9 : 0.7}
                  stroke={isFile ? '#6366F1' : color}
                  strokeWidth={isFile ? 2 : 1}
                />
                {isFile && node.count !== undefined && node.count > 0 && (
                  <text
                    textAnchor="middle"
                    dy="0.35em"
                    fontSize={9}
                    fill="white"
                    fontFamily="monospace"
                    fontWeight="bold"
                  >
                    {node.count}
                  </text>
                )}
                <text
                  y={r + 10}
                  textAnchor="middle"
                  fontSize={isFile ? 9 : 8}
                  fill={isFile ? '#94A3B8' : '#64748B'}
                  fontFamily="monospace"
                >
                  {node.label.length > 14 ? node.label.slice(0, 14) + '…' : node.label}
                </text>
              </g>
            )
          })}
        </svg>

        {/* SVG tooltip */}
        {tooltip && (
          <div
            className="absolute pointer-events-none rounded border border-[#334155] bg-[#0F172A] px-3 py-2 text-xs shadow-xl z-10"
            style={{ left: tooltip.x + 10, top: tooltip.y }}
          >
            <p className="text-white font-medium">{tooltip.label}</p>
            {tooltip.count !== undefined && (
              <p className="text-[#64748B]">{tooltip.count} finding(s)</p>
            )}
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4">
        <div className="flex items-center gap-2">
          <span className="w-4 h-4 rounded-full bg-indigo-700 border-2 border-indigo-400 inline-block" />
          <span className="text-[10px] text-[#64748B]">File node (number = findings)</span>
        </div>
        {Object.entries(SEV_COLORS).map(([sev, color]) => (
          <div key={sev} className="flex items-center gap-2">
            <span className="w-3 h-3 rounded-full inline-block" style={{ backgroundColor: color }} />
            <span className="text-[10px] text-[#64748B]">{sev}</span>
          </div>
        ))}
      </div>

      {/* File summary table */}
      <div className="rounded border border-[#334155] overflow-hidden">
        <div className="px-4 py-2 bg-[#0F172A] border-b border-[#334155]">
          <p className="section-label">File Summary</p>
        </div>
        <div className="divide-y divide-[#1E293B]">
          {Object.entries(results.files).map(([filename, fr]) => {
            const reduced = fr.findings_before.length - fr.findings_after.length
            return (
              <div key={filename} className="flex items-center gap-4 px-4 py-2.5 hover:bg-[#0F172A] transition-colors">
                <span className="font-mono text-xs text-[#94A3B8] flex-1 truncate">{filename}</span>
                <span className="text-xs text-[#64748B]">{fr.findings_before.length} before</span>
                <span className="text-xs text-[#64748B]">{fr.findings_after.length} after</span>
                <span className={cn('text-xs font-semibold font-mono', reduced > 0 ? 'text-emerald-400' : 'text-[#475569]')}>
                  {reduced > 0 ? `−${reduced}` : '—'}
                </span>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
