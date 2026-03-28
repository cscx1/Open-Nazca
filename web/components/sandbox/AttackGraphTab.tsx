'use client'

import { useMemo, useState } from 'react'
import { sankey, sankeyLinkHorizontal, type SankeyGraph } from 'd3-sankey'
import type { SandboxResults, AttackPath } from '@/lib/types'
import { SeverityBadge } from '@/components/ui/severity-badge'
import { cn } from '@/lib/utils'

/* ─── Types ─────────────────────────────────────────────────────────────── */
interface SankeyNodeData {
  id: string
  category: 'source' | 'file' | 'sink'
  name: string
  [key: string]: unknown   // satisfies SankeyExtraProperties
}

interface SankeyLinkData {
  eliminated: boolean
  severity: string
  [key: string]: unknown   // satisfies SankeyExtraProperties
}

/* ─── Input graph types (string ids allowed before layout) ──────────────── */
interface InputLink {
  source: string
  target: string
  value: number
  eliminated: boolean
  severity: string
}

/* ─── Build Sankey graph data from attack paths ──────────────────────────── */
function buildSankeyData(
  paths: AttackPath[],
  eliminatedPaths: AttackPath[]
): { nodes: SankeyNodeData[]; links: InputLink[] } {
  const nodeMap = new Map<string, SankeyNodeData>()
  const links: InputLink[] = []

  function addNode(id: string, category: SankeyNodeData['category'], name: string) {
    if (!nodeMap.has(id)) nodeMap.set(id, { id, category, name })
  }

  function processPaths(batch: AttackPath[], eliminated: boolean) {
    for (const p of batch) {
      const sourceId = `src:${p.source.name}`
      const sinkId   = `sink:${p.sink.name}`
      const fileName = p.transforms.length ? p.transforms[0].name : 'analyzed_file'
      const fileId   = `file:${fileName}`

      addNode(sourceId, 'source', p.source.name)
      addNode(fileId,   'file',   fileName)
      addNode(sinkId,   'sink',   p.sink.name)

      links.push({ source: sourceId, target: fileId, value: 1, eliminated, severity: p.severity })
      links.push({ source: fileId, target: sinkId,   value: 1, eliminated, severity: p.severity })
    }
  }

  processPaths(paths,           false)
  processPaths(eliminatedPaths, true)

  return { nodes: Array.from(nodeMap.values()), links }
}

/* ─── SVG Sankey renderer ────────────────────────────────────────────────── */
const NODE_COLORS: Record<SankeyNodeData['category'], string> = {
  source: '#4338CA',
  file:   '#2563EB',
  sink:   '#DC2626',
}

function SankeyChart({
  paths,
  eliminatedPaths,
  width = 700,
  height = 340,
}: {
  paths: AttackPath[]
  eliminatedPaths: AttackPath[]
  width?: number
  height?: number
}) {
  const rendered = useMemo(() => {
    const { nodes, links } = buildSankeyData(paths, eliminatedPaths)
    if (!nodes.length) return null

    try {
      // d3-sankey resolves string source/target ids via nodeId(); cast input
      // to the expected graph type since TS can't unify string ids with node refs
      const graph = {
        nodes: nodes.map((n) => ({ ...n })),
        links: links.map((l) => ({ ...l })),
      } as unknown as SankeyGraph<SankeyNodeData, SankeyLinkData>

      const layout = sankey<SankeyNodeData, SankeyLinkData>()
        .nodeId((d) => d.id)
        .nodeWidth(18)
        .nodePadding(14)
        .extent([[16, 16], [width - 16, height - 16]])

      const result = layout(graph)
      return { nodes: result.nodes, links: result.links }
    } catch {
      return null
    }
  }, [paths, eliminatedPaths, width, height])

  if (!rendered) {
    return (
      <div className="flex items-center justify-center h-[340px] text-sm text-[#475569]">
        No attack paths to display
      </div>
    )
  }

  const linkPath = sankeyLinkHorizontal()

  return (
    <svg width="100%" viewBox={`0 0 ${width} ${height}`} className="overflow-visible">
      <defs>
        {['active', 'eliminated'].map((kind) => (
          <linearGradient key={kind} id={`link-grad-${kind}`} x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%"   stopColor={kind === 'eliminated' ? '#10B981' : '#DC2626'} stopOpacity="0.5" />
            <stop offset="100%" stopColor={kind === 'eliminated' ? '#059669' : '#9F1239'} stopOpacity="0.3" />
          </linearGradient>
        ))}
      </defs>

      {/* Links */}
      {rendered.links.map((link, i) => {
        const d = linkPath(link as Parameters<typeof linkPath>[0])
        const eliminated = (link as unknown as SankeyLinkData).eliminated
        return (
          <path
            key={i}
            d={d ?? ''}
            fill="none"
            stroke={`url(#link-grad-${eliminated ? 'eliminated' : 'active'})`}
            strokeWidth={Math.max(1, (link.width ?? 2))}
            opacity={0.75}
          />
        )
      })}

      {/* Nodes */}
      {rendered.nodes.map((node, i) => {
        const nodeData = node as unknown as SankeyNodeData
        const cat = nodeData.category
        const color = NODE_COLORS[cat]
        const x0 = node.x0 ?? 0, y0 = node.y0 ?? 0, x1 = node.x1 ?? 0, y1 = node.y1 ?? 0
        const nodeH = Math.max(8, y1 - y0)
        const labelX = cat === 'sink' ? x0 - 6 : x1 + 6
        const anchor = cat === 'sink' ? 'end' : 'start'
        const nodeCount = rendered.links.filter(
          (l) => (l.source as unknown as SankeyNodeData).id === nodeData.id ||
                 (l.target as unknown as SankeyNodeData).id === nodeData.id
        ).length
        const categoryLabel = cat === 'source' ? 'Source' : cat === 'file' ? 'File' : 'Sink'

        return (
          <g key={i}>
            <title>{`${categoryLabel}: ${nodeData.name} (${nodeCount} connection${nodeCount !== 1 ? 's' : ''})`}</title>
            <rect
              x={x0} y={y0}
              width={x1 - x0}
              height={nodeH}
              rx={2}
              fill={color}
              opacity={0.9}
            />
            <text
              x={labelX}
              y={y0 + nodeH / 2}
              dy="0.35em"
              textAnchor={anchor}
              fontSize={9}
              fill="#94A3B8"
              className="font-mono"
            >
              {nodeData.name.slice(0, 22)}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

/* ─── Path detail table ──────────────────────────────────────────────────── */
function PathTable({ paths, eliminated }: { paths: AttackPath[]; eliminated: boolean }) {
  if (!paths.length) return null
  return (
    <div className="mt-1 space-y-1">
      {paths.map((p, i) => (
        <div key={i} className={cn('flex items-center gap-3 px-3 py-2 rounded border text-xs', eliminated ? 'border-emerald-800 bg-emerald-900/10' : 'border-[#334155] bg-[#0B1120]')}>
          <SeverityBadge severity={p.severity} size="sm" />
          <span className="text-[#94A3B8] font-mono">{p.source.name}</span>
          <span className="text-[#475569]">→</span>
          <span className="text-[#94A3B8] font-mono">{p.sink.name}</span>
          <span className="ml-auto text-[11px]">{p.vulnerability_type}</span>
          {eliminated && <span className="text-emerald-400 text-[10px] font-semibold">ELIMINATED</span>}
        </div>
      ))}
    </div>
  )
}

/* ─── Legend ────────────────────────────────────────────────────────────── */
const LEGEND = [
  { color: NODE_COLORS.source,  label: 'Source' },
  { color: NODE_COLORS.file,    label: 'File' },
  { color: NODE_COLORS.sink,    label: 'Sink' },
  { color: '#DC2626',           label: 'Active path',    dashed: false, link: true },
  { color: '#10B981',           label: 'Eliminated',     dashed: false, link: true },
]

/* ─── Main tab ───────────────────────────────────────────────────────────── */
interface AttackGraphTabProps {
  results: SandboxResults | null
}

export function AttackGraphTab({ results }: AttackGraphTabProps) {
  const [toggle, setToggle] = useState<'before' | 'after'>('before')

  if (!results) {
    return <div className="py-16 text-center text-sm text-[#475569]">Run the sandbox to see attack paths</div>
  }

  const allBefore: AttackPath[] = []
  const allAfter:  AttackPath[] = []
  const allEliminated: AttackPath[] = []

  for (const fr of Object.values(results.files)) {
    allBefore.push(...fr.attack_paths_before)
    allAfter.push(...fr.attack_paths_after)
    // Paths present before but not after are eliminated
    const afterKeys = new Set(fr.attack_paths_after.map((p) => `${p.source.name}→${p.sink.name}`))
    for (const p of fr.attack_paths_before) {
      if (!afterKeys.has(`${p.source.name}→${p.sink.name}`)) allEliminated.push(p)
    }
  }

  const activePaths    = toggle === 'before' ? allBefore : allAfter
  const eliminatedShow = toggle === 'after'  ? allEliminated : []

  return (
    <div className="space-y-5">
      {/* Toggle */}
      <div className="flex items-center gap-3">
        <div className="flex rounded border border-[#334155] overflow-hidden text-xs">
          {(['before', 'after'] as const).map((t) => (
            <button
              key={t}
              onClick={() => setToggle(t)}
              className={cn('px-4 py-1.5 capitalize transition-colors', toggle === t ? 'bg-indigo-600 text-white' : 'text-[#64748B] hover:text-[#94A3B8]')}
            >
              {t === 'before' ? 'Before remediation' : 'After remediation'}
            </button>
          ))}
        </div>
        <span className="text-xs text-[#64748B]">
          {activePaths.length} active path(s)
          {toggle === 'after' && allEliminated.length > 0 && ` · ${allEliminated.length} eliminated`}
        </span>
      </div>

      {/* Sankey chart */}
      <div className="rounded border border-[#334155] bg-[#0B1120] p-4">
        <SankeyChart paths={activePaths} eliminatedPaths={eliminatedShow} />
      </div>

      {/* Legend */}
      <div className="flex flex-wrap gap-4">
        {LEGEND.map(({ color, label, link }) => (
          <div key={label} className="flex items-center gap-2">
            {link ? (
              <span className="w-5 h-0.5 inline-block rounded" style={{ backgroundColor: color }} />
            ) : (
              <span className="w-3 h-3 rounded-sm inline-block" style={{ backgroundColor: color }} />
            )}
            <span className="text-[10px] text-[#64748B]">{label}</span>
          </div>
        ))}
      </div>

      {/* Path tables */}
      {activePaths.length > 0 && (
        <div>
          <p className="section-label mb-2">Active Paths</p>
          <PathTable paths={activePaths} eliminated={false} />
        </div>
      )}
      {eliminatedShow.length > 0 && (
        <div>
          <p className="section-label mb-2">Eliminated Paths</p>
          <PathTable paths={eliminatedShow} eliminated />
        </div>
      )}
    </div>
  )
}
