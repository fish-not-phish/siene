'use client'

import * as React from 'react'
import {
  ScatterChart,
  Scatter,
  XAxis,
  YAxis,
  ZAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import type { VulnByProject } from '@/services/registry'

// ── Helpers ───────────────────────────────────────────────────────────────────

function totalCves(r: VulnByProject) {
  return r.critical + r.high + r.medium + r.low
}

function avgCves(r: VulnByProject) {
  if (!r.image_count) return 0
  return totalCves(r) / r.image_count
}

// ── Tooltip ───────────────────────────────────────────────────────────────────

type TooltipPayload = {
  cx?: number
  cy?: number
  project: string
  avg: number
  image_count: number
  total: number
}

type CustomTooltipProps = {
  active?: boolean
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  payload?: any[]
}

function CustomTooltip({ active, payload }: CustomTooltipProps) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload as TooltipPayload
  return (
    <div className='min-w-[180px] rounded-xl border bg-popover/95 p-3 shadow-xl backdrop-blur-sm'>
      <p className='mb-3 rounded-md border bg-muted/35 px-2.5 py-1 text-sm font-medium truncate max-w-[200px]'>
        {d.project}
      </p>
      <div className='space-y-1.5 text-sm'>
        <div className='flex items-center justify-between gap-5'>
          <span className='text-muted-foreground'>Avg CVEs / image</span>
          <span className='font-semibold tabular-nums'>{d.avg.toFixed(1)}</span>
        </div>
        <div className='flex items-center justify-between gap-5'>
          <span className='text-muted-foreground'>Scanned images</span>
          <span className='font-semibold tabular-nums'>{d.image_count}</span>
        </div>
        <div className='flex items-center justify-between gap-5 border-t pt-1.5 mt-1.5'>
          <span className='text-muted-foreground'>Total CVEs</span>
          <span className='font-semibold tabular-nums'>{d.total.toLocaleString()}</span>
        </div>
      </div>
    </div>
  )
}

// ── Custom dot (filled circle with ring) ─────────────────────────────────────

type DotProps = {
  cx?: number
  cy?: number
  r?: number
  fill?: string
  opacity?: number
}

function ScatterDot({ cx = 0, cy = 0, r = 8, fill = 'currentColor', opacity = 1 }: DotProps) {
  return (
    <g>
      <circle cx={cx} cy={cy} r={r} fill={fill} fillOpacity={opacity * 0.25} stroke={fill} strokeWidth={1.5} strokeOpacity={opacity * 0.7} />
      <circle cx={cx} cy={cy} r={Math.max(r * 0.38, 3)} fill={fill} fillOpacity={opacity * 0.8} />
    </g>
  )
}

// ── Props ─────────────────────────────────────────────────────────────────────

export interface RegistryVulnScatterProps {
  data?: VulnByProject[]
  loading?: boolean
  className?: string
}

// ── Component ─────────────────────────────────────────────────────────────────

const DOT_COLOR = 'var(--chart-4)'          // emerald — normal density
const DOT_COLOR_HIGH = 'oklch(0.62 0.22 27)' // red — high density

export function RegistryVulnScatter({ data, loading = false, className }: RegistryVulnScatterProps) {
  const isEmpty = !loading && (data ?? []).length === 0

  // Build scatter data — X is a numeric index for recharts, label stored in payload
  const points = React.useMemo(() => {
    if (!data) return []
    return data.map((r, i) => ({
      x: i,
      y: parseFloat(avgCves(r).toFixed(2)),
      z: Math.max(r.image_count, 1),  // Z = bubble area
      project: r.project,
      avg: avgCves(r),
      image_count: r.image_count,
      total: totalCves(r),
    }))
  }, [data])

  // Determine max avg for coloring (high avg = warning colour)
  const maxAvg = points.length ? Math.max(...points.map(p => p.avg)) : 1

  // Y axis nice ceiling
  const yMax = points.length
    ? Math.ceil(maxAvg * 1.25) || 1
    : 10

  // Z range: min=100 area, max=900 area (recharts ZAxis uses area)
  const zRange: [number, number] = [120, 900]

  return (
    <div className={cn('flex flex-col gap-4 rounded-xl border bg-card p-4 sm:p-5', className)}>
      {/* Header */}
      <div className='flex items-start justify-between gap-3'>
        <div className='space-y-0.5'>
          <p className='text-xs font-semibold tracking-[0.16em] text-muted-foreground uppercase'>
            Vulnerability Density by Project
          </p>
          <p className='text-xs text-muted-foreground'>
            Avg CVEs per scanned image · bubble size = image count
          </p>
        </div>
      </div>

      {/* Chart body */}
      {loading ? (
        <Skeleton className='w-full rounded-lg h-[240px]' />
      ) : isEmpty ? (
        <div className='flex h-[240px] items-center justify-center text-sm text-muted-foreground'>
          No scan data
        </div>
      ) : (
        <div className='h-[240px] w-full'>
          <ResponsiveContainer width='100%' height='100%'>
            <ScatterChart margin={{ top: 8, right: 16, left: 8, bottom: 32 }}>
              {/* X axis: custom ticks mapped from numeric index → project label */}
              <XAxis
                type='number'
                dataKey='x'
                domain={[-0.5, points.length - 0.5]}
                ticks={points.map(p => p.x)}
                tickFormatter={(v) => points[v]?.project ?? ''}
                axisLine={false}
                tickLine={false}
                tick={{ fontSize: 11 }}
                interval={0}
                dy={8}
              />
              <YAxis
                type='number'
                dataKey='y'
                domain={[0, yMax]}
                axisLine={false}
                tickLine={false}
                tick={{ fontSize: 11 }}
                width={48}
                label={{
                  value: 'avg CVEs',
                  angle: -90,
                  position: 'insideLeft',
                  offset: 12,
                  style: { fontSize: 10, fill: 'var(--muted-foreground)', opacity: 0.7 },
                }}
              />
              <ZAxis type='number' dataKey='z' range={zRange} />
              <Tooltip
                content={<CustomTooltip />}
                cursor={{ strokeDasharray: '4 4', stroke: 'color-mix(in oklch, var(--foreground) 15%, transparent)' }}
              />
              <Scatter
                data={points}
                shape={(props: DotProps & { payload?: TooltipPayload }) => {
                  const avg = props.payload?.avg ?? 0
                  const fill = avg > 0 && maxAvg > 0 && avg / maxAvg > 0.6
                    ? DOT_COLOR_HIGH
                    : DOT_COLOR
                  return <ScatterDot {...props} fill={fill} opacity={1} />
                }}
              >
                {points.map((_, i) => (
                  <Cell key={i} />
                ))}
              </Scatter>
            </ScatterChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Mini legend */}
      {!loading && !isEmpty && (
        <div className='flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted-foreground'>
          <span className='flex items-center gap-1.5'>
            <span className='size-2.5 rounded-full shrink-0' style={{ background: DOT_COLOR, opacity: 0.75 }} />
            Normal density
          </span>
          <span className='flex items-center gap-1.5'>
            <span className='size-2.5 rounded-full shrink-0' style={{ background: DOT_COLOR_HIGH, opacity: 0.75 }} />
            High density (&gt;60% of peak)
          </span>
        </div>
      )}
    </div>
  )
}
