'use client'

import * as React from 'react'
import { useMemo, useState } from 'react'
import { Cell, Label, Pie, PieChart, Tooltip, type TooltipProps } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'

export interface DonutSlice {
  label: string
  value: number
  color?: string
}

interface TooltipPayload {
  name: string
  value: number
  payload: { label: string; value: number; color: string; pct: number }
}

function DonutTooltip({ active, payload }: TooltipProps<number, string>) {
  if (!active || !payload?.length) return null
  const item = (payload as unknown as TooltipPayload[])[0]?.payload
  if (!item) return null
  return (
    <div className='min-w-[160px] rounded-xl border bg-popover/95 p-3 shadow-xl backdrop-blur-sm'>
      <div className='flex items-center gap-2 mb-2'>
        <span className='size-2.5 rounded-full shrink-0' style={{ background: item.color }} />
        <span className='text-sm font-medium'>{item.label}</span>
      </div>
      <div className='flex items-center justify-between gap-4 text-sm'>
        <span className='text-muted-foreground'>Count</span>
        <span className='font-semibold tabular-nums'>{item.value.toLocaleString()}</span>
      </div>
      <div className='flex items-center justify-between gap-4 text-sm'>
        <span className='text-muted-foreground'>Share</span>
        <span className='font-semibold tabular-nums'>{item.pct}%</span>
      </div>
    </div>
  )
}

export interface RegistryDonutChartProps {
  title: string
  subtitle?: string
  data?: DonutSlice[]
  loading?: boolean
  className?: string
  /** When true, renders a compact version without the legend */
  compact?: boolean
}

// Default palette that works in light and dark mode
const DEFAULT_COLORS = [
  'var(--chart-1)',
  'var(--chart-2)',
  'var(--chart-3)',
  'var(--chart-4)',
  'var(--chart-5)',
  'color-mix(in oklch, var(--primary) 50%, var(--muted-foreground))',
  'color-mix(in oklch, var(--primary) 30%, var(--muted-foreground))',
]

export function RegistryDonutChart({
  title,
  subtitle,
  data,
  loading = false,
  className,
  compact = false,
}: RegistryDonutChartProps) {
  const [activeIndex, setActiveIndex] = useState<number | null>(null)
  const total = useMemo(() => (data ?? []).reduce((s, d) => s + d.value, 0), [data])

  const enriched = useMemo(
    () =>
      (data ?? []).map((d, i) => ({
        ...d,
        color: d.color ?? DEFAULT_COLORS[i % DEFAULT_COLORS.length],
        pct: total > 0 ? Math.round((d.value / total) * 100) : 0,
      })),
    [data, total],
  )

  const isEmpty = !loading && (data ?? []).length === 0

  return (
    <div className={cn('flex flex-col gap-4 rounded-xl border bg-card p-4 sm:p-5', className)}>
      <div className='space-y-0.5'>
        <p className='text-xs font-semibold tracking-[0.16em] text-muted-foreground uppercase'>{title}</p>
        {subtitle && <p className='text-xs text-muted-foreground'>{subtitle}</p>}
      </div>

      {loading ? (
        <div className='flex flex-col items-center gap-4'>
          <Skeleton className='size-[140px] rounded-full' />
          <div className='w-full space-y-2'>
            {Array.from({ length: 3 }).map((_, i) => (
              <Skeleton key={i} className='h-4 w-full' />
            ))}
          </div>
        </div>
      ) : isEmpty ? (
        <div className='flex h-[180px] items-center justify-center text-sm text-muted-foreground'>No data</div>
      ) : (
        <div className={cn('flex flex-col items-center gap-4', !compact && 'sm:flex-row sm:items-start')}>
          {/* Chart */}
          <div className='shrink-0'>
            <PieChart width={140} height={140}>
              <Pie
                data={enriched}
                cx={65}
                cy={65}
                innerRadius={42}
                outerRadius={62}
                paddingAngle={2}
                dataKey='value'
                nameKey='label'
                strokeWidth={0}
                onMouseEnter={(_, index) => setActiveIndex(index)}
                onMouseLeave={() => setActiveIndex(null)}
              >
                {enriched.map((entry, i) => (
                  <Cell key={i} fill={entry.color} />
                ))}
                {/* Center label — hidden while a slice is hovered so it never overlaps the tooltip */}
                {activeIndex === null && (
                  <Label
                    content={({ viewBox }) => {
                      if (!viewBox || !('cx' in viewBox) || !('cy' in viewBox)) return null
                      const { cx, cy } = viewBox as { cx: number; cy: number }
                      return (
                        <g>
                          <text x={cx} y={cy - 6} textAnchor='middle' dominantBaseline='middle' className='fill-foreground text-xl font-semibold'>
                            <tspan fontSize={18} fontWeight={600}>{total.toLocaleString()}</tspan>
                          </text>
                          <text x={cx} y={cy + 12} textAnchor='middle' dominantBaseline='middle'>
                            <tspan fontSize={10} fill='var(--muted-foreground)'>total</tspan>
                          </text>
                        </g>
                      )
                    }}
                  />
                )}
              </Pie>
              <Tooltip
                content={<DonutTooltip />}
                wrapperStyle={{ zIndex: 50 }}
              />
            </PieChart>
          </div>

          {/* Legend */}
          {!compact && (
            <div className='min-w-0 flex-1 space-y-2'>
              {enriched.map((entry) => (
                <div key={entry.label} className='flex items-center justify-between gap-2 text-xs'>
                  <div className='flex min-w-0 items-center gap-1.5'>
                    <span className='size-2 shrink-0 rounded-full' style={{ background: entry.color }} />
                    <span className='truncate text-muted-foreground'>{entry.label}</span>
                  </div>
                  <div className='flex shrink-0 items-center gap-2 tabular-nums'>
                    <span className='font-medium'>{entry.value.toLocaleString()}</span>
                    <span className='w-[30px] text-right text-muted-foreground'>{entry.pct}%</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
