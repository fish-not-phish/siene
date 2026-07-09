'use client'

import * as React from 'react'
import { Bar, BarChart, Tooltip, XAxis, YAxis } from 'recharts'
import { Skeleton } from '@/components/ui/skeleton'
import { cn } from '@/lib/utils'
import { ChartContainer, type ChartConfig } from '@/components/ui/chart'

export interface StackedBarRow {
  label: string
  /** Values keyed by stack segment name */
  [key: string]: number | string
}

export interface StackSegment {
  key: string
  label: string
  color: string
}

type StackedTooltipProps = {
  active?: boolean
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  payload?: any[]
  label?: string
  segments: StackSegment[]
}

function StackedTooltip({ active, payload, label, segments }: StackedTooltipProps) {
  if (!active || !payload?.length) return null
  const total = (payload as Array<{ value: number }>).reduce((s, p) => s + (p.value ?? 0), 0)
  return (
    <div className='min-w-[180px] rounded-xl border bg-popover/95 p-3 shadow-xl backdrop-blur-sm'>
      <p className='mb-3 rounded-md border bg-muted/35 px-2.5 py-1 text-sm font-medium truncate max-w-[200px]'>{label}</p>
      <div className='space-y-1.5 text-sm'>
        {segments.map((seg) => {
          const p = (payload as Array<{ name: string; value: number }>).find((x) => x.name === seg.key)
          if (!p) return null
          return (
            <div key={seg.key} className='flex items-center justify-between gap-5'>
              <span className='flex items-center gap-2 text-muted-foreground'>
                <span className='size-1.5 rounded-full shrink-0' style={{ background: seg.color }} />
                {seg.label}
              </span>
              <span className='font-semibold tabular-nums'>{p.value.toLocaleString()}</span>
            </div>
          )
        })}
        {segments.length > 1 && (
          <div className='flex items-center justify-between gap-5 border-t pt-1.5 mt-1.5'>
            <span className='text-muted-foreground'>Total</span>
            <span className='font-semibold tabular-nums'>{total.toLocaleString()}</span>
          </div>
        )}
      </div>
    </div>
  )
}

export interface RegistryStackedBarChartProps {
  title: string
  subtitle?: string
  data?: StackedBarRow[]
  segments: StackSegment[]
  loading?: boolean
  className?: string
  height?: number
}

export function RegistryStackedBarChart({
  title,
  subtitle,
  data,
  segments,
  loading = false,
  className,
  height = 220,
}: RegistryStackedBarChartProps) {
  const isEmpty = !loading && (data ?? []).length === 0

  const chartConfig = Object.fromEntries(
    segments.map((s) => [s.key, { label: s.label, color: s.color }])
  ) satisfies ChartConfig

  return (
    <div className={cn('flex flex-col gap-4 rounded-xl border bg-card p-4 sm:p-5', className)}>
      <div className='flex items-start justify-between gap-3'>
        <div className='space-y-0.5'>
          <p className='text-xs font-semibold tracking-[0.16em] text-muted-foreground uppercase'>{title}</p>
          {subtitle && <p className='text-xs text-muted-foreground'>{subtitle}</p>}
        </div>
        {/* Legend */}
        {!loading && !isEmpty && (
          <div className='flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground'>
            {segments.map((s) => (
              <span key={s.key} className='flex items-center gap-1.5'>
                <span className='size-2 shrink-0 rounded-full' style={{ background: s.color }} />
                {s.label}
              </span>
            ))}
          </div>
        )}
      </div>

      {loading ? (
        <Skeleton className='w-full rounded-lg' style={{ height }} />
      ) : isEmpty ? (
        <div className='flex items-center justify-center text-sm text-muted-foreground' style={{ height }}>
          No data
        </div>
      ) : (
        <ChartContainer config={chartConfig} style={{ height }} className='w-full [&_.recharts-cartesian-axis-line]:stroke-transparent [&_.recharts-cartesian-axis-tick_line]:stroke-transparent'>
          <BarChart
            data={data}
            margin={{ top: 4, right: 4, left: -20, bottom: 4 }}
            barCategoryGap='30%'
          >
            <XAxis
              dataKey='label'
              axisLine={false}
              tickLine={false}
              tick={{ fontSize: 11 }}
              interval={0}
              dy={4}
            />
            <YAxis
              axisLine={false}
              tickLine={false}
              tick={{ fontSize: 11 }}
              width={40}
            />
            <Tooltip
              content={(props) => <StackedTooltip {...props} segments={segments} />}
              cursor={{ fill: 'color-mix(in oklch, var(--foreground) 5%, transparent)', radius: 4 }}
            />
            {segments.map((seg, idx) => (
              <Bar
                key={seg.key}
                dataKey={seg.key}
                stackId='a'
                fill={seg.color}
                radius={idx === segments.length - 1 ? [4, 4, 0, 0] : [0, 0, 0, 0]}
              />
            ))}
          </BarChart>
        </ChartContainer>
      )}
    </div>
  )
}
